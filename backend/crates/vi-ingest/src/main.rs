use serde_json::json;
use std::{collections::HashSet, sync::Arc};
#[tokio::main]
async fn main() -> Result<(), String> {
    let db = vi_db::Database::new();
    db.initialize().await?;
    let args: Vec<_> = std::env::args().collect();
    let once = args.iter().any(|a| a == "--once");
    let source = args
        .windows(2)
        .find(|a| a[0] == "--source")
        .map(|a| a[1].clone());
    let names: Vec<String> = source.map(|s| vec![s]).unwrap_or_else(|| {
        vi_core::SOURCES
            .iter()
            .map(|(s, _)| s.to_string())
            .collect()
    });
    let semaphore = Arc::new(tokio::sync::Semaphore::new(4));
    let mut tasks = tokio::task::JoinSet::new();
    let mut active: HashSet<String> = HashSet::new();
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
    loop {
        tokio::select! {
         _=shutdown()=>{tasks.abort_all();while tasks.join_next().await.is_some(){}for name in &active{let _=db.interrupt(name).await;}return Ok(())},
         result=tasks.join_next(),if !tasks.is_empty()=>{if let Some(Ok((name,_)))=result{active.remove(&name);}},
         _=interval.tick()=>{
          let mut work=vec![];if !once{for(id,name)in db.queued().await?{if active.contains(&name){db.finish_job(id,None).await?;}else{work.push((Some(id),name));}}}
          let checkpoints=db.checkpoints().await?;
          for name in &names{let due=once||checkpoints.iter().find(|cp|cp["source_name"]==*name).is_none_or(|cp|{!["next_run_at","backoff_until"].iter().any(|key|cp[*key].as_str().and_then(|v|chrono::DateTime::parse_from_rfc3339(v).ok()).is_some_and(|t|t>chrono::Utc::now()))&&cp["status"]!="Disabled"});if due&&!active.contains(name)&&!work.iter().any(|(_,s)|s==name){work.push((None,name.clone()))}}
          for(job,name)in work{active.insert(name.clone());let db=db.clone();let semaphore=semaphore.clone();tasks.spawn(async move{let _permit=semaphore.acquire().await.unwrap();let result=vi_ingest::run_source(&db,&name,once||job.is_some()).await;if let Some(id)=job{let _=db.finish_job(id,result.as_ref().err().map(String::as_str)).await;}if once||job.is_some()||!matches!(result,Ok(0)){eprintln!("{}",json!({"event":"source_run","source":name,"job":job,"result":result}));}(name,result.is_err())});}
          if once{let mut failed=false;while let Some(result)=tasks.join_next().await{let(_,error)=result.map_err(|e|e.to_string())?;failed|=error;}return if failed{Err("One or more sources failed; see source status".into())}else{Ok(())}}
         }
        }
    }
}
async fn shutdown() {
    #[cfg(unix)]
    {
        let mut term =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
        tokio::select! {_=term.recv()=>{},_=tokio::signal::ctrl_c()=>{}}
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
