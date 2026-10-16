import {spawn,spawnSync} from 'node:child_process';
import {randomBytes} from 'node:crypto';
import net from 'node:net';
import assert from 'node:assert/strict';
import {environment} from './environment.mjs';
const baseEnv=environment();const database=`sentinel_test_${process.pid}`;const token=randomBytes(32).toString('hex');
function sql(database,statement){const r=spawnSync('docker',['compose','exec','-T','postgres','psql','-X','-v','ON_ERROR_STOP=1','-U','sentinel','-d',database],{input:statement,encoding:'utf8',env:baseEnv});if(r.status!==0)throw new Error(r.stderr);return r.stdout}
const listener=net.createServer();await new Promise(r=>listener.listen(0,'127.0.0.1',r));const port=listener.address().port;await new Promise(r=>listener.close(r));const base=`http://127.0.0.1:${port}`;
sql('postgres',`CREATE DATABASE ${database} OWNER sentinel_app;`);
const env={...baseEnv,VI_ENV:'production',VI_API_TOKEN:token,VI_PUBLIC_ORIGIN:'https://sentinel.test',PORT:String(port),DATABASE_URL:baseEnv.DATABASE_URL.replace(/\/[^/]+$/,`/${database}`)};
let proc;let checks=0;
async function start(){proc=spawn('backend/target/debug/vi-server',[],{env,stdio:['ignore','pipe','pipe']});let stderr='';proc.stderr.on('data',b=>stderr+=b.toString());for(let i=0;i<100;i++){try{const r=await fetch(base+'/readyz');if(r.ok)return}catch{}if(proc.exitCode!==null)throw new Error('API exited: '+stderr);await new Promise(r=>setTimeout(r,100));}throw new Error('API startup timed out: '+stderr)}
async function request(path,{body,expected=200,auth=true,headers={}}={}){const r=await fetch(base+path,{method:body===undefined?'GET':'POST',headers:{'Content-Type':'application/json',...(auth?{Authorization:`Bearer ${token}`} :{}),...headers},body:body===undefined?undefined:JSON.stringify(body),signal:AbortSignal.timeout(180000)});const text=await r.text();assert.equal(r.status,expected,`${path}: ${text}`);checks++;return {data:text?JSON.parse(text):null,response:r}}
async function stop(){if(!proc||proc.exitCode!==null)return;proc.kill('SIGTERM');await new Promise(resolve=>{proc.once('exit',resolve);setTimeout(()=>{proc.kill('SIGKILL');resolve()},3000).unref()})}
try{
 await start();await request('/api/stats/',{expected:401,auth:false});await request('/api/stats/',{expected:401,headers:{Authorization:'Bearer invalid'}});assert.equal((await request('/api/stats/')).data.total,0);
 const login=await request('/api/session',{auth:false,body:{token}});const cookie=login.response.headers.get('set-cookie');assert.match(cookie,/HttpOnly/);assert.match(cookie,/SameSite=Strict/);assert.match(cookie,/Secure/);await request('/api/stats/',{auth:false,headers:{Cookie:cookie.split(';')[0]}});
 await request('/api/session',{auth:false,body:{token:'wrong'},expected:401});await request('/api/session',{auth:false,body:{token},headers:{Origin:'https://evil.test'},expected:403});await request('/api/v2/vulnerabilities/filter',{body:{},headers:{Origin:'https://evil.test'},expected:403});
 // Production must reject development origins, even though dev mode supports both.
 await request('/api/v2/vulnerabilities/filter',{body:{limit:1},headers:{Origin:'https://sentinel.test'}});
 for(const origin of ['http://localhost:5173','http://127.0.0.1:5173']) {
  await request('/api/v2/vulnerabilities/filter',{body:{},headers:{Origin:origin},expected:403});
  await request('/api/session',{auth:false,body:{token},headers:{Origin:origin},expected:403});
 }
 const records=[1000,1001,1002].map((n,i)=>({id:`CVE-2099-${n}`,title:i===0?'Alpha fixture':'Beta fixture',description:'Synthetic record in isolated test database only.',cvss:9-i,cvss_known:true,epss_score:0.1*i,epss_known:true,priority_score:100*(i+1),ssvc_decision:'Unassessed',seen_wild:i===0,is_zeroday:false,published:`2099-01-0${i+1}`,ecosystem:'npm',vendor:'test',product:'test-package',purl:'pkg:npm/test-only',sources:['isolated-test'],ingested_at:'2026-01-01T00:00:00Z',aliases:[],provenance:[],score_breakdown:{exploitation:0,epss:0,severity:0,threat:0,supply_chain:0}}));
 for(const v of records)sql(database,`INSERT INTO vulnerabilities(id,data,priority_score,cvss,epss_score,published,ssvc_decision,seen_wild,ecosystem,vendor) VALUES('${v.id}','${JSON.stringify(v).replaceAll("'","''")}'::jsonb,${v.priority_score},${v.cvss},${v.epss_score},'${v.published}','Unassessed',${v.seen_wild},'npm','test');`);
 assert.equal((await request('/api/stats/')).data.total,3);
 const first=(await request('/api/v2/vulnerabilities/filter',{body:{limit:1}})).data;const next=(await request('/api/v2/vulnerabilities/filter',{body:{limit:1,cursor:first.next_cursor}})).data;assert.notEqual(first.results[0].id,next.results[0].id);
 assert.equal((await request('/api/v2/vulnerabilities/filter',{body:{text_search:'Alpha'}})).data.total,1);
 assert.equal((await request('/api/v2/vulnerabilities/filter',{body:{text_search:'CVE-2099'}})).data.total,3);
 assert.equal((await request('/api/v2/vulnerabilities/filter',{body:{text_search:'pkg:npm/test-only'}})).data.total,3);
 assert.equal((await request('/api/v2/vulnerabilities/filter',{body:{conditions:[{field:'seen_wild',operator:'eq',value:true}]}})).data.total,1);
 assert.equal((await request('/api/v2/vulnerabilities/filter',{body:{conditions:[{field:'priority_score',operator:'gte',value:200}]}})).data.total,2);
 assert.equal((await request('/api/v2/vulnerabilities/filter',{body:{conditions:[{field:'id',operator:'in',value:['CVE-2099-1000','CVE-2099-1002']}]}})).data.total,2);
 await request('/api/v2/vulnerabilities/filter',{body:{cursor:'bad'},expected:400});await request('/api/v2/vulnerabilities/filter',{body:{conditions:[{field:'cvss',operator:'gt',value:'wrong'}]},expected:400});await request('/api/v2/vulnerabilities/filter',{body:{conditions:[{field:'DROP TABLE',operator:'eq',value:true}]},expected:400});
 await request('/api/vulnerabilities/CVE-2099-1000');await request('/api/vulnerabilities/CVE-2099-9999',{expected:404});
 // MCP transport, security, discovery and tool dispatch against isolated records.
 const mcpHeaders={Accept:'application/json, text/event-stream','MCP-Protocol-Version':'2025-11-25'};
 const rpc=async(method,params={},options={})=>(await request('/api/mcp',{body:{jsonrpc:'2.0',id:42,method,params},headers:mcpHeaders,...options})).data;
 await rpc('ping',{}, {auth:false,expected:401});
 await rpc('ping',{}, {headers:{...mcpHeaders,Origin:'https://evil.test'},expected:403});
 await request('/api/mcp',{headers:{Origin:'https://evil.test'},expected:403});
 await request('/api/mcp',{expected:405});
 await rpc('ping',{}, {headers:{Accept:'application/json'},expected:406});
 await rpc('ping',{}, {headers:{...mcpHeaders,'MCP-Protocol-Version':'2099-01-01'},expected:400});
 const initialized=await rpc('initialize',{protocolVersion:'2025-11-25',capabilities:{},clientInfo:{name:'sentinel-test',version:'1'}});
 assert.equal(initialized.result.protocolVersion,'2025-11-25');assert.equal(initialized.result.capabilities.tools.listChanged,false);
 assert.equal((await rpc('initialize',{protocolVersion:'unsupported'})).result.protocolVersion,'2025-11-25');
 for(const version of ['2025-03-26','2025-06-18']) assert.equal((await rpc('initialize',{protocolVersion:version})).result.protocolVersion,version);
 await request('/api/mcp',{body:{jsonrpc:'2.0',method:'notifications/initialized'},headers:mcpHeaders,expected:202});
 const catalog=(await rpc('tools/list')).result.tools;assert.equal(catalog.length,9);assert.ok(catalog.every(t=>t.annotations.readOnlyHint));
 const call=async(name,args={})=>rpc('tools/call',{name,arguments:args});
 assert.equal((await call('search_vulnerabilities',{text_search:'Alpha'})).result.structuredContent.total,1);
 const mcpFirst=(await call('search_vulnerabilities',{limit:1})).result.structuredContent;
 assert.notEqual((await call('search_vulnerabilities',{limit:1,cursor:mcpFirst.next_cursor})).result.structuredContent.results[0].id,mcpFirst.results[0].id);
 assert.equal((await call('get_vulnerability',{id:'cve-2099-1000'})).result.structuredContent.id,'CVE-2099-1000');
 assert.equal((await call('get_vulnerability',{id:'CVE-2099-9999'})).result.isError,true);
 assert.equal((await call('get_statistics')).result.structuredContent.total,3);
 for(const [name,args] of [['get_sources',{}],['get_detection_rules',{id:'CVE-2099-1000'}],['get_relationships',{id:'CVE-2099-1000'}],['search_products',{name:'test'}],['search_threat_actors',{name:'test'}]]) assert.equal((await call(name,args)).result.isError,false);
 assert.equal((await call('lookup_patch',{kb:'KB-unknown'})).result.isError,true);
 for(const [name,args] of [['get_vulnerability',{}],['get_statistics',{unexpected:true}],['search_vulnerabilities',{limit:101}],['search_products',{limit:'10'}],['save_vex',{}]]) assert.equal((await call(name,args)).error.code,-32602);
 assert.equal((await call('search_vulnerabilities',{conditions:[{field:'cvss',operator:'gt',value:'wrong'}]})).result.isError,true);
 assert.equal((await rpc('missing')).error.code,-32601);
 assert.equal((await request('/api/mcp',{body:[],headers:mcpHeaders})).data.error.code,-32600);
 const malformed=await fetch(base+'/api/mcp',{method:'POST',headers:{...mcpHeaders,'Content-Type':'application/json',Authorization:`Bearer ${token}`},body:'{'});assert.equal((await malformed.json()).error.code,-32700);checks++;
 const bridge=spawn(process.execPath,['scripts/mcp-stdio.mjs'],{env:{...process.env,VI_API_TOKEN:token,VI_MCP_URL:base+'/api/mcp'},stdio:['pipe','pipe','pipe']});
 let bridgeOut='';let bridgeErr='';bridge.stdout.on('data',b=>bridgeOut+=b);bridge.stderr.on('data',b=>bridgeErr+=b);
 bridge.stdin.end([{jsonrpc:'2.0',id:1,method:'initialize',params:{protocolVersion:'2025-11-25',capabilities:{},clientInfo:{name:'test',version:'1'}}},{jsonrpc:'2.0',method:'notifications/initialized'},{jsonrpc:'2.0',id:2,method:'tools/call',params:{name:'get_statistics',arguments:{}}}].map(JSON.stringify).join('\n')+'\n');
 const bridgeExit=await new Promise((resolve,reject)=>{bridge.on('error',reject);bridge.on('exit',resolve)});assert.equal(bridgeExit,0,bridgeErr);assert.equal(bridgeErr,'');
 const bridgeMessages=bridgeOut.trim().split('\n').map(JSON.parse);assert.equal(bridgeMessages.length,2);assert.equal(bridgeMessages[1].result.structuredContent.total,3);checks++;
 const sources=(await request('/api/sources')).data.results;assert.equal(sources.length,12);assert.equal((await request('/api/admin/ingest',{body:{source:'CISA KEV'}})).data.queued,true);assert.equal((await request('/api/admin/ingest',{body:{source:'CISA KEV'}})).data.queued,false);await request('/api/admin/ingest',{body:{source:'invalid'},expected:400});assert.equal((await request('/api/admin/jobs')).data.results.length,1);
 const doc={'@context':'https://openvex.dev/ns/v0.2.0','@id':'urn:uuid:isolated-test',author:'Isolated QA',timestamp:'2026-01-01T00:00:00Z',version:1,statements:[{vulnerability:{name:'CVE-2099-1000'},products:[{'@id':'pkg:npm/test-only@1.0.0'}],status:'not_affected',justification:'vulnerable_code_not_in_execute_path'}]};await request('/api/v2/vex',{body:doc});assert.equal((await request('/api/v2/vex')).data.results.length,1);await request('/api/v2/vex',{body:{...doc,author:''},expected:400});await request('/api/v2/vex',{body:{...doc,statements:[{...doc.statements[0],justification:'invalid'}]},expected:400});
 await request('/api/v2/sbom/analyze',{body:{},expected:400});await request('/api/v2/sbom/analyze',{body:{bomFormat:'CycloneDX',components:[]},expected:400});
 const graph=(await request('/api/graphql',{body:{query:'{ vulnerabilities(search:"Alpha") }'}})).data;assert.equal(graph.data.vulnerabilities.total,1);
 const stix=(await request('/api/v21/collections/sentinel/objects/?limit=1')).data;assert.equal(stix.objects.length,1);assert.equal(stix.more,true);
 const exported=await fetch(base+'/api/download/latest',{headers:{Authorization:`Bearer ${token}`}});assert.equal(exported.status,200);assert.equal((await exported.text()).trim().split('\n').length,3);checks++;
 const spec=(await request('/api-docs/openapi.json',{auth:false})).data;assert.equal(spec.openapi,'3.1.0');
 await stop();await start();assert.equal((await request('/api/v2/vex')).data.results.length,1);assert.equal((await request('/api/stats/')).data.total,3);
 const expired=await fetch(base+'/api/session',{method:'DELETE',headers:{Cookie:cookie.split(';')[0]}});assert.equal(expired.status,200);await request('/api/stats/',{auth:false,headers:{Cookie:cookie.split(';')[0]},expected:401});
 // Reproduce the original local API launch: Compose origin in .env, Vite on 5173.
 await stop();env.VI_ENV='development';env.VI_PUBLIC_ORIGIN='http://localhost:3000';await start();
 for(const origin of ['http://localhost:5173','http://127.0.0.1:5173']) {
  const session=await request('/api/session',{auth:false,body:{token},headers:{Origin:origin}});
  const sessionCookie=session.response.headers.get('set-cookie').split(';')[0];
  assert.ok(!session.response.headers.get('set-cookie').includes('; Secure'));
  assert.equal((await request('/api/v2/vulnerabilities/filter',{auth:false,body:{limit:1},headers:{Origin:origin,Cookie:sessionCookie}})).data.total,3);
 }
 for(const origin of ['https://evil.test','null','http://localhost:5174']) {
  await request('/api/v2/vulnerabilities/filter',{body:{},headers:{Origin:origin},expected:403});
  await request('/api/session',{auth:false,body:{token},headers:{Origin:origin},expected:403});
 }
 console.log(`PASS: ${checks} PostgreSQL/Valkey production API checks, including auth, CSRF, keyset paging, jobs, streaming export, and persistence.`);
}finally{await stop();sql('postgres',`DROP DATABASE ${database} WITH (FORCE);`)}
