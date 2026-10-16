import { readFileSync, existsSync } from "node:fs";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const env={...process.env};
if(existsSync(resolve(root,'.env'))){for(const line of readFileSync(resolve(root,'.env'),'utf8').split('\n')){const i=line.indexOf('=');if(i>0&&!line.startsWith('#'))env[line.slice(0,i)]=line.slice(i+1);}env.DATABASE_URL ||= `postgresql://${env.VI_DB_PASSWORD?"sentinel_app":"sentinel"}:${env.VI_DB_PASSWORD||env.POSTGRES_PASSWORD}@127.0.0.1:5433/sentinel`;env.REDIS_URL ||= 'redis://127.0.0.1:6380';}
// Always override a Compose/public origin, including when .env is absent.
env.VI_PUBLIC_ORIGIN='http://localhost:5173';
env.VI_ENV='development';
const processes = [
  spawn(
    "cargo",
    ["run", "--manifest-path", "backend/Cargo.toml", "--bin", "vi-server"],
    { cwd: root, stdio: "inherit",env },
  ),
  spawn("cargo",["run","--manifest-path","backend/Cargo.toml","--bin","vi-worker"],{cwd:root,stdio:"inherit",env}),
  spawn("npm", ["--prefix", "frontend", "run", "dev"], {
    cwd: root,
    stdio: "inherit",env,
  }),
];
let stopping = false;
function stop(code = 0) {
  if (stopping) return;
  stopping = true;
  for (const p of processes) p.kill("SIGTERM");
  setTimeout(() => process.exit(code), 300).unref();
}
for (const p of processes) {
  p.on("error", (e) => {
    console.error(e.message);
    stop(1);
  });
  p.on("exit", (code) => {
    if (!stopping) stop(code ?? 1);
  });
}
process.on("SIGINT", () => stop());
process.on("SIGTERM", () => stop());
