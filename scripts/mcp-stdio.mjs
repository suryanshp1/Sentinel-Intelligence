#!/usr/bin/env node
// MCP stdio transport adapter. Only JSON-RPC messages may be written to stdout.
import {createInterface} from 'node:readline';
const endpoint = new URL(process.env.VI_MCP_URL || 'http://127.0.0.1:8080/api/mcp');
if (endpoint.username || endpoint.password || endpoint.search || endpoint.hash ||
    (endpoint.protocol !== 'https:' && !(endpoint.protocol === 'http:' && ['localhost','127.0.0.1','[::1]'].includes(endpoint.hostname)))) {
  console.error('VI_MCP_URL must use HTTPS, or HTTP on loopback, without embedded credentials, query or fragment.');
  process.exit(1);
}
let version = '2025-11-25';
const send = message => process.stdout.write(JSON.stringify(message) + '\n');
for await (const line of createInterface({input:process.stdin, crlfDelay:Infinity})) {
  if (!line.trim()) continue;
  let message;
  try { message = JSON.parse(line); }
  catch { send({jsonrpc:'2.0',id:null,error:{code:-32700,message:'Parse error'}}); continue; }
  if (Buffer.byteLength(line) > 64 * 1024) {
    send({jsonrpc:'2.0',id:message?.id ?? null,error:{code:-32600,message:'Message exceeds 64 KiB'}}); continue;
  }
  try {
    const response = await fetch(endpoint, {
      method:'POST', redirect:'error', signal:AbortSignal.timeout(60000),
      headers:{'Content-Type':'application/json',Accept:'application/json, text/event-stream',
        'MCP-Protocol-Version':version,
        ...(process.env.VI_API_TOKEN ? {Authorization:`Bearer ${process.env.VI_API_TOKEN}`} : {})},
      body:JSON.stringify(message),
    });
    if (!response.ok) throw new Error(`MCP endpoint returned HTTP ${response.status}`);
    if (response.status === 202) continue;
    const result = await response.json();
    if (message?.method === 'initialize' && result.result?.protocolVersion) version = result.result.protocolVersion;
    send(result);
  } catch (error) {
    console.error(error.message);
    if (message && Object.hasOwn(message,'id')) send({jsonrpc:'2.0',id:message.id,error:{code:-32603,message:'Sentinel MCP request failed; check endpoint, authentication and server availability.'}});
  }
}
