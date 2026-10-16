import {spawn} from 'node:child_process';import {environment} from './environment.mjs';
const child=spawn('cargo',['run','--manifest-path','backend/Cargo.toml','--bin','vi-worker','--',...process.argv.slice(2)],{stdio:'inherit',env:environment()});child.on('exit',code=>process.exit(code??1));process.on('SIGINT',()=>child.kill('SIGINT'));process.on('SIGTERM',()=>child.kill('SIGTERM'));
