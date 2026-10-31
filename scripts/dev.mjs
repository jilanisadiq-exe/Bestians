// Dev mode: API on :4000 + Vite on :5173 (Vite proxies /api to the API, so there are no CORS or URL errors).
import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const isWin = process.platform === 'win32';
const npm = isWin ? 'npm.cmd' : 'npm';
const procs = [
  spawn(process.execPath, ['--watch', 'src/index.js'], { cwd: path.join(root, 'server'), stdio: 'inherit' }),
  spawn(npm, ['run', 'dev'], { cwd: path.join(root, 'client'), stdio: 'inherit', shell: isWin })
];
const stop = () => procs.forEach(p => { try { p.kill(); } catch {} });
procs.forEach(p => p.on('exit', stop));
for (const s of ['SIGINT', 'SIGTERM']) process.on(s, stop);
