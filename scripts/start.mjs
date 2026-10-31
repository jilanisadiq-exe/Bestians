// One command: builds the React app (only if needed) and starts the API + UI on ONE port.
// Usage: npm start   ->  http://localhost:4000
import { spawnSync, spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const dist = path.join(root, 'client', 'dist', 'index.html');
const isWin = process.platform === 'win32';
const npm = isWin ? 'npm.cmd' : 'npm';

function newest(dir) {
  let t = 0;
  for (const f of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, f.name);
    t = Math.max(t, f.isDirectory() ? newest(p) : fs.statSync(p).mtimeMs);
  }
  return t;
}
const needsBuild = !fs.existsSync(dist) || newest(path.join(root, 'client', 'src')) > fs.statSync(dist).mtimeMs;
if (needsBuild) {
  console.log('• Building the CampusOS frontend (first run only)…');
  const r = spawnSync(npm, ['--prefix', 'client', 'run', 'build'], { cwd: root, stdio: 'inherit', shell: isWin });
  if (r.status !== 0) { console.error('Frontend build failed. Run "npm install" first.'); process.exit(1); }
}
const server = spawn(process.execPath, ['src/index.js'], { cwd: path.join(root, 'server'), stdio: 'inherit' });
server.on('exit', c => process.exit(c ?? 0));
for (const s of ['SIGINT', 'SIGTERM']) process.on(s, () => server.kill(s));
