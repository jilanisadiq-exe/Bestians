// In-memory database with crash-safe persistence.
//  - Reads are served from memory (microseconds) instead of re-parsing a JSON file on every request.
//  - Writes are batched and saved atomically (temp file + rename), with a backup copy, so a crash or
//    a double-click can never leave a half-written / corrupt db.json.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const DATA_DIR = path.resolve(__dirname, '../data');
export const UPLOAD_DIR = path.resolve(__dirname, '../uploads');
const DB_FILE = path.join(DATA_DIR, 'db.json');
const BAK_FILE = path.join(DATA_DIR, 'db.backup.json');
fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

export const now = () => new Date().toISOString();
export const id = prefix => `${prefix}-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;

const DEMO_USERS = [
  { email: 'admin@team14.com', name: 'Admin', role: 'admin', phone_number: '9000000004' },
  { email: 'student@team14.com', name: 'Student', role: 'student', phone_number: '9000000002' },
  { email: 'faculty@team14.com', name: 'Faculty', role: 'faculty', phone_number: '9000000003' },
  { email: 'officestaff@team14.com', name: 'Office Staff', role: 'office_staff', phone_number: '9000000001' }
];

let db = null;
let timer = null;
let dirty = false;

function parseFile(file) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return null; }
}
function persistNow() {
  if (!dirty || !db) return;
  dirty = false;
  const tmp = `${DB_FILE}.${process.pid}.tmp`;
  try {
    fs.writeFileSync(tmp, JSON.stringify(db));
    if (fs.existsSync(DB_FILE)) { try { fs.copyFileSync(DB_FILE, BAK_FILE); } catch {} }
    fs.renameSync(tmp, DB_FILE);
  } catch (err) {
    console.error('Could not save database:', err.message);
    dirty = true;
  }
}
export function readDB() { return db; }
export function writeDB() {
  dirty = true;
  if (timer) return;
  timer = setTimeout(() => { timer = null; persistNow(); }, 40);
}
export function flushDB() { if (timer) { clearTimeout(timer); timer = null; } persistNow(); }
for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => { flushDB(); process.exit(0); });
process.on('exit', flushDB);

function seed() {
  const day = n => new Date(Date.now() - n * 864e5).toISOString().slice(0, 10);
  const t = now();
  const mk = (title, description, location_found, found_on) => ({ post_id: id('FND'), title, description, location_found, found_on, images: [], status: 'active', resolved: false, created_by: 'officestaff@team14.com', created_at: t, updated_at: t });
  return {
    users: DEMO_USERS.map(u => ({ ...u })),
    posts: [
      mk('Blue water bottle', 'Steel bottle with a blue lid. Small scratch near the base.', 'Library, 2nd floor', day(1)),
      mk('Wireless earbuds', 'White earbuds in a matte charging case.', 'Auditorium', day(1)),
      mk('Set of keys', 'Three silver keys on a green fabric keychain.', 'Canteen', day(2))
    ],
    claims: [],
    lost_requests: [{ request_id: id('LST'), title: 'Black umbrella', description: 'Folding, wooden handle', location_lost: 'Canteen', lost_on: day(2), status: 'active', created_by: 'student@team14.com', created_by_name: 'Student', created_by_role: 'student', created_by_phone_number: '9000000002', created_at: t, updated_at: t }],
    resolutions: []
  };
}

export function initDB() {
  db = parseFile(DB_FILE) || parseFile(BAK_FILE);
  if (!db || typeof db !== 'object') { db = seed(); dirty = true; }
  // Self-heal: make sure every collection exists and the four demo accounts are present with the right roles.
  for (const k of ['users', 'posts', 'claims', 'lost_requests', 'resolutions']) if (!Array.isArray(db[k])) { db[k] = []; dirty = true; }
  const legacy = { 'admin@team1.com': 'admin@team14.com', 'asha@team1.com': 'student@team14.com', 'faculty@team1.com': 'faculty@team14.com', 'ravi@team1.com': 'officestaff@team14.com' };
  const remap = v => legacy[v] || v;
  db.posts.forEach(p => { if (p.created_by) p.created_by = remap(p.created_by); });
  db.lost_requests.forEach(r => { if (r.created_by) r.created_by = remap(r.created_by); });
  db.claims.forEach(c => { if (c.claimant_email) c.claimant_email = remap(c.claimant_email); });
  db.resolutions.forEach(r => { if (r.resolved_by) r.resolved_by = remap(r.resolved_by); });
  db.users = DEMO_USERS.map(u => ({ ...u })); // no password hashes are stored; sign-in uses the OTP rule
  dirty = true;
  persistNow();
}
