import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { initDB, readDB, writeDB, id, now, UPLOAD_DIR, DATA_DIR } from './store.js';

dotenv.config();
initDB();

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CLIENT_DIST = path.resolve(__dirname, '../../client/dist');
const BASE = '/api/v1/findit';
const START_PORT = Number(process.env.PORT) || 4000;
const DEMO_OTP = '967702'; // shared demo OTP required by the CampusOS rules
const CAMPUS_TZ = process.env.CAMPUS_TZ || 'Asia/Kolkata';

// ---- Secret: never ship a guessable default. Use .env, otherwise generate once and keep it. ----
function loadSecret() {
  const fromEnv = (process.env.JWT_SECRET || '').trim();
  if (fromEnv.length >= 16 && !fromEnv.startsWith('replace-this')) return fromEnv;
  const file = path.join(DATA_DIR, '.secret');
  try { const s = fs.readFileSync(file, 'utf8').trim(); if (s.length >= 32) return s; } catch {}
  const s = crypto.randomBytes(48).toString('hex');
  try { fs.writeFileSync(file, s, { mode: 0o600 }); } catch {}
  return s;
}
const SECRET = loadSecret();

const allowedOrigins = (process.env.CLIENT_ORIGIN || '').split(',').map(x => x.trim()).filter(Boolean);
const localOrigin = /^https?:\/\/(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$/;

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.set('etag', 'strong');

// ---- Compression (optional dependency: the app still runs if it is missing) ----
try { const { default: compression } = await import('compression'); app.use(compression({ threshold: 1024 })); } catch { /* fine */ }

// ---- Security headers ----
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-site');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
  res.setHeader('Content-Security-Policy', "default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; font-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'");
  next();
});

app.use(cors({
  origin(origin, cb) { cb(null, !origin || allowedOrigins.includes(origin) || localOrigin.test(origin)); },
  methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  maxAge: 600
}));
app.use(express.json({ limit: '200kb' }));

// ---- Tiny in-memory rate limiter (no extra dependency) ----
function limiter({ windowMs, max, keyFn, code = 'RATE_LIMITED', message = 'Too many requests. Please wait a moment and try again.' }) {
  const hits = new Map();
  setInterval(() => { const t = Date.now(); for (const [k, v] of hits) if (v.reset < t) hits.delete(k); }, windowMs).unref();
  const mw = (req, res, next) => {
    const key = keyFn(req), t = Date.now();
    let h = hits.get(key);
    if (!h || h.reset < t) { h = { n: 0, reset: t + windowMs }; hits.set(key, h); }
    h.n += 1;
    if (h.n > max) { res.setHeader('Retry-After', Math.ceil((h.reset - t) / 1000)); return fail(res, 429, code, message); }
    next();
  };
  mw.clear = key => hits.delete(key);
  return mw;
}
const fail = (res, status, code, message) => res.status(status).json({ error: code, message });
const ipOf = req => req.ip || req.socket?.remoteAddress || 'unknown';
const apiLimiter = limiter({ windowMs: 60_000, max: 600, keyFn: ipOf });
const loginLimiter = limiter({ windowMs: 10 * 60_000, max: 10, keyFn: req => `${ipOf(req)}|${String(req.body?.email || '').toLowerCase()}`, code: 'TOO_MANY_ATTEMPTS', message: 'Too many sign-in attempts. Try again in a few minutes.' });
const writeLimiter = limiter({ windowMs: 60_000, max: 120, keyFn: req => `${ipOf(req)}|${req.user?.email || ''}` });

// ---- Uploads: size/type limits + real file-signature check (the MIME header alone can be faked) ----
const ALLOWED_MIME = ['image/jpeg', 'image/png', 'image/webp'];
const EXT_BY_MIME = { 'image/jpeg': '.jpg', 'image/png': '.png', 'image/webp': '.webp' };
const upload = multer({
  storage: multer.diskStorage({
    destination: (_, __, cb) => cb(null, UPLOAD_DIR),
    filename: (_, file, cb) => cb(null, `${Date.now()}-${crypto.randomBytes(6).toString('hex')}${EXT_BY_MIME[file.mimetype] || '.bin'}`)
  }),
  limits: { fileSize: 5 * 1024 * 1024, files: 5, fields: 20, fieldSize: 10_000 },
  fileFilter: (_, file, cb) => ALLOWED_MIME.includes(file.mimetype) ? cb(null, true) : cb(new Error('INVALID_IMAGE_TYPE'))
});
function sniff(file) {
  try {
    const fd = fs.openSync(file.path, 'r'); const b = Buffer.alloc(12); fs.readSync(fd, b, 0, 12, 0); fs.closeSync(fd);
    if (file.mimetype === 'image/jpeg') return b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff;
    if (file.mimetype === 'image/png') return b.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]));
    if (file.mimetype === 'image/webp') return b.subarray(0, 4).toString() === 'RIFF' && b.subarray(8, 12).toString() === 'WEBP';
  } catch {}
  return false;
}
const dropFiles = files => (files || []).forEach(f => { try { fs.unlinkSync(f.path); } catch {} });
function checkImages(req, res, next) {
  if ((req.files || []).every(sniff)) return next();
  dropFiles(req.files);
  return fail(res, 400, 'INVALID_IMAGE_TYPE', 'Images must be real JPEG, PNG or WebP files.');
}
// Validation failure helper that also removes any files multer already saved.
const reject = (req, res, code, message, status = 400) => { dropFiles(req.files); return fail(res, status, code, message); };

// ---- Helpers ----
const isStr = v => typeof v === 'string';
const today = () => new Date().toLocaleDateString('en-CA', { timeZone: CAMPUS_TZ }); // YYYY-MM-DD in campus time
const future = d => !!d && d > today();
const validDate = d => /^\d{4}-\d{2}-\d{2}$/.test(d || '') && !Number.isNaN(Date.parse(`${d}T00:00:00Z`)) && new Date(`${d}T00:00:00Z`).toISOString().slice(0, 10) === d;
const cleanUser = u => ({ email: u.email, name: u.name, role: u.role, phone_number: u.phone_number });
const roleOfLost = ['student', 'faculty', 'office_staff'];

function auth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7).trim() : '';
  if (!token) return fail(res, 401, 'UNAUTHORIZED', 'Sign in to continue.');
  try {
    const payload = jwt.verify(token, SECRET, { algorithms: ['HS256'] });
    const user = readDB().users.find(u => u.email === payload.email);
    if (!user) return fail(res, 401, 'UNAUTHORIZED', 'Account not found.');
    req.user = cleanUser(user);
    next();
  } catch { return fail(res, 401, 'INVALID_TOKEN', 'Your session expired. Please sign in again.'); }
}
const staffOnly = (req, res, next) => req.user?.role === 'office_staff' ? next() : fail(res, 403, 'FORBIDDEN', 'Office staff permission required.');
const lostRole = (req, res, next) => roleOfLost.includes(req.user?.role) ? next() : fail(res, 403, 'FORBIDDEN', 'This role cannot report lost items.');
const ownerOfLost = (r, user) => r.created_by === user.email;
const roleCanSeeClaim = (claim, user) => user.role === 'office_staff' || claim.claimant_email === user.email;

function pagination(rows, limit, cursor, key) {
  const n = Math.min(100, Math.max(1, Number(limit) || 25));
  let start = 0;
  if (cursor) { const i = rows.findIndex(x => x[key] === cursor); start = i < 0 ? 0 : i + 1; }
  const page = rows.slice(start, start + n);
  return { items: page, next_cursor: start + n < rows.length ? page.at(-1)?.[key] || null : null, limit: n };
}
const withPostImages = files => (files || []).map(f => ({ image_id: id('IMG'), url: `${BASE}/uploads/${path.basename(f.filename)}`, content_type: f.mimetype }));
function removeFiles(images = []) {
  for (const image of images) {
    const name = path.basename(String(image.url || ''));
    const p = path.join(UPLOAD_DIR, name);
    if (name && p.startsWith(UPLOAD_DIR) && fs.existsSync(p)) { try { fs.unlinkSync(p); } catch {} }
  }
}
function postView(post, user, db) {
  const out = { ...post };
  if (user.role === 'office_staff') {
    const cs = db.claims.filter(c => c.post_id === post.post_id);
    out.total_claims = cs.length;
    out.pending_claims = cs.filter(c => c.decision === 'pending' && c.status === 'active').length;
  }
  return out;
}
function claimView(c, db) {
  const p = db.posts.find(x => x.post_id === c.post_id);
  return { ...c, post_title: p?.title || null, post_location: p?.location_found || null };
}
function statusFilter(q) { return q === 'archived' ? 'archived' : q === 'active' ? 'active' : null; }

// ---- Routes ----
app.use(BASE, apiLimiter);
app.get(`${BASE}/health`, (_, res) => { res.set('Cache-Control', 'no-store'); res.json({ ok: true, service: 'CampusOS API', time: now() }); });

app.post(`${BASE}/auth/login`, loginLimiter, (req, res) => {
  const email = isStr(req.body?.email) ? req.body.email.trim().toLowerCase() : '';
  const otp = isStr(req.body?.otp) ? req.body.otp.trim() : '';
  const user = readDB().users.find(u => u.email.toLowerCase() === email);
  const a = Buffer.from(otp.padEnd(32).slice(0, 32)), b = Buffer.from(DEMO_OTP.padEnd(32));
  const otpOk = crypto.timingSafeEqual(a, b) && otp.length === DEMO_OTP.length;
  if (!user || !otpOk) return fail(res, 401, 'INVALID_CREDENTIALS', 'Email or OTP is incorrect.');
  loginLimiter.clear(`${ipOf(req)}|${email}`);
  const token = jwt.sign({ email: user.email }, SECRET, { algorithm: 'HS256', expiresIn: '12h' });
  res.set('Cache-Control', 'no-store');
  res.json({ token, user: cleanUser(user) });
});
app.get(`${BASE}/auth/me`, auth, (req, res) => res.json({ user: req.user }));
app.get(`${BASE}/auth/demo-accounts`, (_, res) => res.json({ accounts: readDB().users.map(u => ({ email: u.email, name: u.name, role: u.role })), otp: DEMO_OTP }));

// One request returns everything a screen needs: fast navigation, no waterfalls.
app.get(`${BASE}/dashboard`, auth, (req, res) => {
  const db = readDB(), staff = req.user.role === 'office_staff', sf = statusFilter(req.query.status);
  let posts = db.posts.filter(p => (sf ? p.status === sf : (staff || p.status === 'active')));
  let lost = db.lost_requests.filter(r => !sf || r.status === sf);
  if (!staff || req.query.mine === 'true') lost = lost.filter(r => ownerOfLost(r, req.user));
  const claims = db.claims.filter(c => c.claimant_email === req.user.email).map(c => claimView(c, db));
  res.set('Cache-Control', 'no-store');
  res.json({ posts: posts.map(p => postView(p, req.user, db)), lost_requests: lost, claims });
});

// Found posts
app.post(`${BASE}/posts`, auth, staffOnly, writeLimiter, upload.array('images', 5), checkImages, (req, res) => {
  const b = req.body || {};
  const title = isStr(b.title) ? b.title.trim() : '', loc = isStr(b.location_found) ? b.location_found.trim() : '';
  const description = isStr(b.description) ? b.description.trim() : '';
  if (title.length < 3 || title.length > 100) return reject(req, res, 'VALIDATION_ERROR', 'title must be 3–100 characters.');
  if (loc.length < 2 || loc.length > 120) return reject(req, res, 'VALIDATION_ERROR', 'location_found must be 2–120 characters.');
  if (!validDate(b.found_on) || future(b.found_on)) return reject(req, res, 'VALIDATION_ERROR', 'found_on must be a valid date that is not in the future.');
  if (description.length > 2000) return reject(req, res, 'VALIDATION_ERROR', 'description must be at most 2000 characters.');
  const db = readDB(), t = now();
  const post = { post_id: id('FND'), title, description, location_found: loc, found_on: b.found_on, images: withPostImages(req.files), status: 'active', resolved: false, created_by: req.user.email, created_at: t, updated_at: t };
  db.posts.unshift(post); writeDB();
  res.status(201).json(post);
});
app.get(`${BASE}/posts`, auth, (req, res) => {
  const db = readDB(), status = req.query.status === 'archived' ? 'archived' : 'active';
  let rows = db.posts.filter(p => p.status === status);
  if (req.query.q) { const q = String(req.query.q).toLowerCase(); rows = rows.filter(p => `${p.title} ${p.description} ${p.location_found}`.toLowerCase().includes(q)); }
  const page = pagination(rows, req.query.limit, req.query.cursor, 'post_id');
  res.json({ ...page, items: page.items.map(p => postView(p, req.user, db)) });
});
app.get(`${BASE}/posts/:post_id`, auth, (req, res) => {
  const db = readDB(), p = db.posts.find(x => x.post_id === req.params.post_id);
  if (!p) return fail(res, 404, 'NOT_FOUND', 'Found post not found.');
  res.json(postView(p, req.user, db));
});
app.patch(`${BASE}/posts/:post_id`, auth, staffOnly, writeLimiter, upload.array('images', 5), checkImages, (req, res) => {
  const db = readDB(), p = db.posts.find(x => x.post_id === req.params.post_id);
  if (!p) return reject(req, res, 'NOT_FOUND', 'Found post not found.', 404);
  const b = req.body || {};
  if (p.resolved && b.status === 'active') return reject(req, res, 'POST_RESOLVED', 'Undo the resolution before reopening this post.', 409);
  for (const k of ['title', 'description', 'location_found', 'found_on', 'status']) if (b[k] !== undefined && !isStr(b[k])) return reject(req, res, 'VALIDATION_ERROR', `${k} must be text.`);
  if (b.title !== undefined && (b.title.trim().length < 3 || b.title.trim().length > 100)) return reject(req, res, 'VALIDATION_ERROR', 'title must be 3–100 characters.');
  if (b.description !== undefined && b.description.length > 2000) return reject(req, res, 'VALIDATION_ERROR', 'description must be at most 2000 characters.');
  if (b.location_found !== undefined && (b.location_found.trim().length < 2 || b.location_found.trim().length > 120)) return reject(req, res, 'VALIDATION_ERROR', 'location_found must be 2–120 characters.');
  if (b.found_on !== undefined && (!validDate(b.found_on) || future(b.found_on))) return reject(req, res, 'VALIDATION_ERROR', 'found_on must be a valid non-future date.');
  if (b.status !== undefined && !['active', 'archived'].includes(b.status)) return reject(req, res, 'VALIDATION_ERROR', 'status must be active or archived.');
  if (b.title !== undefined) p.title = b.title.trim();
  if (b.description !== undefined) p.description = b.description.trim();
  if (b.location_found !== undefined) p.location_found = b.location_found.trim();
  if (b.found_on !== undefined) p.found_on = b.found_on;
  if (req.files?.length) { removeFiles(p.images); p.images = withPostImages(req.files); }
  else if (String(b.remove_images) === 'true') { removeFiles(p.images); p.images = []; }
  if (b.status && b.status !== p.status) {
    p.status = b.status;
    db.claims.filter(c => c.post_id === p.post_id).forEach(c => { c.status = b.status; });
  }
  p.updated_at = now(); writeDB();
  res.json(p);
});
app.delete(`${BASE}/posts/:post_id`, auth, staffOnly, writeLimiter, (req, res) => {
  const db = readDB(), i = db.posts.findIndex(x => x.post_id === req.params.post_id);
  if (i < 0) return fail(res, 404, 'NOT_FOUND', 'Found post not found.');
  if (db.claims.some(c => c.post_id === req.params.post_id && c.decision === 'pending' && c.status === 'active')) return fail(res, 409, 'POST_HAS_PENDING_CLAIMS', 'This post has pending claims. Resolve or otherwise handle them first.');
  removeFiles(db.posts[i].images);
  db.posts.splice(i, 1);
  db.claims = db.claims.filter(c => c.post_id !== req.params.post_id);
  db.resolutions = db.resolutions.filter(r => r.post_id !== req.params.post_id);
  writeDB(); res.status(204).end();
});

// Claims
app.post(`${BASE}/posts/:post_id/claims`, auth, writeLimiter, (req, res) => {
  const db = readDB(), post = db.posts.find(p => p.post_id === req.params.post_id);
  if (!post) return fail(res, 404, 'NOT_FOUND', 'Found post not found.');
  if (post.status !== 'active' || post.resolved) return fail(res, 409, 'POST_NOT_CLAIMABLE', 'This item is not available to claim.');
  const message = isStr(req.body?.message) ? req.body.message.trim() : '';
  if (message.length < 10 || message.length > 1000) return fail(res, 400, 'VALIDATION_ERROR', 'message must be 10–1000 characters.');
  if (db.claims.some(c => c.post_id === post.post_id && c.claimant_email === req.user.email)) return fail(res, 409, 'CLAIM_ALREADY_EXISTS', 'You can submit only one claim per post.');
  const t = now();
  const claim = { claim_id: id('CLM'), post_id: post.post_id, claimant_email: req.user.email, claimant_name: req.user.name, claimant_role: req.user.role, claimant_phone_number: req.user.phone_number, message, status: 'active', decision: 'pending', created_at: t, updated_at: t };
  db.claims.unshift(claim); writeDB();
  res.status(201).json(claimView(claim, db));
});
app.get(`${BASE}/posts/:post_id/claims`, auth, (req, res) => {
  const db = readDB();
  if (!db.posts.some(p => p.post_id === req.params.post_id)) return fail(res, 404, 'NOT_FOUND', 'Found post not found.');
  res.json({ items: db.claims.filter(c => c.post_id === req.params.post_id && roleCanSeeClaim(c, req.user)).map(c => claimView(c, db)) });
});
app.get(`${BASE}/claims/me`, auth, (req, res) => {
  const db = readDB(), rows = db.claims.filter(c => c.claimant_email === req.user.email).map(c => claimView(c, db));
  res.json(pagination(rows, req.query.limit, req.query.cursor, 'claim_id'));
});
app.get(`${BASE}/claims/:claim_id`, auth, (req, res) => {
  const db = readDB(), c = db.claims.find(x => x.claim_id === req.params.claim_id);
  if (!c) return fail(res, 404, 'NOT_FOUND', 'Claim not found.');
  if (!roleCanSeeClaim(c, req.user)) return fail(res, 403, 'FORBIDDEN', 'You can only view your own claim.');
  res.json(claimView(c, db));
});
app.delete(`${BASE}/claims/:claim_id`, auth, writeLimiter, (req, res) => {
  const db = readDB(), c = db.claims.find(x => x.claim_id === req.params.claim_id);
  if (!c) return fail(res, 404, 'NOT_FOUND', 'Claim not found.');
  if (c.claimant_email !== req.user.email) return fail(res, 403, 'FORBIDDEN', 'You can only withdraw your own claim.');
  if (c.decision !== 'pending' || c.status !== 'active') return fail(res, 409, 'CLAIM_NOT_WITHDRAWABLE', 'Only active pending claims can be withdrawn.');
  c.status = 'archived'; c.updated_at = now(); writeDB(); res.status(204).end();
});

// Resolution
function canSeeResolution(user, resolution, db) {
  if (user.role === 'office_staff') return true;
  const claim = db.claims.find(c => c.claim_id === resolution.claim_id);
  return claim?.claimant_email === user.email;
}
app.post(`${BASE}/posts/:post_id/resolution`, auth, staffOnly, writeLimiter, (req, res) => {
  const db = readDB(), p = db.posts.find(x => x.post_id === req.params.post_id);
  if (!p) return fail(res, 404, 'NOT_FOUND', 'Found post not found.');
  const claim = db.claims.find(c => c.claim_id === req.body?.claim_id && c.post_id === p.post_id);
  if (!claim || claim.status !== 'active' || claim.decision !== 'pending') return fail(res, 400, 'INVALID_CLAIM', 'Choose an active pending claim for this post.');
  const t = now();
  db.claims.filter(c => c.post_id === p.post_id).forEach(c => { c.decision = c.claim_id === claim.claim_id ? 'approved' : 'rejected'; c.status = 'archived'; c.updated_at = t; });
  p.status = 'archived'; p.resolved = true; p.updated_at = t;
  let r = db.resolutions.find(x => x.post_id === p.post_id);
  if (!r) { r = { post_id: p.post_id }; db.resolutions.push(r); }
  Object.assign(r, { claim_id: claim.claim_id, note: String(req.body.note || '').slice(0, 1000), resolved_by: req.user.email, resolved_at: t, updated_at: t });
  writeDB(); res.status(201).json({ post: postView(p, req.user, db), resolution: r });
});
app.get(`${BASE}/posts/:post_id/resolution`, auth, (req, res) => {
  const db = readDB(), p = db.posts.find(x => x.post_id === req.params.post_id), r = db.resolutions.find(x => x.post_id === req.params.post_id);
  if (!p) return fail(res, 404, 'NOT_FOUND', 'Found post not found.');
  if (!r) return fail(res, 404, 'RESOLUTION_NOT_FOUND', 'This post has not been resolved.');
  if (!canSeeResolution(req.user, r, db)) return fail(res, 403, 'FORBIDDEN', 'Resolution details are not available to this account.');
  res.json(r);
});
app.patch(`${BASE}/posts/:post_id/resolution`, auth, staffOnly, writeLimiter, (req, res) => {
  const db = readDB(), p = db.posts.find(x => x.post_id === req.params.post_id), r = db.resolutions.find(x => x.post_id === req.params.post_id);
  if (!p || !r) return fail(res, 404, 'RESOLUTION_NOT_FOUND', 'Resolution not found.');
  const claimId = req.body?.claim_id || r.claim_id, claim = db.claims.find(c => c.claim_id === claimId && c.post_id === p.post_id);
  if (!claim) return fail(res, 400, 'INVALID_CLAIM', 'Choose a claim belonging to this post.');
  const t = now();
  db.claims.filter(c => c.post_id === p.post_id).forEach(c => { c.decision = c.claim_id === claim.claim_id ? 'approved' : 'rejected'; c.status = 'archived'; c.updated_at = t; });
  r.claim_id = claim.claim_id; if (req.body.note !== undefined) r.note = String(req.body.note).slice(0, 1000);
  r.resolved_by = req.user.email; r.resolved_at = t; r.updated_at = t;
  p.status = 'archived'; p.resolved = true; p.updated_at = t; writeDB();
  res.json(r);
});
app.delete(`${BASE}/posts/:post_id/resolution`, auth, staffOnly, writeLimiter, (req, res) => {
  const db = readDB(), p = db.posts.find(x => x.post_id === req.params.post_id), i = db.resolutions.findIndex(r => r.post_id === req.params.post_id);
  if (!p || i < 0) return fail(res, 404, 'RESOLUTION_NOT_FOUND', 'Resolution not found.');
  const t = now();
  db.resolutions.splice(i, 1); p.status = 'active'; p.resolved = false; p.updated_at = t;
  db.claims.filter(c => c.post_id === p.post_id).forEach(c => { c.status = 'active'; c.decision = 'pending'; c.updated_at = t; });
  writeDB(); res.status(204).end();
});

// Lost requests
app.post(`${BASE}/lost-requests`, auth, lostRole, writeLimiter, (req, res) => {
  const b = req.body || {};
  const title = isStr(b.title) ? b.title.trim() : '', description = isStr(b.description) ? b.description.trim() : '', location_lost = isStr(b.location_lost) ? b.location_lost.trim() : '';
  const lost_on = isStr(b.lost_on) && b.lost_on ? b.lost_on : null;
  if (title.length < 3 || title.length > 100) return fail(res, 400, 'VALIDATION_ERROR', 'title must be 3–100 characters.');
  if (description.length > 2000) return fail(res, 400, 'VALIDATION_ERROR', 'description must be at most 2000 characters.');
  if (location_lost.length > 120) return fail(res, 400, 'VALIDATION_ERROR', 'location_lost must be at most 120 characters.');
  if (lost_on && (!validDate(lost_on) || future(lost_on))) return fail(res, 400, 'VALIDATION_ERROR', 'lost_on must be a valid non-future date.');
  const t = now(), db = readDB();
  const r = { request_id: id('LST'), title, description, location_lost, lost_on, status: 'active', created_by: req.user.email, created_by_name: req.user.name, created_by_role: req.user.role, created_by_phone_number: req.user.phone_number, created_at: t, updated_at: t };
  db.lost_requests.unshift(r); writeDB(); res.status(201).json(r);
});
app.get(`${BASE}/lost-requests`, auth, (req, res) => {
  const db = readDB(), status = req.query.status === 'archived' ? 'archived' : 'active';
  let rows = db.lost_requests.filter(r => r.status === status);
  if (req.user.role !== 'office_staff' || req.query.mine === 'true') rows = rows.filter(r => ownerOfLost(r, req.user));
  res.json(pagination(rows, req.query.limit, req.query.cursor, 'request_id'));
});
app.get(`${BASE}/lost-requests/:request_id`, auth, (req, res) => {
  const db = readDB(), r = db.lost_requests.find(x => x.request_id === req.params.request_id);
  if (!r) return fail(res, 404, 'NOT_FOUND', 'Lost request not found.');
  if (req.user.role !== 'office_staff' && !ownerOfLost(r, req.user)) return fail(res, 403, 'FORBIDDEN', 'You can only view your own lost request.');
  res.json(r);
});
app.patch(`${BASE}/lost-requests/:request_id`, auth, writeLimiter, (req, res) => {
  const db = readDB(), r = db.lost_requests.find(x => x.request_id === req.params.request_id);
  if (!r) return fail(res, 404, 'NOT_FOUND', 'Lost request not found.');
  if (!ownerOfLost(r, req.user) && req.user.role !== 'office_staff') return fail(res, 403, 'FORBIDDEN', 'Only the owner or office staff can edit this request.');
  const b = req.body || {};
  for (const k of ['title', 'description', 'location_lost', 'status']) if (b[k] !== undefined && !isStr(b[k])) return fail(res, 400, 'VALIDATION_ERROR', `${k} must be text.`);
  if (b.title !== undefined && (b.title.trim().length < 3 || b.title.trim().length > 100)) return fail(res, 400, 'VALIDATION_ERROR', 'title must be 3–100 characters.');
  if (b.description !== undefined && b.description.length > 2000) return fail(res, 400, 'VALIDATION_ERROR', 'description must be at most 2000 characters.');
  if (b.location_lost !== undefined && b.location_lost.length > 120) return fail(res, 400, 'VALIDATION_ERROR', 'location_lost must be at most 120 characters.');
  if (b.lost_on !== undefined && b.lost_on !== null && b.lost_on !== '' && (!isStr(b.lost_on) || !validDate(b.lost_on) || future(b.lost_on))) return fail(res, 400, 'VALIDATION_ERROR', 'lost_on must be a valid non-future date.');
  if (b.status !== undefined && !['active', 'archived'].includes(b.status)) return fail(res, 400, 'VALIDATION_ERROR', 'status must be active or archived.');
  for (const k of ['title', 'description', 'location_lost']) if (b[k] !== undefined) r[k] = b[k].trim();
  if (b.lost_on !== undefined) r.lost_on = b.lost_on || null;
  if (b.status !== undefined) r.status = b.status;
  r.updated_at = now(); writeDB(); res.json(r);
});
app.delete(`${BASE}/lost-requests/:request_id`, auth, writeLimiter, (req, res) => {
  const db = readDB(), i = db.lost_requests.findIndex(x => x.request_id === req.params.request_id);
  if (i < 0) return fail(res, 404, 'NOT_FOUND', 'Lost request not found.');
  if (!ownerOfLost(db.lost_requests[i], req.user)) return fail(res, 403, 'FORBIDDEN', 'Only the owner can delete this request.');
  db.lost_requests.splice(i, 1); writeDB(); res.status(204).end();
});

// Uploaded images (random, unguessable names; served as images only; cached hard)
app.use(`${BASE}/uploads`, express.static(UPLOAD_DIR, { index: false, dotfiles: 'deny', maxAge: '7d', immutable: true, setHeaders: res => res.setHeader('Content-Disposition', 'inline') }));

// Unknown API route -> clean JSON (never an HTML error page)
app.use('/api', (req, res) => fail(res, 404, 'NOT_FOUND', 'That API route does not exist.'));

// ---- Serve the built React app from the same server (one port, no CORS, no "cannot connect") ----
const hasClient = fs.existsSync(path.join(CLIENT_DIST, 'index.html'));
if (hasClient) {
  app.use('/assets', express.static(path.join(CLIENT_DIST, 'assets'), { maxAge: '1y', immutable: true, index: false }));
  app.use(express.static(CLIENT_DIST, { maxAge: '1h', index: false }));
  app.get(/^\/(?!api\/).*/, (req, res) => { res.set('Cache-Control', 'no-cache'); res.sendFile(path.join(CLIENT_DIST, 'index.html')); });
} else {
  app.get('/', (_, res) => res.type('html').send('<h2>CampusOS API is running</h2><p>Build the frontend with <code>npm run build</code> (or run <code>npm start</code> from the project root), or use <code>npm run dev</code> and open http://localhost:5173.</p>'));
}

// ---- Error handling: always JSON, never a stack trace ----
app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  if (req.files) dropFiles(req.files);
  if (err instanceof multer.MulterError) {
    const map = { LIMIT_FILE_SIZE: ['FILE_TOO_LARGE', 'Each image must be 5 MB or smaller.'], LIMIT_FILE_COUNT: ['TOO_MANY_FILES', 'You can upload up to 5 images.'], LIMIT_UNEXPECTED_FILE: ['TOO_MANY_FILES', 'You can upload up to 5 images.'] };
    const [code, msg] = map[err.code] || ['UPLOAD_ERROR', err.message];
    return fail(res, 400, code, msg);
  }
  if (err.message === 'INVALID_IMAGE_TYPE') return fail(res, 400, 'INVALID_IMAGE_TYPE', 'Images must be JPEG, PNG or WebP.');
  if (err.type === 'entity.parse.failed') return fail(res, 400, 'BAD_JSON', 'The request body is not valid JSON.');
  if (err.type === 'entity.too.large') return fail(res, 413, 'PAYLOAD_TOO_LARGE', 'The request is too large.');
  console.error(err);
  return fail(res, 500, 'INTERNAL_ERROR', 'An unexpected server error occurred.');
});
process.on('unhandledRejection', e => console.error('Unhandled rejection:', e));
process.on('uncaughtException', e => console.error('Uncaught exception:', e));

// ---- Start (if the port is busy, move to the next free one instead of crashing) ----
function listen(port, tries = 0) {
  const server = app.listen(port, () => {
    console.log(`\n  CampusOS is running\n  → Open: http://localhost:${port}${hasClient ? '' : '  (API only - frontend not built)'}\n  → Health: http://localhost:${port}${BASE}/health\n`);
  });
  server.on('error', err => {
    if (err.code === 'EADDRINUSE' && tries < 10) { console.log(`Port ${port} is busy, trying ${port + 1}…`); return listen(port + 1, tries + 1); }
    console.error('Server failed to start:', err.message); process.exit(1);
  });
  server.keepAliveTimeout = 65_000;
}
listen(START_PORT);
