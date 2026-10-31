// Same-origin by default: in production Express serves the UI and the API on one port,
// in dev Vite proxies /api to the server. No CORS, no wrong-port, no "failed to fetch".
const BASE = (import.meta.env.VITE_API_BASE || '/api/v1/findit').replace(/\/$/, '');
const safe = fn => { try { return fn(); } catch { return null; } };
export function getToken(){return safe(()=>localStorage.getItem('findit_token'))||''}
export function setSession(token,user){safe(()=>{localStorage.setItem('findit_token',token);localStorage.setItem('findit_user',JSON.stringify(user))})}
export function getUser(){return safe(()=>JSON.parse(localStorage.getItem('findit_user')||'null'))}
export function clearSession(){safe(()=>{localStorage.removeItem('findit_token');localStorage.removeItem('findit_user')})}

const wait = ms => new Promise(r => setTimeout(r, ms));
export const CONNECT_MSG = 'We can’t reach the CampusOS server yet. Make sure it is running (run “npm start” in the project folder) — this page will reconnect automatically.';

async function once(path, { method, body, form }, timeoutMs) {
  const headers = {};
  if (!form && body !== undefined) headers['Content-Type'] = 'application/json';
  const token = getToken();
  if (token) headers.Authorization = `Bearer ${token}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(`${BASE}${path.startsWith('/') ? path : `/${path}`}`, { method, headers, body: body === undefined ? undefined : form ? body : JSON.stringify(body), signal: controller.signal });
  } finally { clearTimeout(timer); }
}

export async function api(path, { method = 'GET', body, form = false } = {}) {
  let res;
  const isRead = method === 'GET';
  // Reads are retried quietly (covers the first second after the server starts). Writes are never retried (no duplicates).
  for (let attempt = 0; attempt < (isRead ? 3 : 1); attempt++) {
    try { res = await once(path, { method, body, form }, form ? 30000 : 10000); break; }
    catch (err) {
      if (attempt < (isRead ? 2 : 0)) { await wait(350 * (attempt + 1)); continue; }
      if (err?.name === 'AbortError') throw new Error('CampusOS is taking longer than usual to respond. Please try again.');
      throw Object.assign(new Error(CONNECT_MSG), { offline: true });
    }
  }
  if (res.status === 204) return null;
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    if (res.status === 401 && getToken()) window.dispatchEvent(new Event('campusos:unauthorized'));
    throw Object.assign(new Error(data.message || data.error || `Request failed (${res.status})`), { status: res.status, code: data.error });
  }
  return data;
}

export async function ping() {
  try { const r = await once('/health', { method: 'GET' }, 3000); return r.ok; } catch { return false; }
}
export { BASE };
