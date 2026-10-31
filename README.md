# CampusOS — Campus Lost & Found

React + Vite frontend, Node + Express API, persistent JSON storage. **One command, one port.**

## Run (2 steps)
Requires Node.js 18+ (20+ recommended).

```bash
npm install     # installs root, server and client automatically
npm start       # builds the UI the first time, then serves everything
```
Open **http://localhost:4000** (the terminal prints the exact URL; if 4000 is busy it picks the next free port).

Because the UI and API share one origin there is no CORS, no wrong-port and no "Could not connect to the server" error.

Developer mode with hot reload: `npm run dev` → http://localhost:5173 (Vite proxies `/api` to the server).

## Demo accounts (OTP for all: `967702`)
`admin@team14.com` · `student@team14.com` · `faculty@team14.com` · `officestaff@team14.com`

## What was fixed / improved
**Reliability**
- Single-command start; frontend uses a relative API path (no `localhost:4000` hard-coding).
- Login screen shows a live "Server connected / Connecting…" status and auto-retries instead of an error box.
- Read requests retry quietly; write requests never retry (no duplicate posts/claims).
- Crash-safe database: in-memory with atomic saves + automatic backup; self-heals if a file is damaged.
- Port-in-use handling, JSON-only error responses, React error boundary (never a blank page), expired sessions log out cleanly.
- Future-date check uses campus time (Asia/Kolkata, override with `CAMPUS_TZ`) — fixes false "date in the future" errors near midnight.

**Speed**
- DB served from memory; one `/dashboard` request loads a whole screen; tab changes are instant (filtered client-side).
- gzip compression, long-term caching of built assets, lazy images, no external font download (works offline / on slow campus Wi-Fi).

**Security**
- Strong JWT secret auto-generated if not provided; HS256 pinned; 12 h expiry.
- Login rate-limit + timing-safe OTP check; global and write rate-limits.
- Security headers + strict Content-Security-Policy, no framing, nosniff.
- Uploads: 5 files × 5 MB, JPEG/PNG/WebP by MIME **and real file signature**, random file names, orphan cleanup on failed requests.
- All inputs type-checked (no crashes from malformed bodies); role checks on every protected route; CORS locked to same-origin/localhost.

**UI bugs fixed**
- Photos are now shown on item cards.
- "My claims" shows the item title even after the post is archived/resolved.
- Review-claims table shows real pending/total counts; sidebar badge is accurate.
- Staff can change the approved claim on a resolved post ("Approve instead").
- Lost requests have Active/Archived views; Overview no longer empties after visiting Archive.
- Location filter is built from real data; client-side photo validation; toast timer bug removed.

## API rules implemented
Base path `/api/v1/findit` — office staff only create/edit/archive/delete found posts and resolve; every role can claim once per post; claimant can withdraw own pending claim; staff see all claims, others only their own; resolution approves one claim and rejects/archives the rest; undo reactivates; changing a resolution recalculates; `409 POST_HAS_PENDING_CLAIMS` on delete; max 5 images ≤ 5 MB; lost requests for student/faculty/staff.

## Notes
JSON file storage suits a demo. For production use PostgreSQL, cloud image storage, real SSO/OTP delivery and HTTPS. The shared OTP exists only because the hackathon rules require it.
