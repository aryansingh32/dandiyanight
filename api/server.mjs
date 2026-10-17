// Dandiya Night API — a thin, stateless layer in front of the Postgres functions.
// All business rules (atomic check-in, permissions, validation) live in the database; this adds
// Google identity, rate limiting, CORS and a health endpoint. Point DATABASE_URL at Supabase or the VM.
import { createHash, randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import Fastify from 'fastify';
import cors from '@fastify/cors';
import rateLimit from '@fastify/rate-limit';
import compress from '@fastify/compress';
import pg from 'pg';
import { OAuth2Client } from 'google-auth-library';
import { makeRazorpay, mapMethod } from './razorpay.mjs';
import { makeChat } from './chat.mjs';
import { checkMessage } from './chat-filter.mjs';
import { makeFirebase } from './firebase.mjs';
import { makeProofStorage } from './proof-storage.mjs';

export function buildApp(env = process.env) {
  const { DATABASE_URL, GOOGLE_CLIENT_ID = '', CORS_ORIGIN = '', DEV_AUTH = '' } = env;
  if (!DATABASE_URL) throw new Error('DATABASE_URL is required');
  const devAuth = DEV_AUTH === '1';
  const production = env.NODE_ENV === 'production';
  // Fail closed: settings that are only safe on a developer's machine refuse to start in production.
  if (production && devAuth) throw new Error('DEV_AUTH=1 is not allowed when NODE_ENV=production (anyone could sign in as anyone).');
  if (production && env.DEMO_CHECKOUT === '1') throw new Error('DEMO_CHECKOUT=1 is not allowed when NODE_ENV=production (passes without payment).');
  if (production && !CORS_ORIGIN.trim()) throw new Error('Set CORS_ORIGIN to the site address(es) in production.');
  if (!GOOGLE_CLIENT_ID && !devAuth) console.warn('[api] GOOGLE_CLIENT_ID is not set — Google sign-in will be refused');

  // Supabase needs TLS; a Postgres on the same machine or private network (a VM standby) usually has none — PGSSL=off says so.
  const ssl = env.PGSSL === 'off' || DATABASE_URL.includes('localhost') || DATABASE_URL.includes('127.0.0.1') ? false : { rejectUnauthorized: false };
  const pool = new pg.Pool({
    connectionString: DATABASE_URL, ssl,
    max: Number(env.PG_POOL_MAX ?? 20), idleTimeoutMillis: 30_000, connectionTimeoutMillis: 10_000, statement_timeout: 15_000,
  });
  pool.on('error', e => console.error('[pg] idle client error', e.message));
  // Staff (gate scanners, finance, admins) get their own few connections, so a student rush can never make a scan or an approval wait in line.
  const staffPool = new pg.Pool({
    connectionString: DATABASE_URL, ssl,
    max: Number(env.PG_STAFF_POOL_MAX ?? 8), idleTimeoutMillis: 30_000, connectionTimeoutMillis: 10_000, statement_timeout: 20_000,
  });
  staffPool.on('error', e => console.error('[pg] idle staff client error', e.message));
  const google = new OAuth2Client();
  // Razorpay is RETIRED: payments are manual (UPI QR + UTR + screenshot, or cash) and confirmed in the admin panel.
  // The integration below is kept but stays switched off unless ENABLE_RAZORPAY=1 *and* its keys are set.
  const rzp = makeRazorpay(env.ENABLE_RAZORPAY === '1' ? env : { ...env, RAZORPAY_KEY_ID: '', RAZORPAY_KEY_SECRET: '', RAZORPAY_WEBHOOK_SECRET: '' });
  const demoCheckout = env.DEMO_CHECKOUT === '1' && !rzp.enabled;      // the old test checkout: development only, never in production
  // Firebase is optional and loaded on first use, so the API starts (and tests run) without it.
  let fbReady; const fbGet = () => (fbReady ??= makeFirebase(env));
  const firebase = Object.fromEntries(['verifyIdToken', 'pushMessages', 'resetLive', 'setStatus', 'prune', 'sendPush', 'subscribe', 'saveFile', 'readFile', 'hasFile'].map(k => [k, async (...a) => (await fbGet())[k](...a)]));
  if (rzp.enabled && !rzp.webhookEnabled) console.warn('[api] RAZORPAY_WEBHOOK_SECRET is not set — payments are confirmed only when the student returns to the site');
  /** Public payment settings merged into what the browser is told. With Razorpay on, the demo checkout is off. */
  const gateway = info => (info ? { ...info, razorpay: rzp.enabled, ...(rzp.enabled ? { razorpayKeyId: rzp.keyId, testMode: false } : {}) } : info);

  // Only trust X-Forwarded-For from a known number of proxy hops (e.g. TRUST_PROXY=1 behind Railway/Cloudflare).
  // Trusting it blindly would let anyone fake their IP and dodge every per-IP limit.
  const trustProxy = /^\d+$/.test(env.TRUST_PROXY ?? '') ? Number(env.TRUST_PROXY) : false;
  const app = Fastify({ logger: { level: env.LOG_LEVEL ?? 'info', redact: ['req.headers.authorization', 'req.headers.cookie'] }, trustProxy, bodyLimit: 100_000, connectionTimeout: 30_000, keepAliveTimeout: 65_000, requestTimeout: 30_000, maxRequestsPerSocket: 5000, onProtoPoisoning: 'error', onConstructorPoisoning: 'error', return503OnClosing: true });

  const origins = CORS_ORIGIN.split(',').map(s => s.trim()).filter(Boolean);
  /** Answers sent from an early hook skip the CORS plugin, so they carry the allow-origin header themselves — otherwise the browser reports "network error" instead of the real 401 / 429 / 503. */
  const withCors = (req, reply) => {
    const o = req.headers.origin;
    if (o && (!origins.length || origins.includes(o))) reply.header('access-control-allow-origin', o).header('vary', 'Origin');
    return reply;
  };
  /* ── scanners & token-rotation: an IP that keeps presenting bad sessions or hitting unknown routes is shut out for a while ── */
  const strikes = new Map();       // ip → { n, reset, until, synced }
  const STRIKE_LIMIT = Number(env.STRIKE_LIMIT ?? 300), STRIKE_WINDOW = 60_000;
  const shared = new Map();        // ip → until: blocks recorded in the database, so every API instance (and the admin panel) agrees
  const blocked = ip => { const e = strikes.get(ip); return (!!e && e.until > Date.now()) || (shared.get(ip) ?? 0) > Date.now(); };
  function strike(ip, weight = 1) {
    const now = Date.now(); let e = strikes.get(ip);
    if (!e || e.reset < now) { e = { n: 0, reset: now + STRIKE_WINDOW, until: 0, synced: false }; strikes.set(ip, e); }
    e.n += weight;
    if (e.n >= STRIKE_LIMIT && e.until < now) {
      e.until = now + 15 * 60_000; e.synced = false;                    // 15 minutes at once; the database decides repeat offenders get 30, then 60
      app.log.warn(`[guard] blocking ${ip} after ${Math.round(e.n)} bad requests`);
      void call('api_ip_block_add', [ip, `${Math.round(e.n)} bad requests in a minute`, 'auto', null]).then(r => { if (r?.seconds) e.until = Date.now() + r.seconds * 1000; e.synced = true; }).catch(() => { e.synced = false; });
    }
    if (strikes.size > 20_000) for (const [k, v] of strikes) if (v.reset < now && v.until < now) strikes.delete(k);
  }
  async function syncBlocks() {                                         // admin unblocks and other instances' blocks arrive within a few seconds
    try {
      const rows = await call('api_ip_blocks_active'); const now = Date.now(); shared.clear();
      for (const r of rows ?? []) shared.set(r.ip, new Date(r.until).getTime());
      for (const [ip, e] of strikes) if (e.until > now && e.synced && !shared.has(ip)) e.until = 0;      // lifted by an admin
    } catch { /* keep the last list */ }
  }
  app.addHook('onRequest', async (req, reply) => {
    if (blocked(req.ip)) return withCors(req, reply).code(429).header('retry-after', '900').send({ ok: false, error: 'Too many bad requests from this network. Try again in a few minutes.' });
  });
  /* ── who is on the site right now: counted in memory, written to the database every few seconds in one batch ── */
  const visitors = new Map();
  const deviceOf = ua => {
    const u = String(ua ?? ''); if (!u) return 'Unknown';
    const br = /Edg\//.test(u) ? 'Edge' : /OPR\/|Opera/.test(u) ? 'Opera' : /SamsungBrowser/.test(u) ? 'Samsung Internet' : /Firefox\//.test(u) ? 'Firefox' : /(CriOS|Chrome)\//.test(u) ? 'Chrome' : /Safari\//.test(u) ? 'Safari' : /bot|crawl|spider|curl|python|node|axios|wget/i.test(u) ? 'Bot/script' : 'Browser';
    const os = /Android ([\d.]+)/.exec(u) ? `Android ${/Android ([\d.]+)/.exec(u)[1].split('.')[0]}` : /iPhone|iPad|iPod/.test(u) ? 'iOS' : /Windows NT/.test(u) ? 'Windows' : /Mac OS X/.test(u) ? 'macOS' : /CrOS/.test(u) ? 'ChromeOS' : /Linux/.test(u) ? 'Linux' : '';
    return `${br}${os ? ' · ' + os : ''}${/Mobile|Android|iPhone/.test(u) ? ' (phone)' : ''}`;
  };
  function noteVisit(req, status, errText) {
    const url = req.url; if (req.method === 'OPTIONS' || url.startsWith('/health')) return;
    const device = deviceOf(req.headers['user-agent']); const key = `${req.ip}|${device}`; const now = Date.now();
    let v = visitors.get(key);
    if (!v) { if (visitors.size > 30_000) return; v = { key, ip: req.ip, device, first: now, last: now, hits: 0, errors: 0, lastError: '', lastErrorAt: 0, page: '', dirty: false }; visitors.set(key, v); }
    v.last = now; v.hits++; v.dirty = true;
    if (status >= 400 && status !== 429) { v.errors++; v.lastError = `${status} ${req.method} ${url.split('?')[0].replace(/[a-f0-9]{24,}/gi, ':id').slice(0, 60)}${errText ? ' — ' + errText.slice(0, 70) : ''}`; v.lastErrorAt = now; }
    else if (status === 429) { v.errors++; v.lastError = `429 Rate limited ${url.split('?')[0].slice(0, 50)}`; v.lastErrorAt = now; }
  }
  async function flushVisitors() {
    const now = Date.now(); const rows = [];
    for (const v of visitors.values()) {
      if (v.dirty) { rows.push({ key: v.key, ip: v.ip, device: v.device, first: new Date(v.first).toISOString(), last: new Date(v.last).toISOString(), hits: v.hits, errors: v.errors, lastError: v.lastError, lastErrorAt: v.lastErrorAt ? new Date(v.lastErrorAt).toISOString() : '', page: v.page }); v.hits = 0; v.errors = 0; v.dirty = false; v.lastError = ''; v.lastErrorAt = 0; }
      else if (now - v.last > 5 * 60_000) visitors.delete(v.key);
    }
    for (let i = 0; i < rows.length; i += 400) { try { await call('api_visitors_flush', [JSON.stringify(rows.slice(i, i + 400))]); } catch (e) { app.log.warn(`[visitors] flush failed: ${e.message}`); break; } }
    return rows.length;
  }
  app.decorate('flushVisitors', flushVisitors); app.decorate('syncBlocks', syncBlocks);
  if (env.NODE_ENV !== 'test') {
    const t1 = setInterval(() => { void flushVisitors(); }, 8000), t2 = setInterval(() => { void syncBlocks(); }, 4000); t1.unref(); t2.unref(); void syncBlocks();
    app.addHook('onClose', async () => { clearInterval(t1); clearInterval(t2); });
  }
  /* ── flood protection ──
     1. Load shedding: past MAX_INFLIGHT requests being handled at once (or a backed-up database pool) new work gets a quick 503 + Retry-After
        instead of piling up until everything is slow. /health is exempt so monitors and failover probes still get an answer.
     2. Cheap rejection before any body is read: private routes need a well-formed session token, so anonymous floods and oversized junk
        bodies die at the headers. */
  let inflight = 0; const MAX_INFLIGHT = Number(env.MAX_INFLIGHT ?? 3000), MAX_POOL_WAIT = Number(env.MAX_POOL_WAIT ?? 1500);      // a queue this deep is ~2–4 s of work: patient enough for a stampede, bounded enough to protect the database
  const PRIVATE = /^\/(me|pay|chat|auth\/logout(-all)?)(\/|$|\?)/;
  app.addHook('onRequest', async (req, reply) => {
    const path = req.url;
    if (req.method === 'OPTIONS' || path.startsWith('/health')) return;      // CORS preflights never carry a token; the CORS plugin answers them
    const staffPath = false;
    if (inflight >= (staffPath ? MAX_INFLIGHT * 2 : MAX_INFLIGHT) || (!staffPath && pool.waitingCount > MAX_POOL_WAIT)) return withCors(req, reply).code(503).header('retry-after', '2').send({ ok: false, error: 'The server is very busy. Please try again in a few seconds.', busy: true });
    inflight++; let ended = false; reply.raw.once('close', () => { if (!ended) { ended = true; inflight--; } });
    if (PRIVATE.test(path) && !/^Bearer [a-f0-9]{48}$/.test(req.headers.authorization ?? '')) return withCors(req, reply).code(401).send({ ok: false, error: 'session' });
  });
  // High enough that a whole college Wi-Fi (one shared IP) never trips it by accident; a scanner does within seconds.
    // A dead session (401) is normal — a signed-in-elsewhere phone, a token that expired overnight — and a whole college can share one IP, so it counts a tenth as much as a scanner's 404/400/403/413.
  app.addHook('onResponse', async (req, reply) => { noteVisit(req, reply.statusCode, req.errText); const c = reply.statusCode; if (c === 401) strike(req.ip, 0.1); else if (c === 404 || c === 400 || c === 403 || c === 413) strike(req.ip); });
  // Every API answer is private, never cached, never framed, never sniffed into something executable.
  app.addHook('onSend', async (req, reply, payload) => {
    if (reply.statusCode >= 400 && typeof payload === 'string' && payload.length < 400) { try { req.errText = String(JSON.parse(payload).error ?? '').slice(0, 80); } catch { /* not json */ } }
    if (!reply.getHeader('cache-control')) reply.header('cache-control', 'no-store');
    reply.header('x-content-type-options', 'nosniff').header('x-frame-options', 'DENY')
      .header('referrer-policy', 'no-referrer').header('content-security-policy', "default-src 'none'; frame-ancestors 'none'").header('cross-origin-opener-policy', 'same-origin');
    if (production) reply.header('strict-transport-security', 'max-age=31536000; includeSubDomains');
    return payload;
  });
  const proofs = makeProofStorage(env, { firebase, log: { warn: m => app.log.warn(m) } });

  app.register(cors, { origin: origins.length ? origins : true, methods: ['GET', 'POST', 'OPTIONS'], allowedHeaders: ['content-type', 'authorization'], maxAge: 86_400 });
  app.register(compress, { global: true, threshold: 1024, encodings: ['gzip', 'deflate'] });
  // Everyone at the college shares one Wi-Fi address, so limits are per session token, not per IP.
  app.register(rateLimit, {
    global: true, max: 600, timeWindow: '1 minute',
    // Sessions are 48 hex characters. Only a well-formed one gets its own bucket; anything else shares the caller's IP bucket.
    keyGenerator: req => { const a = req.headers.authorization ?? ''; return /^Bearer [a-f0-9]{48}$/.test(a) ? a : `ip:${req.ip}`; },
  });

  /* ── database helpers ── */
  const bearer = req => (req.headers.authorization ?? '').replace(/^Bearer\s+/i, '').trim();
  async function call(fn, args = []) {
    const { rows } = await pool.query(`select ${fn}(${args.map((_, i) => `$${i + 1}`).join(', ')}) as r`, args);
    return rows[0].r;
  }
  async function callOn(db, fn, args = []) {
    const { rows } = await db.query(`select ${fn}(${args.map((_, i) => `$${i + 1}`).join(', ')}) as r`, args);
    return rows[0].r;
  }
  app.setErrorHandler((err, req, reply) => {
    // Client mistakes get a short, generic answer — never parser or database internals.
    if (err.statusCode && err.statusCode < 500) return reply.code(err.statusCode).send({ ok: false, error: err.statusCode === 413 ? 'That upload is too large.' : err.statusCode === 429 ? err.message : 'Bad request.' });
    // Wrong argument names or types sent to a database function (only a tampered client does this).
    if (typeof err.code === 'string' && (/^22/.test(err.code) || ['42883', '42703', '42804', '42P18', '23502', '23514'].includes(err.code))) return reply.code(400).send({ ok: false, error: 'Bad request.' });
    if (typeof err.message === 'string' && err.message.startsWith('DN:session')) return reply.code(401).send({ ok: false, error: 'session' });
    if (typeof err.message === 'string' && err.message.startsWith('DN:password')) return reply.code(403).send({ ok: false, error: 'password_change_required' });
    if (typeof err.message === 'string' && err.message.startsWith('DN:denied')) return reply.code(403).send({ ok: false, error: 'denied' });
    req.log.error(err);
    return reply.code(503).send({ ok: false, error: 'The server is busy. Please try again in a moment.' });
  });

  /* ── every JSON body: no NUL bytes or stray control characters (they break Postgres text and smuggle past filters), bounded depth and size ── */
  app.addHook('preValidation', async (req, reply) => {
    if (req.method !== 'POST' || !req.body || typeof req.body !== 'object') return;
    let nodes = 0; const maxNodes = 5000;      // the roster import sends thousands of rows
    const bad = (v, depth) => {
      if (++nodes > maxNodes || depth > 8) return true;
      if (typeof v === 'string') return /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f\u2028\u2029\u202a-\u202e\u2066-\u2069]/.test(v);      // control + bidi-override characters
      if (Array.isArray(v)) return v.some(x => bad(x, depth + 1));
      if (v && typeof v === 'object') return Object.entries(v).some(([k, x]) => bad(k, depth + 1) || bad(x, depth + 1));
      return false;
    };
    if (bad(req.body, 0)) return reply.code(400).send({ ok: false, error: 'Bad request.' });
  });
  /* ── student session guard ── */
  const sessions = new Map();      // token → { sub, exp }: the chat polls every second or two, so the session check is remembered for 5 s (a newer sign-in on another phone ends this one within that time)
  async function studentSubCached(req, reply) {
    const token = bearer(req); const hit = token && sessions.get(token);
    if (hit && hit.exp > Date.now()) return hit.sub;
    const sub = token ? await call('api_student_from_token', [token]) : null;
    if (!sub) { sessions.delete(token); return refuse(reply, token); }
    if (sessions.size > 5000) sessions.clear();
    sessions.set(token, { sub, exp: Date.now() + 5_000 }); return sub;
  }
  async function studentSub(req, reply) {
    const token = bearer(req);
    const sub = token ? await call('api_student_from_token', [token]) : null;
    if (!sub) return refuse(reply, token);
    return sub;
  }
  /** 401 for a dead session; says why when a newer sign-in on another device ended it, so the old phone can explain itself. */
  async function refuse(reply, token) {
    const reason = token ? await call('api_student_session_reason', [token]).catch(() => null) : null;
    reply.code(401).send({ ok: false, error: 'session', ...(reason ? { reason } : {}) }); return null;
  }

  /* ── health / public ── */
  let healthAt = 0, healthLast = null;      // a flood on /health must not become a flood on the database: the check runs at most once a second
  app.get('/health', { config: { rateLimit: { max: 1200 } } }, async (_req, reply) => {
    if (healthLast && Date.now() - healthAt < 1000) return reply.code(healthLast.ok ? 200 : 503).send({ ...healthLast, cached: true });
    const t0 = performance.now();
    try { await pool.query('select 1'); healthLast = { ok: true, db: true, latencyMs: Math.round(performance.now() - t0), pool: { total: pool.totalCount, idle: pool.idleCount, waiting: pool.waitingCount, inflight }, time: new Date().toISOString() }; }
    catch (e) { healthLast = { ok: false, db: false, error: e.message }; }
    healthAt = Date.now(); return reply.code(healthLast.ok ? 200 : 503).send(healthLast);
  });
  /* The public numbers and all site text are read by every visitor every 30 s. One database read per 10 s serves all of them, and
     browsers revalidate with an ETag so an unchanged answer costs a few bytes. */
  let infoCache = { at: 0, body: '', etag: '', pending: null };
  async function publicInfoCached() {
    if (infoCache.body && Date.now() - infoCache.at < 10_000) return infoCache;
    infoCache.pending ??= call('public_info').then(i => {
      const body = JSON.stringify(gateway(i)); infoCache = { at: Date.now(), body, etag: `W/"${createHash('sha1').update(body).digest('base64url').slice(0, 16)}"`, pending: null };
    }).catch(e => { infoCache.pending = null; if (!infoCache.body) throw e; });
    await infoCache.pending; return infoCache;
  }
  /* What the browser itself saw (could not reach the main server, a script error …), so the team can tell what visitors are stuck on. */
  app.post('/public/diag', { bodyLimit: 2000, config: { rateLimit: { max: 20, timeWindow: '1 minute' } } }, async (req, reply) => {
    const m = String(req.body?.m ?? '').replace(/[^\x20-\x7e]/g, ' ').slice(0, 90); if (!m) return reply.code(204).send();
    const device = deviceOf(req.headers['user-agent']); const key = `${req.ip}|${device}`; const now = Date.now();
    let v = visitors.get(key); if (!v && visitors.size < 30_000) { v = { key, ip: req.ip, device, first: now, last: now, hits: 0, errors: 0, lastError: '', lastErrorAt: 0, page: '', dirty: false }; visitors.set(key, v); }
    if (v) { v.errors++; v.lastError = `browser: ${m}`; v.lastErrorAt = now; v.last = now; v.dirty = true; }
    return reply.code(204).send();
  });
  app.get('/public/info', { config: { rateLimit: false } }, async (req, reply) => {      // cheap (served from memory), and a whole college can sit behind one IP, so no per-IP cap
    const c = await publicInfoCached();
    reply.header('cache-control', 'no-cache').header('etag', c.etag).type('application/json');
    if (req.headers['if-none-match'] === c.etag) return reply.code(304).send();
    return c.body;
  });
  // Pictures the team uploads for the site. Their ids are random and never reused, so browsers may keep them for a year.
  const imgCache = new Map();        // id → { mime, data }: the few site pictures stay in memory (they never change once uploaded)
  app.get('/public/img/:id', { config: { rateLimit: false } }, async (req, reply) => {
    const id = String(req.params.id ?? '');
    if (!/^[a-f0-9]{18}$/.test(id)) return reply.code(404).send({ ok: false, error: 'Not found.' });
    let img = imgCache.get(id);
    if (!img) {
      const { rows } = await pool.query('select mime, data from site_images where id = $1', [id]);
      if (!rows[0]) return reply.code(404).send({ ok: false, error: 'Not found.' });
      img = rows[0]; if (imgCache.size >= 40) imgCache.delete(imgCache.keys().next().value); imgCache.set(id, img);
    }
    return reply.header('cache-control', 'public, max-age=31536000, immutable').header('cross-origin-resource-policy', 'cross-origin').type(img.mime).send(img.data);
  });

  /* ── Google sign-in ── */
  app.post('/auth/google', { config: { rateLimit: { max: Number(env.RATE_AUTH ?? 2400), timeWindow: '1 minute' } } }, async (req, reply) => {
    const credential = typeof req.body?.credential === 'string' ? req.body.credential : '';
    if (!credential) return reply.code(400).send({ ok: false, error: 'Sign-in could not start. Please try again.' });   // missing / wrong-typed token: the caller's mistake, not an outage
    let sub, email, name, picture;
    if (req.body?.provider === 'firebase') {
      const v = await firebase.verifyIdToken(credential);
      if (!v) return reply.code(401).send({ ok: false, error: 'Google sign-in could not be verified. Please try again.' });
      ({ sub, email, name, picture } = v);
    } else if (devAuth && credential.startsWith('dev:')) {
      email = credential.slice(4).trim().toLowerCase();
      if (!/^[^@\s]+@[^@\s]+$/.test(email)) return reply.code(400).send({ ok: false, error: 'Enter a valid email.' });
      sub = 'dev-' + createHash('sha256').update(email).digest('hex').slice(0, 24); name = email.split('@')[0]; picture = '';
    } else {
      if (!GOOGLE_CLIENT_ID) return reply.code(400).send({ ok: false, error: 'This sign-in method is not available. Please use “Continue with Google” on the site.' });
      try {
        const ticket = await google.verifyIdToken({ idToken: credential, audience: GOOGLE_CLIENT_ID });
        const p = ticket.getPayload();
        if (!p?.sub || !p.email || p.email_verified === false) throw new Error('unverified');
        ({ sub, email, name = '', picture = '' } = { sub: p.sub, email: p.email, name: p.name, picture: p.picture });
      } catch { return reply.code(401).send({ ok: false, error: 'Google sign-in could not be verified. Please try again.' }); }
    }
    const token = await call('api_student_login', [sub, email, name, picture, req.ip, String(req.headers['user-agent'] ?? '').slice(0, 200)]);
    for (const [t, v] of sessions) if (v.sub === sub) sessions.delete(t);      // one device at a time: any other phone's remembered session ends now
    return { ok: true, token };
  });
  app.post('/auth/logout-all', { config: { rateLimit: { max: 10, timeWindow: '1 minute' } } }, async (req, reply) => {
    const token = bearer(req);
    const n = token ? await call('api_student_logout_all', [token]) : 0;
    if (!n) return reply.code(401).send({ ok: false, error: 'session' });
    sessions.clear();                                                   // drop the 30-second session cache so the other devices are refused at once
    return { ok: true, revoked: n };
  });
  app.post('/auth/logout', async req => { sessions.delete(bearer(req)); await call('api_student_logout', [bearer(req)]); return { ok: true }; });

  /* ── the signed-in student ── */
  app.get('/me', async (req, reply) => {
    const sub = await studentSub(req, reply); if (!sub) return;
    // ?light=1 is what pages poll with: the same answer without the photos (the page already holds them), a few hundred bytes instead of ~250 KB.
    const me = await call(req.query?.light === '1' ? 'api_student_state_lite' : 'api_student_state', [sub]);
    return me ? { ...me, info: gateway(me.info) } : me;
  });
  // (The old /students/lookup route is gone: it let any signed-in account read names off the roster. Lookups happen
  //  only inside /me/draft, which caps how many different roll numbers one account may try.)
  app.post('/me/draft', { bodyLimit: 600_000, config: { rateLimit: { max: 90, timeWindow: '1 minute' } } }, async (req, reply) => {
    const sub = await studentSub(req, reply); if (!sub) return;
    const patch = req.body?.patch;
    if (!patch || typeof patch !== 'object' || Array.isArray(patch)) return reply.code(400).send({ ok: false, error: 'Nothing to save.' });
    const clean = {};
    const MAX = { year: 20, roll: 20, name: 120, branch: 120, branchOther: 80, photo: 400_000 };
    for (const k of Object.keys(MAX)) if (k in patch) clean[k] = (patch[k] == null ? '' : String(patch[k])).slice(0, MAX[k]);
    if ('manual' in patch) clean.manual = patch.manual === true;
    const r = await call('api_save_draft', [sub, JSON.stringify(clean)]);
    if (req.body?.light === true && r?.draft && !('photo' in clean)) { r.draft.hasPhoto = !!r.draft.photo; r.draft.photo = ''; }      // the page already has its photo: don't send it back
    const what = Object.keys(clean).filter(k => k !== 'photo').concat('photo' in clean ? ['photo'] : []);
    void call('api_log_student', [sub, r?.ok ? 'details_saved' : 'details_rejected', `${what.join(', ')}${clean.roll ? ' · roll ' + clean.roll : ''}${r?.ok ? '' : ' · ' + String(r?.error ?? '').slice(0, 100)}`]).catch(() => undefined);
    return r;
  });
  app.post('/me/pay', { config: { rateLimit: { max: 20, timeWindow: '1 minute' } } }, async (req, reply) => {
    const sub = await studentSub(req, reply); if (!sub) return;
    if (!rzp.enabled && !demoCheckout) return reply.code(410).send({ ok: false, reason: 'gateway', error: 'Card and net-banking payments are not available. Pay with the UPI QR or in cash.' });
    const r = await call('api_begin_payment', [sub]);
    if (!r?.ok || !rzp.enabled) return r;
    try {                                                   // a real Razorpay order, created server-side for exactly this attempt
      const order = await rzp.createOrder({ amountRupees: r.amount, receipt: r.txnId, notes: { regId: r.regId, txnId: r.txnId } });
      if (!(await call('api_set_order', [sub, r.txnId, order.id]))) throw new Error('order could not be attached');
      return { ...r, orderId: order.id, razorpay: { keyId: rzp.keyId, amountPaise: order.amount } };
    } catch (e) {
      req.log.error({ err: e }, 'razorpay order failed');
      await call('api_fail_order', [sub, r.orderId, 'Could not start the payment']).catch(() => undefined);
      return reply.code(503).send({ ok: false, reason: 'gateway', error: 'The payment service is unavailable right now. Please try again in a moment.' });
    }
  });
  // Demo checkout only — refused outright once Razorpay is configured, whatever the database flag says.
  app.post('/me/pay/test-settle', { config: { rateLimit: { max: 20, timeWindow: '1 minute' } } }, async (req, reply) => {
    const sub = await studentSub(req, reply); if (!sub) return;
    if (!demoCheckout) return reply.code(403).send({ ok: false, error: 'Test checkout is disabled.' });
    const { txnId = '', ok = false, method = '', error = '' } = req.body ?? {};
    const paymentId = ok ? `pay_${randomBytes(9).toString('base64url').replace(/[-_]/g, 'x').slice(0, 14)}` : '';
    return call('api_test_settle', [sub, String(txnId), Boolean(ok), paymentId, String(method).slice(0, 20), String(error).slice(0, 200)]);
  });
  // Called by the browser after Razorpay Checkout succeeds. Nothing is trusted: signature, order owner, amount and status are all re-checked.
  app.post('/me/pay/verify', { config: { rateLimit: { max: 30, timeWindow: '1 minute' } } }, async (req, reply) => {
    const sub = await studentSub(req, reply); if (!sub) return;
    if (!rzp.enabled) return reply.code(404).send({ ok: false, error: 'Online payments are not enabled.' });
    const { razorpay_order_id: orderId = '', razorpay_payment_id: paymentId = '', razorpay_signature: signature = '' } = req.body ?? {};
    if (!rzp.verifyCheckoutSignature(String(orderId), String(paymentId), String(signature))) return reply.code(400).send({ ok: false, error: 'This payment could not be verified.' });
    const info = await call('api_order_info', [sub, String(orderId)]);
    if (!info) return reply.code(404).send({ ok: false, error: 'We could not find that order.' });
    if (info.status === 'paid') return { ok: true, duplicate: true };
    try {
      let pay = await rzp.fetchPayment(String(paymentId));
      if (pay.order_id !== orderId || pay.amount !== info.amount * 100 || pay.currency !== 'INR') return reply.code(400).send({ ok: false, error: 'The payment details do not match this order.' });
      if (pay.status === 'authorized') pay = await rzp.capture(pay.id, pay.amount);
      if (pay.status !== 'captured') return reply.code(202).send({ ok: false, pending: true, error: 'Your payment is still being confirmed. Your pass will appear in a moment.' });
      return await call('settle_payment_by_order', [String(orderId), true, pay.id, mapMethod(pay.method), '']);
    } catch (e) {
      req.log.error({ err: e }, 'razorpay verify failed');
      return reply.code(503).send({ ok: false, error: 'We could not confirm the payment just now. If money was deducted, your pass will appear shortly.' });
    }
  });
  // The student closed the checkout or the bank declined: record the attempt as failed so they can retry cleanly.
  app.post('/me/pay/failed', { config: { rateLimit: { max: 30, timeWindow: '1 minute' } } }, async (req, reply) => {
    const sub = await studentSub(req, reply); if (!sub) return;
    return call('api_fail_order', [sub, String(req.body?.orderId ?? ''), String(req.body?.reason ?? 'Payment was not completed').slice(0, 200), mapMethod(req.body?.method ?? '')]);
  });
  /* ── manual payments: UPI QR (UTR + screenshot) or cash. The admin panel decides; nothing here can issue a pass. ── */
  let payCfg = { at: 0, v: null, pending: null };            // the same for every student and it carries the QR picture, so one read serves everyone for 5 s
  async function payConfigCached() {
    if (payCfg.v && Date.now() - payCfg.at < 5000) return payCfg.v;
    payCfg.pending ??= call('api_pay_config').then(v => { payCfg = { at: Date.now(), v, pending: null }; return v; }).catch(e => { payCfg.pending = null; throw e; });
    return payCfg.pending;
  }
  app.get('/pay/config', { config: { rateLimit: { max: 60, timeWindow: '1 minute' } } }, async (req, reply) => {
    const sub = await studentSub(req, reply); if (!sub) return;
    return payConfigCached();
  });
  const MAX_PROOF_CHARS = Number(env.MAX_PROOF_CHARS ?? 450_000);       // ≈ 330 KB of image: plenty to read a UTR, small enough to keep storage light
  app.post('/me/pay/submit', { bodyLimit: MAX_PROOF_CHARS + 2_000, config: { rateLimit: { max: 12, timeWindow: '1 minute' } } }, async (req, reply) => {
    const sub = await studentSub(req, reply); if (!sub) return;
    const b = req.body && typeof req.body === 'object' ? req.body : {};
    const mode = String(b.mode ?? ''), utr = String(b.utr ?? '').slice(0, 40), proof = typeof b.screenshot === 'string' ? b.screenshot : '';
    if (!['upi', 'cash'].includes(mode)) return reply.code(400).send({ ok: false, reason: 'invalid', error: 'Choose how you are paying.' });
    if (proof.length > MAX_PROOF_CHARS) return reply.code(413).send({ ok: false, reason: 'invalid', field: 'proof', error: 'That screenshot is too large. Choose a smaller one — it is shrunk automatically, so try cropping it.' });
    const r = await call('api_submit_payment', [sub, mode, utr, proof, '']);
    if (r?.ok && mode === 'upi') {                       // the screenshot is already safe in Postgres; copy it elsewhere without making the student wait
      void proofs.mirror(r.txnId, proof).then(m => (Object.keys(m).length ? call('api_set_proof_mirrors', [r.txnId, JSON.stringify(m)]) : undefined)).catch(e => req.log.warn({ err: e }, 'proof mirror failed'));
    }
    return r;
  });
  app.post('/me/pay/cancel', { config: { rateLimit: { max: 10, timeWindow: '1 minute' } } }, async (req, reply) => {
    const sub = await studentSub(req, reply); if (!sub) return;
    return call('api_cancel_payment', [sub]);
  });
  app.post('/me/recover', { config: { rateLimit: { max: 10, timeWindow: '1 minute' } } }, async (req, reply) => {
    const sub = await studentSub(req, reply); if (!sub) return;
    const reg = await call('api_recover_pass', [sub, String(req.body?.roll ?? ''), String(req.body?.code ?? '')]);
    return reg ? { ok: true, reg } : reply.code(404).send({ ok: false, error: 'We couldn’t match those details.' });
  });

  /* ── Razorpay webhook: confirms payments even if the student never returns to the site ── */
  app.register(async hook => {
    hook.addContentTypeParser('application/json', { parseAs: 'buffer' }, (_req, body, done) => done(null, body));
    hook.post('/webhooks/razorpay', { config: { rateLimit: { max: 600, timeWindow: '1 minute', keyGenerator: req => req.ip } } }, async (req, reply) => {
      if (!rzp.webhookEnabled) return reply.code(503).send({ ok: false, error: 'Webhook is not configured.' });
      if (!rzp.verifyWebhook(req.body, req.headers['x-razorpay-signature'])) return reply.code(400).send({ ok: false, error: 'Bad signature.' });
      let ev; try { ev = JSON.parse(req.body.toString('utf8')); } catch { return reply.code(400).send({ ok: false }); }
      const p = ev?.payload?.payment?.entity;
      if (p?.order_id && (ev.event === 'payment.captured' || ev.event === 'order.paid')) {
        await call('settle_payment_by_order', [p.order_id, true, p.id, mapMethod(p.method), '']);
      } else if (p?.order_id && ev.event === 'payment.failed') {
        await call('settle_payment_by_order', [p.order_id, false, '', mapMethod(p.method), String(p.error_description ?? 'Payment failed').slice(0, 200)]);
      }
      return { ok: true };
    });
  });

  /* ── community chat ── */
  const chat = makeChat({ call, firebase, log: { warn: (...a) => app.log.warn(a.join(' ')) } });
  app.addHook('onClose', async () => { chat.stop(); });
  const gates = new Map();          // sub → { g, exp }: the read-permission check for the feed is remembered for 2 s
  async function gateFor(sub, fresh = false) {
    const hit = gates.get(sub);
    if (!fresh && hit && hit.exp > Date.now()) return hit.g;
    const g = await call('api_chat_me', [sub]); if (gates.size > 5000) gates.clear();
    gates.set(sub, { g, exp: Date.now() + 2_000 }); return g;
  }
  /** The private trail moderators can read: what each person did in the room. Best effort — it never blocks the chat. */
  const lastOpen = new Map();       // sub → ms of the last "opened the room" entry (one per 10 minutes is enough)
  const trail = (sub, action, detail, req) => { void call('api_chat_activity', [sub, action, String(detail ?? '').slice(0, 300), String(req.ip ?? '').slice(0, 45)]).catch(() => undefined); };
  app.get('/chat/me', { config: { rateLimit: { max: 90, timeWindow: '1 minute' } } }, async (req, reply) => {
    const sub = await studentSubCached(req, reply); if (!sub) return;
    chat.start();
    const g = await gateFor(sub, true);
    const inRoom = g.canRead ? chat.enter(sub) : true;
    if (g.canRead && (lastOpen.get(sub) ?? 0) < Date.now() - 600_000) { if (lastOpen.size > 5000) lastOpen.clear(); lastOpen.set(sub, Date.now()); trail(sub, 'open', '', req); }
    return { ok: true, ...g, ...(inRoom ? {} : { canPost: false, reason: 'full', full: true }), online: chat.activeCount() };
  });
  app.get('/chat/feed', { config: { rateLimit: { max: 120, timeWindow: '1 minute' } } }, async (req, reply) => {
    const sub = await studentSubCached(req, reply); if (!sub) return;
    chat.start();
    const g = await gateFor(sub);
    if (chat.ready() && !chat.flags().visible) return { ok: false, reason: 'hidden', visible: false };      // the team's "hide the chat" switch applies within a second
    if (!g.canRead) return { ok: false, reason: g.reason ?? 'identity', visible: g.visible };
    chat.enter(sub);
    return { ok: true, ...chat.feed(Number(req.query?.after ?? 0) || 0, req.query?.epoch), online: chat.activeCount() };
  });
  app.post('/chat/send', { config: { rateLimit: { max: 40, timeWindow: '1 minute' } } }, async (req, reply) => {
    const sub = await studentSubCached(req, reply); if (!sub) return;
    chat.start();
    const g = await gateFor(sub, true);
    if (!g.canPost) return { ok: false, code: g.reason };
    if (!chat.enter(sub)) return { ok: false, code: 'full' };
    if (typeof req.body?.body !== 'string') return { ok: false, code: 'reject', rule: 'empty message' };      // only text: objects and arrays are refused outright
    const v = checkMessage(String(req.body?.body ?? ''), g.words ?? []);
    if (v.action === 'reject') {
      if (v.rule === 'links and contact details') await call('api_chat_reject', [sub, v.text, v.rule]).catch(() => undefined);
      trail(sub, 'rejected', `${v.rule}: ${v.text}`, req);
      return { ok: false, code: 'reject', rule: v.rule };
    }
    if (v.action === 'block') {                     // vanishes: never stored, never shown; first time a warning, second time removed
      const r = await call('api_chat_violation', [sub, v.text, v.rule]);
      gates.delete(sub); trail(sub, 'blocked', `${v.rule}: ${v.text}`, req);
      return r?.ok ? { ok: false, code: r.action === 'kick' ? 'kicked' : 'warned', action: r.action, warnings: r.warnings, rule: v.rule } : { ok: false, code: r?.code ?? 'blocked' };
    }
    const r = await call('api_chat_post', [sub, v.text, v.mention, v.flag ?? null]);
    if (!r?.ok) return { ok: false, code: r?.code ?? 'failed', ...(r?.wait ? { wait: r.wait } : {}) };
    chat.add(r.message); trail(sub, 'send', `#${r.message.id}${v.mention ? ' (@admin)' : ''}`, req);
    return { ok: true, message: r.message };
  });
  /** The few buttons that matter in the room (opening the rules, accepting the monitoring notice). Anything else is ignored. */
  app.post('/chat/act', { bodyLimit: 500, config: { rateLimit: { max: 20, timeWindow: '1 minute' } } }, async (req, reply) => {
    const sub = await studentSubCached(req, reply); if (!sub) return;
    const a = String(req.body?.action ?? '');
    if (a === 'rules' || a === 'ack' || a === 'notify') trail(sub, a, '', req);
    return { ok: true };
  });
  app.post('/chat/appeal', { config: { rateLimit: { max: 10, timeWindow: '1 minute' } } }, async (req, reply) => {
    const sub = await studentSubCached(req, reply); if (!sub) return;
    gates.delete(sub); trail(sub, 'appeal', '', req);
    return call('api_chat_appeal', [sub, typeof req.body?.text === 'string' ? req.body.text.slice(0, 700) : '']);
  });
  app.post('/chat/push', { config: { rateLimit: { max: 10, timeWindow: '1 minute' } } }, async (req, reply) => {
    const sub = await studentSubCached(req, reply); if (!sub) return;
    const token = String(req.body?.token ?? '').slice(0, 400);
    if (token.length < 20) return reply.code(400).send({ ok: false, error: 'Bad token.' });
    await call('api_chat_register_push', [sub, token]); await firebase.subscribe(token);
    return { ok: true };
  });

  /* ── keeping the database small: screenshots move to object storage, draft selfies are dropped once a registration holds one ── */
  const sweepState = { dbBytes: 0, at: 0, lastError: '', moved: 0 };
  async function sweepStorage({ minAge = Number(env.PROOF_OFFLOAD_AFTER_S ?? 120), batch = 20 } = {}) {
    const c = await staffPool.connect();
    try {
      await c.query('begin');
      const { rows: [lock] } = await c.query('select pg_try_advisory_xact_lock(770123) as got');
      if (!lock.got) { await c.query('rollback'); return { skipped: true }; }       // another instance is already doing it
      let moved = 0, mirrored = 0;
      if (proofs.enabled) {
        const { rows } = await c.query('select * from api_proofs_to_offload($1, $2)', [minAge, batch]);
        for (const row of rows) {
          let m = row.mirrors ?? {};
          if (!Object.keys(m).length) {                                              // the copy failed at submit time: try again now
            m = await proofs.mirror(row.txn_id, row.data).catch(() => ({}));
            if (Object.keys(m).length) { await c.query('select api_set_proof_mirrors($1, $2::jsonb)', [row.txn_id, JSON.stringify(m)]); mirrored++; }
          }
          if (Object.keys(m).length && await proofs.verify(m)) { await c.query('select api_proof_offloaded($1)', [row.txn_id]); moved++; }
        }
      }
      const keep = Number(env.PROOF_KEEP_DAYS ?? 0);
      const purged = keep > 0 ? (await c.query('select api_purge_proofs($1) as n', [keep])).rows[0].n : 0;
      const released = (await c.query('select api_release_draft_photos(200) as n')).rows[0].n;
      const usage = (await c.query('select api_db_usage() as u')).rows[0].u;
      await c.query('commit');
      Object.assign(sweepState, { dbBytes: Number(usage.bytes), at: Date.now(), lastError: '', moved: sweepState.moved + moved });
      const limitMb = Number(env.DB_LIMIT_MB ?? 500), usedMb = sweepState.dbBytes / 1048576;
      if (usedMb > limitMb * 0.8) app.log.warn(`[storage] database is ${usedMb.toFixed(0)} MB of ${limitMb} MB — ${usage.proofsInDb} screenshots still inside it, storage backends ${proofs.enabled ? 'on' : 'OFF'}`);
      return { moved, mirrored, purged, released, usage };
    } catch (e) {
      await c.query('rollback').catch(() => undefined); sweepState.lastError = String(e.message).slice(0, 120); app.log.warn(`[storage] sweep failed: ${e.message}`); return { error: e.message };
    } finally { c.release(); }
  }
  app.decorate('sweepStorage', sweepStorage);
  if (env.STORAGE_SWEEP !== '0' && env.NODE_ENV !== 'test') {
    const every = Number(env.STORAGE_SWEEP_S ?? 60) * 1000;
    const timer = setInterval(() => { void sweepStorage(); }, every); timer.unref();
    const first = setTimeout(() => { void sweepStorage(); }, 5_000 + Math.random() * 15_000); first.unref();
    app.addHook('onClose', async () => { clearInterval(timer); clearTimeout(first); });
  }

  app.addHook('onClose', async () => { await Promise.all([pool.end(), staffPool.end()]); });
  return app;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const app = buildApp();
  const port = Number(process.env.PORT ?? 8787);
  app.listen({ port, host: process.env.HOST ?? '0.0.0.0' }).then(() => app.inject('/health')).catch(e => { console.error(e); process.exit(1); });   // listen, then warm the pool
  for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => app.close().then(() => process.exit(0)));
  process.on('unhandledRejection', e => console.error('[api] unhandledRejection', e));
}
