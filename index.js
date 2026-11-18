// Upsy OAuth Bridge with a fail-closed password gate.
// Every route that can start OAuth, finish OAuth, show token status or reach Upsy
// requires the owner's password (a browser session for the web pages, a bearer key for /mcp).
// Until the owner has set a password through the one-time setup flow, those routes stay locked.

const ISSUER = 'https://upsy.ai';
const TOKEN_ENDPOINT = 'https://upsy.ai/api/oauth/token';
const REGISTER_ENDPOINT = 'https://upsy.ai/api/oauth/register';
const MCP_ENDPOINT = 'https://upsy.ai/connect';
const SCOPES = 'memory files browser gmail calendar drive outlook zohomail slack linear atlassian todoist clickup airtable notion miro granola fireflies calendly attio close intercom klaviyo customerio customerioeu stripe paypal webflow wix zapier upstash github context7 sentry supabase neon cloudflare vercel netlify posthog huggingface';

const SESSION_COOKIE = '__Host-bridge_session';
const SESSION_TTL_MS = 12 * 60 * 60 * 1000;      // 12 hours
const SETUP_LINK_TTL_MS = 10 * 60 * 1000;        // 10 minutes, single use
const OAUTH_STATE_TTL_MS = 10 * 60 * 1000;
const MIN_PASSWORD_LENGTH = 12;
const MAX_PASSWORD_LENGTH = 256;
const RL_MAX_FAILURES = 10;                      // per client IP
const RL_WINDOW_MS = 15 * 60 * 1000;

const enc = new TextEncoder();
const b64url = (bytes) => { let s = ''; const a = new Uint8Array(bytes); for (let i = 0; i < a.length; i++) s += String.fromCharCode(a[i]); return btoa(s).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_'); };
const randomToken = (n = 32) => b64url(crypto.getRandomValues(new Uint8Array(n)));
async function sha256(s) { return crypto.subtle.digest('SHA-256', enc.encode(s)); }
async function hmac(keyBytes, msg) {
  const key = await crypto.subtle.importKey('raw', typeof keyBytes === 'string' ? enc.encode(keyBytes) : keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, enc.encode(msg)));
}
function equalBytes(a, b) { if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i]; return d === 0; }
// Constant-time string comparison: compare HMACs of both values under a random per-call key.
async function safeEqual(a, b) { const k = crypto.getRandomValues(new Uint8Array(32)); return equalBytes(await hmac(k, String(a)), await hmac(k, String(b))); }
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const SEC_HEADERS = { 'cache-control': 'no-store', 'x-frame-options': 'DENY', 'x-content-type-options': 'nosniff', 'referrer-policy': 'same-origin', 'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'" };
function json(data, status = 200, headers = {}) { return new Response(JSON.stringify(data, null, 2), { status, headers: { 'content-type': 'application/json; charset=utf-8', ...SEC_HEADERS, ...headers } }); }
function page(title, body, status = 200, headers = {}) {
  const doc = '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>' + esc(title) + '</title><style>body{font:16px/1.5 system-ui,sans-serif;max-width:32rem;margin:3rem auto;padding:0 1rem;color:#111}input,button{font:inherit;padding:.6rem .8rem;width:100%;box-sizing:border-box;margin:.3rem 0 .9rem}button{background:#111;color:#fff;border:0;border-radius:6px;cursor:pointer}input{border:1px solid #aaa;border-radius:6px}.muted{color:#555;font-size:.9rem}code{background:#eee;padding:.1rem .3rem;border-radius:4px;word-break:break-all}.err{color:#b00020}</style></head><body><h1>' + esc(title) + '</h1>' + body + '</body></html>';
  return new Response(doc, { status, headers: { 'content-type': 'text/html; charset=utf-8', ...SEC_HEADERS, ...headers } });
}
function redirect(location, headers = {}) { return new Response(null, { status: 303, headers: { location, 'cache-control': 'no-store', ...headers } }); }

// ---------- Durable Object storage helpers ----------
function store(env) { return env.TOKEN_STORE.get(env.TOKEN_STORE.idFromName('upsy-oauth-tokens')); }
async function kv(env, method, key, value) {
  const r = await store(env).fetch('https://token-store.internal/item?key=' + encodeURIComponent(key), { method, headers: { 'content-type': 'application/json' }, ...(value === undefined ? {} : { body: JSON.stringify(value) }) });
  if (r.status === 404) return null;
  if (!r.ok) throw new Error('Token storage error ' + r.status);
  if (method === 'GET') return r.json();
  return true;
}
// Atomically read and delete a key (single-use values).
async function take(env, key) {
  const r = await store(env).fetch('https://token-store.internal/take?key=' + encodeURIComponent(key), { method: 'POST' });
  if (r.status === 404) return null;
  if (!r.ok) throw new Error('Token storage error ' + r.status);
  return r.json();
}
async function rateLimit(env, req, action) {
  const ip = req.headers.get('cf-connecting-ip') || 'unknown';
  const r = await store(env).fetch('https://token-store.internal/ratelimit', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ key: 'rl:' + ip, action, max: RL_MAX_FAILURES, windowMs: RL_WINDOW_MS }) });
  if (!r.ok) throw new Error('Rate limit storage error ' + r.status);
  return r.json(); // { blocked: boolean }
}
const tooMany = () => json({ error: 'too_many_failed_attempts', retry_after_seconds: RL_WINDOW_MS / 1000 }, 429, { 'retry-after': String(RL_WINDOW_MS / 1000) });

// ---------- Password and sessions ----------
async function getAuth(env) { const a = await kv(env, 'GET', 'auth:password'); return a && a.salt && a.hash ? a : null; }
async function hashPassword(salt, password) { return b64url(await hmac(enc.encode(salt), 'bridge-password-v1:' + password)); }
async function checkPassword(auth, password) {
  if (!auth || typeof password !== 'string' || !password || password.length > MAX_PASSWORD_LENGTH) return false;
  return safeEqual(await hashPassword(auth.salt, password), auth.hash);
}
async function sessionKey(auth) { return hmac(enc.encode(auth.hash), 'bridge-session-key-v1:' + auth.salt); }
async function makeSession(auth) {
  const sid = randomToken(18); const exp = Date.now() + SESSION_TTL_MS;
  const sig = b64url(await hmac(await sessionKey(auth), sid + '.' + exp));
  return { sid, cookie: SESSION_COOKIE + '=' + sid + '.' + exp + '.' + sig + '; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=' + Math.floor(SESSION_TTL_MS / 1000) };
}
function readCookie(req, name) {
  const h = req.headers.get('cookie') || '';
  for (const part of h.split(';')) { const i = part.indexOf('='); if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim(); }
  return null;
}
// Returns the session id when the request carries a valid, unexpired session cookie.
async function getSession(req, auth) {
  if (!auth) return null;
  const v = readCookie(req, SESSION_COOKIE); if (!v) return null;
  const [sid, exp, sig] = v.split('.'); if (!sid || !exp || !sig) return null;
  if (!/^\d+$/.test(exp) || Number(exp) < Date.now()) return null;
  const good = b64url(await hmac(await sessionKey(auth), sid + '.' + exp));
  return (await safeEqual(good, sig)) ? sid : null;
}
const clearSessionCookie = SESSION_COOKIE + '=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0';
// Bearer key for MCP clients: "Authorization: Bearer <password>" or "X-Bridge-Key: <password>".
function presentedKey(req) {
  const a = req.headers.get('authorization') || '';
  const m = /^Bearer\s+(.+)$/i.exec(a);
  if (m) return m[1].trim();
  const x = req.headers.get('x-bridge-key');
  return x ? x.trim() : null;
}
// Browser form posts from this site: Origin matches, or (when a browser sends Origin: null) Sec-Fetch-Site says same-origin.
function sameOrigin(req, url) {
  const o = req.headers.get('origin');
  if (o === url.origin) return true;
  return (o === null || o === 'null') && req.headers.get('sec-fetch-site') === 'same-origin';
}

// ---------- Upsy OAuth ----------
async function fetchToken(body) {
  const r = await fetch(TOKEN_ENDPOINT, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' }, body: new URLSearchParams(body) });
  const t = await r.text(); let d; try { d = JSON.parse(t); } catch { d = {}; }
  if (!r.ok) throw new Error('Upsy token endpoint returned ' + r.status + (d && d.error ? ' (' + String(d.error).slice(0, 80) + ')' : ''));
  return d;
}

const lockedPage = () => page('Bridge locked', '<p>This bridge has no owner password yet, so everything that can reach Upsy is switched off.</p><p class="muted">The owner finishes setup with the one-time setup code stored as the <code>SETUP_CODE</code> secret in Cloudflare.</p><p><a href="/setup">Owner setup</a></p>', 503);
function loginPage(msg = '', status = 200) {
  return page('Upsy OAuth Bridge', (msg ? '<p class="err">' + esc(msg) + '</p>' : '') + '<form method="post" action="/login"><label for="p">Password</label><input id="p" name="password" type="password" autocomplete="current-password" required autofocus><button type="submit">Sign in</button></form>', status);
}

async function handle(req, env) {
  const url = new URL(req.url); const path = url.pathname;
  if (url.protocol !== 'https:' && url.hostname !== 'localhost' && url.hostname !== '127.0.0.1') return json({ error: 'https_required' }, 400);
  const auth = await getAuth(env);

  // Public, reveals nothing about tokens.
  if (path === '/health') {
    const out = { ok: true, service: 'upsy-oauth-bridge', locked: !auth };
    const sid = await getSession(req, auth);
    if (sid) out.oauthConfigured = !!(await kv(env, 'GET', 'oauth:tokens'));
    return json(out);
  }

  // ----- One-time owner setup -----
  // Step 1: POST /setup with the SETUP_CODE secret issues a single-use link (10 minutes) to choose the password.
  // Step 2: GET/POST /setup/password?t=... lets the owner choose the password privately.
  // The same SETUP_CODE cannot be used twice. Rotating the SETUP_CODE secret in Cloudflare re-enables setup (password reset).
  if (path === '/setup' || path === '/setup/password') {
    const code = env.SETUP_CODE;
    if (!code || String(code).length < 24) return page('Setup unavailable', '<p>The <code>SETUP_CODE</code> secret is not set in Cloudflare, so setup is switched off.</p>', 503);
    const codeFp = b64url(await hmac(enc.encode('bridge-setup-fp-v1'), String(code)));
    if (auth && auth.setupFp === codeFp) return page('Setup finished', '<p>The owner password is already set. <a href="/">Sign in</a>.</p><p class="muted">To reset it, change the <code>SETUP_CODE</code> secret in Cloudflare and run setup again.</p>', 410);

    if (path === '/setup') {
      if (req.method === 'GET') return page('Owner setup', '<form method="post" action="/setup"><label for="c">Setup code</label><input id="c" name="setup_code" type="password" autocomplete="off" required><button type="submit">Continue</button></form>');
      if (req.method !== 'POST') return json({ error: 'method_not_allowed' }, 405, { allow: 'GET, POST' });
      if (!sameOrigin(req, url)) return json({ error: 'bad_origin' }, 403);
      if ((await rateLimit(env, req, 'check')).blocked) return tooMany();
      const form = await req.formData().catch(() => null);
      const given = form ? String(form.get('setup_code') || '') : '';
      if (!given || given.length > 512 || !(await safeEqual(given, String(code)))) { await rateLimit(env, req, 'fail'); return page('Owner setup', '<p class="err">That setup code is wrong.</p><p><a href="/setup">Try again</a></p>', 401); }
      await rateLimit(env, req, 'clear');
      const t = randomToken(32);
      await kv(env, 'PUT', 'setup:link:' + t, { codeFp, created_at: Date.now() });
      const link = url.origin + '/setup/password?t=' + t;
      return page('Setup link ready', '<p>Open this one-time link to choose the owner password. It works once and expires in 10 minutes.</p><p><a id="setup-link" href="' + esc(link) + '">' + esc(link) + '</a></p>');
    }

    // /setup/password
    const t = url.searchParams.get('t') || '';
    if (!/^[A-Za-z0-9_-]{40,64}$/.test(t)) return page('Link not valid', '<p>This setup link is missing or malformed.</p>', 400);
    const rec = await kv(env, 'GET', 'setup:link:' + t);
    if (!rec || rec.codeFp !== codeFp || Date.now() - rec.created_at > SETUP_LINK_TTL_MS) return page('Link expired', '<p>This setup link has expired or was already used.</p>', 410);
    if (req.method === 'GET') return page('Choose the owner password', '<form method="post"><label for="p1">Password (at least ' + MIN_PASSWORD_LENGTH + ' characters)</label><input id="p1" name="password" type="password" autocomplete="new-password" minlength="' + MIN_PASSWORD_LENGTH + '" maxlength="' + MAX_PASSWORD_LENGTH + '" required autofocus><label for="p2">Type it again</label><input id="p2" name="confirm" type="password" autocomplete="new-password" required><button type="submit">Save password</button></form><p class="muted">This password signs you in here and is also the key your MCP client sends to /mcp.</p>');
    if (req.method !== 'POST') return json({ error: 'method_not_allowed' }, 405, { allow: 'GET, POST' });
    if (!sameOrigin(req, url)) return json({ error: 'bad_origin' }, 403);
    const form = await req.formData().catch(() => null);
    const p1 = form ? String(form.get('password') || '') : ''; const p2 = form ? String(form.get('confirm') || '') : '';
    if (p1.length < MIN_PASSWORD_LENGTH || p1.length > MAX_PASSWORD_LENGTH) return page('Choose the owner password', '<p class="err">Use ' + MIN_PASSWORD_LENGTH + ' to ' + MAX_PASSWORD_LENGTH + ' characters.</p><p><a href="' + esc(url.pathname + url.search) + '">Try again</a></p>', 400);
    if (p1 !== p2) return page('Choose the owner password', '<p class="err">The two passwords don\'t match.</p><p><a href="' + esc(url.pathname + url.search) + '">Try again</a></p>', 400);
    const used = await take(env, 'setup:link:' + t); // single use, atomic
    if (!used || used.codeFp !== codeFp || Date.now() - used.created_at > SETUP_LINK_TTL_MS) return page('Link expired', '<p>This setup link has expired or was already used.</p>', 410);
    const salt = randomToken(32);
    const newAuth = { salt, hash: await hashPassword(salt, p1), setupFp: codeFp, updated_at: Date.now() };
    await kv(env, 'PUT', 'auth:password', newAuth);
    const s = await makeSession(newAuth);
    return redirect('/', { 'set-cookie': s.cookie });
  }

  // Everything below requires an owner password to exist (fail closed).
  if (!auth) {
    if (path === '/mcp') return json({ error: 'bridge_locked', message: 'Owner password not set; the bridge refuses all requests.' }, 503);
    if (path === '/' || path === '/login' || path === '/auth/start' || path === '/oauth/callback' || path === '/logout') return lockedPage();
    return json({ error: 'not_found' }, 404);
  }

  if (path === '/login') {
    if (req.method === 'GET') return loginPage();
    if (req.method !== 'POST') return json({ error: 'method_not_allowed' }, 405, { allow: 'GET, POST' });
    if (!sameOrigin(req, url)) return json({ error: 'bad_origin' }, 403);
    if ((await rateLimit(env, req, 'check')).blocked) return tooMany();
    const form = await req.formData().catch(() => null);
    const pw = form ? String(form.get('password') || '') : '';
    if (!(await checkPassword(auth, pw))) { await rateLimit(env, req, 'fail'); return loginPage('Wrong password.', 401); }
    await rateLimit(env, req, 'clear');
    const s = await makeSession(auth);
    return redirect('/', { 'set-cookie': s.cookie });
  }
  if (path === '/logout') {
    if (req.method !== 'POST') return json({ error: 'method_not_allowed' }, 405, { allow: 'POST' });
    if (!sameOrigin(req, url)) return json({ error: 'bad_origin' }, 403);
    return redirect('/', { 'set-cookie': clearSessionCookie });
  }

  if (path === '/') {
    const sid = await getSession(req, auth);
    if (!sid) return loginPage();
    const connected = !!(await kv(env, 'GET', 'oauth:tokens'));
    return page('Upsy OAuth Bridge', '<p>Upsy: <strong>' + (connected ? 'connected' : 'not connected') + '</strong></p><form method="post" action="/auth/start"><button type="submit">' + (connected ? 'Reconnect Upsy' : 'Connect Upsy') + '</button></form><p class="muted">MCP endpoint: <code>' + esc(url.origin) + '/mcp</code>. Send your password as <code>Authorization: Bearer &lt;password&gt;</code> or <code>X-Bridge-Key: &lt;password&gt;</code>.</p><form method="post" action="/logout"><button type="submit" style="background:#666">Sign out</button></form>');
  }

  if (path === '/auth/start') {
    // POST only, from the signed-in page, so a third-party site cannot start OAuth for you.
    if (req.method !== 'POST') return redirect('/');
    if (!sameOrigin(req, url)) return json({ error: 'bad_origin' }, 403);
    const sid = await getSession(req, auth);
    if (!sid) return loginPage('Sign in first.', 401);
    const redirectUri = new URL('/oauth/callback', url.origin).href;
    const verifier = randomToken(32);
    const challenge = b64url(await sha256(verifier));
    const state = randomToken(24);
    const reg = await fetch(REGISTER_ENDPOINT, { method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json' }, body: JSON.stringify({ client_name: 'Upsy OAuth Bridge', redirect_uris: [redirectUri], token_endpoint_auth_method: 'none', grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'] }) });
    let client = {}; try { client = await reg.json(); } catch { client = {}; }
    if (!reg.ok || !client.client_id) return json({ error: 'dynamic_client_registration_failed', status: reg.status }, 502);
    await kv(env, 'PUT', 'oauth:state:' + state, { verifier, client_id: client.client_id, redirect_uri: redirectUri, sid, created_at: Date.now() });
    const a = new URL('/oauth/authorize', ISSUER);
    a.searchParams.set('response_type', 'code'); a.searchParams.set('client_id', client.client_id); a.searchParams.set('redirect_uri', redirectUri); a.searchParams.set('scope', SCOPES); a.searchParams.set('state', state); a.searchParams.set('code_challenge', challenge); a.searchParams.set('code_challenge_method', 'S256'); a.searchParams.set('resource', MCP_ENDPOINT);
    return redirect(a.href);
  }

  if (path === '/oauth/callback') {
    const sid = await getSession(req, auth);
    if (!sid) return loginPage('Your session expired. Sign in and start the connection again.', 401);
    const code = url.searchParams.get('code'), state = url.searchParams.get('state'), error = url.searchParams.get('error');
    if (error) return page('Upsy authorization failed', '<p>' + esc(String(error).slice(0, 100)) + '</p><p><a href="/">Back</a></p>', 400);
    if (!code || !state) return json({ error: 'missing_code_or_state' }, 400);
    const s = await take(env, 'oauth:state:' + state);
    if (!s || Date.now() - s.created_at > OAUTH_STATE_TTL_MS) return json({ error: 'state_expired_or_invalid' }, 400);
    if (!(await safeEqual(s.sid, sid))) return json({ error: 'state_session_mismatch' }, 400);
    try {
      const tokens = await fetchToken({ grant_type: 'authorization_code', code, redirect_uri: s.redirect_uri, client_id: s.client_id, code_verifier: s.verifier, resource: MCP_ENDPOINT });
      if (!tokens.access_token || !tokens.refresh_token) return json({ error: 'no_refresh_token_returned' }, 502);
      await kv(env, 'PUT', 'oauth:tokens', { ...tokens, client_id: s.client_id, updated_at: Date.now() });
      return page('Upsy connected', '<p>Tokens are stored inside the Worker and are never shown here.</p><p>Point your MCP client at <code>' + esc(url.origin) + '/mcp</code> with your password as the bearer key.</p><p><a href="/">Back</a></p>');
    } catch (e) { return json({ error: 'token_exchange_failed', details: String(e.message) }, 502); }
  }

  if (path === '/mcp') {
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: { allow: 'POST, DELETE, OPTIONS', 'cache-control': 'no-store' } });
    if ((await rateLimit(env, req, 'check')).blocked) return tooMany();
    const key = presentedKey(req);
    if (!key || !(await checkPassword(auth, key))) {
      await rateLimit(env, req, 'fail');
      return json({ error: 'unauthorized', message: 'Send the bridge password as Authorization: Bearer <password> or X-Bridge-Key.' }, 401, { 'www-authenticate': 'Bearer realm="upsy-oauth-bridge"' });
    }
    if (req.method === 'GET') return new Response('MCP endpoint. Use POST with your MCP client.', { status: 405, headers: { allow: 'POST, DELETE, OPTIONS', 'cache-control': 'no-store' } });
    if (req.method !== 'POST' && req.method !== 'DELETE') return json({ error: 'method_not_allowed' }, 405, { allow: 'POST, DELETE, OPTIONS' });
    let t = await kv(env, 'GET', 'oauth:tokens');
    if (!t) return json({ error: 'upsy_not_connected', message: 'Sign in at ' + url.origin + '/ and connect Upsy.' }, 409);
    if (!t.access_token || (t.expires_in && t.updated_at + Math.max(0, t.expires_in - 90) * 1000 < Date.now())) {
      if (!t.refresh_token) return json({ error: 'refresh_token_missing', message: 'Reconnect Upsy at ' + url.origin + '/' }, 409);
      try {
        const fresh = await fetchToken({ grant_type: 'refresh_token', refresh_token: t.refresh_token, client_id: t.client_id, resource: MCP_ENDPOINT });
        t = { ...t, ...fresh, refresh_token: fresh.refresh_token || t.refresh_token, client_id: t.client_id, updated_at: Date.now() };
        await kv(env, 'PUT', 'oauth:tokens', t);
      } catch (e) { return json({ error: 'upsy_token_refresh_failed', details: String(e.message) }, 502); }
    }
    const headers = new Headers(req.headers);
    for (const h of ['host', 'content-length', 'cookie', 'x-bridge-key', 'authorization', 'cf-connecting-ip', 'x-forwarded-for', 'x-real-ip']) headers.delete(h);
    headers.set('authorization', 'Bearer ' + t.access_token);
    const init = { method: req.method, headers, redirect: 'manual' }; if (req.method === 'POST') init.body = req.body;
    const upstream = await fetch(MCP_ENDPOINT, init);
    const out = new Headers(upstream.headers);
    out.set('cache-control', 'no-store'); out.delete('content-encoding'); out.delete('content-length'); out.delete('set-cookie');
    return new Response(upstream.body, { status: upstream.status, statusText: upstream.statusText, headers: out });
  }

  return json({ error: 'not_found' }, 404);
}

export class TokenStore {
  constructor(state, env) { this.state = state; this.env = env; }
  async fetch(req) {
    const u = new URL(req.url);
    if (u.pathname === '/ratelimit') {
      const { key, action, max, windowMs } = await req.json();
      const now = Date.now();
      let rec = (await this.state.storage.get(key)) || { count: 0, first: now };
      if (now - rec.first > windowMs) rec = { count: 0, first: now };
      if (action === 'fail') { rec.count += 1; await this.state.storage.put(key, rec); }
      else if (action === 'clear') { await this.state.storage.delete(key); rec = { count: 0, first: now }; }
      return Response.json({ blocked: rec.count >= max });
    }
    const key = u.searchParams.get('key');
    if (!key) return new Response('missing key', { status: 400 });
    if (u.pathname === '/take') { const v = await this.state.storage.get(key); if (v === undefined) return new Response('', { status: 404 }); await this.state.storage.delete(key); return Response.json(v); }
    if (req.method === 'GET') { const v = await this.state.storage.get(key); return v === undefined ? new Response('', { status: 404 }) : Response.json(v); }
    if (req.method === 'PUT') { await this.state.storage.put(key, await req.json()); return new Response('ok'); }
    if (req.method === 'DELETE') { await this.state.storage.delete(key); return new Response('ok'); }
    return new Response('method not allowed', { status: 405 });
  }
}

export default { fetch(req, env) { return handle(req, env).catch(() => json({ error: 'bridge_error' }, 500)); } };
