const VERSION = '0.2.0';
const ENCODER = new TextEncoder();
const ORIGIN = 'https://ai-development-bridge.dlguddn1222.workers.dev';
const RESOURCE = ORIGIN + '/mcp';
const SCOPE = 'bridge:run';
const JSON_HEADERS = { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' };
const json = (value, status = 200, headers = {}) => new Response(JSON.stringify(value), { status, headers: { ...JSON_HEADERS, ...headers } });
const now = () => Math.floor(Date.now() / 1000);
const random = () => crypto.randomUUID() + crypto.randomUUID();
const sha = async value => [...new Uint8Array(await crypto.subtle.digest('SHA-256', ENCODER.encode(value)))].map(v => v.toString(16).padStart(2, '0')).join('');
async function equal(a, b) {
  const x = await sha(a), y = await sha(b);
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x.charCodeAt(i) ^ y.charCodeAt(i);
  return diff === 0;
}
async function pkce(value) {
  const bytes = new Uint8Array(await crypto.subtle.digest('SHA-256', ENCODER.encode(value)));
  return btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}
let initializedDb;
async function init(db) {
  if (!db) throw new Error('AUTH_DB missing');
  if (initializedDb === db) return;
  await db.batch([
    'CREATE TABLE IF NOT EXISTS oauth_clients (id TEXT PRIMARY KEY, redirects TEXT NOT NULL, name TEXT NOT NULL, created INTEGER NOT NULL)',
    'CREATE TABLE IF NOT EXISTS auth_requests (id TEXT PRIMARY KEY, client_id TEXT NOT NULL, redirect_uri TEXT NOT NULL, challenge TEXT NOT NULL, state TEXT NOT NULL, csrf TEXT NOT NULL, exp INTEGER NOT NULL)',
    'CREATE TABLE IF NOT EXISTS oauth_codes (hash TEXT PRIMARY KEY, client_id TEXT NOT NULL, redirect_uri TEXT NOT NULL, challenge TEXT NOT NULL, exp INTEGER NOT NULL)',
    'CREATE TABLE IF NOT EXISTS oauth_tokens (hash TEXT PRIMARY KEY, client_id TEXT NOT NULL, kind TEXT NOT NULL, exp INTEGER NOT NULL)',
    'CREATE TABLE IF NOT EXISTS rate_limits (key TEXT PRIMARY KEY, count INTEGER NOT NULL, exp INTEGER NOT NULL)',
  ].map(sql => db.prepare(sql)));
  initializedDb = db;
}
async function limit(db, key, max, seconds) {
  const bucket = Math.floor(now() / seconds);
  const row = await db.prepare('INSERT INTO rate_limits (key,count,exp) VALUES (?,1,?) ON CONFLICT(key) DO UPDATE SET count=count+1 RETURNING count').bind(key + ':' + bucket, (bucket + 1) * seconds).first();
  return row.count <= max;
}
async function ipKey(request) {
  return sha((request.headers.get('CF-Connecting-IP') || 'unknown') + ':' + Math.floor(now() / 86400));
}
function validRedirect(value) {
  try {
    const u = new URL(value);
    if (u.username || u.password || u.hash) return false;
    if (u.protocol === 'http:' && ['127.0.0.1', 'localhost', '[::1]'].includes(u.hostname)) return true;
    return u.protocol === 'https:' && ['chatgpt.com', 'chat.openai.com'].includes(u.hostname) && (!u.port || u.port === '443');
  } catch { return false; }
}
const escapeHtml = s => String(s).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&#39;');
function loginPage(auth, clientName, error = '') {
  const body = `<!doctype html><html lang="ko"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AI Development Bridge 연결</title><style>body{background:#f4f7fc;font:16px system-ui;color:#202632;padding:36px 16px}main{max-width:480px;margin:6vh auto;background:white;padding:32px;border-radius:20px}h1{font-size:25px}label{display:block;margin:24px 0 8px}input{width:100%;padding:14px;box-sizing:border-box;border:1px solid #ccd4e0;border-radius:9px;font-size:16px}button{background:#0064ff;color:white;border:0;border-radius:9px;padding:14px;width:100%;font-size:16px;margin-top:16px}small{display:block;color:#62718a;overflow-wrap:anywhere;margin-top:16px}.error{color:#bb2424}</style><main><h1>AI Development Bridge 연결</h1><p><b>${escapeHtml(clientName)}</b>에 Bridge 사용 권한을 연결합니다.</p><p>연결하면 구성 상태를 확인하고 Claude Code의 지정된 루틴을 실행할 수 있습니다.</p><p>Cloudflare에 저장한 <b>BRIDGE_TOKEN</b>을 입력하세요. Claude 루틴 토큰은 입력하지 마세요.</p>${error ? `<p class="error">${escapeHtml(error)}</p>` : ''}<form method="post" action="/oauth/authorize"><input type="hidden" name="request_id" value="${escapeHtml(auth.id)}"><label for="bridge-key">Bridge 연결 키</label><input id="bridge-key" name="bridge_key" type="password" required autocomplete="off" minlength="32" maxlength="512"><button type="submit">키 확인 후 연결 승인</button></form><small>연결 대상: ${escapeHtml(auth.redirect_uri)}<br>루틴 실행은 Claude 구독 사용량을 소모합니다. 별도 유료 API를 사용하지 않습니다.</small></main></html>`;
  return new Response(body, { headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer', 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'", 'Set-Cookie': `bridge_csrf=${auth.csrf}; HttpOnly; Secure; SameSite=Strict; Path=/oauth/authorize; Max-Age=600` } });
}
async function boundedBody(request) {
  if (Number(request.headers.get('content-length') || 0) > 70000) throw new Error('Body too large');
  const reader = request.body?.getReader();
  if (!reader) return '';
  const decoder = new TextDecoder();
  let total = 0, result = '';
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > 70000) { await reader.cancel(); throw new Error('Body too large'); }
    result += decoder.decode(value, { stream: true });
  }
  return result + decoder.decode();
}
async function issueTokens(db, clientId) {
  const access = random(), refresh = random();
  await db.batch([
    db.prepare('INSERT INTO oauth_tokens (hash,client_id,kind,exp) VALUES (?,?,?,?)').bind(await sha(access), clientId, 'access', now() + 3600),
    db.prepare('INSERT INTO oauth_tokens (hash,client_id,kind,exp) VALUES (?,?,?,?)').bind(await sha(refresh), clientId, 'refresh', now() + 1209600),
  ]);
  return json({ access_token: access, token_type: 'Bearer', expires_in: 3600, refresh_token: refresh, scope: SCOPE });
}
async function oauth(request, env, url) {
  if (!env.BRIDGE_TOKEN || env.BRIDGE_TOKEN.length < 32 || !env.AUTH_DB) return json({ error: 'temporarily_unavailable', error_description: 'Bridge authentication is not configured.' }, 503);
  const db = env.AUTH_DB;
  await init(db);
  if (url.pathname === '/oauth/register' && request.method === 'POST') {
    if (!await limit(db, 'register:' + await ipKey(request), 10, 3600)) return json({ error: 'rate_limited' }, 429);
    let data;
    try { data = JSON.parse(await boundedBody(request)); } catch { return json({ error: 'invalid_client_metadata' }, 400); }
    if (!Array.isArray(data.redirect_uris) || data.redirect_uris.length < 1 || data.redirect_uris.length > 8 || !data.redirect_uris.every(validRedirect) || (data.token_endpoint_auth_method && data.token_endpoint_auth_method !== 'none')) return json({ error: 'invalid_client_metadata', error_description: 'Only ChatGPT HTTPS or local loopback callbacks with public PKCE clients are supported.' }, 400);
    const id = 'bridge_' + crypto.randomUUID();
    const name = typeof data.client_name === 'string' ? data.client_name.slice(0, 80) : 'ChatGPT / Codex';
    await db.prepare('INSERT INTO oauth_clients (id,redirects,name,created) VALUES (?,?,?,?)').bind(id, JSON.stringify(data.redirect_uris), name, now()).run();
    return json({ client_id: id, client_id_issued_at: now(), client_name: name, redirect_uris: data.redirect_uris, token_endpoint_auth_method: 'none', grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'] }, 201);
  }
  if (url.pathname === '/oauth/authorize' && request.method === 'GET') {
    if (!await limit(db, 'authorize:' + await ipKey(request), 30, 600)) return json({ error: 'rate_limited' }, 429);
    const p = url.searchParams;
    const client = await db.prepare('SELECT * FROM oauth_clients WHERE id=?').bind(p.get('client_id')).first();
    const challenge = p.get('code_challenge') || '';
    if (!client || !JSON.parse(client.redirects).includes(p.get('redirect_uri')) || !validRedirect(p.get('redirect_uri')) || p.get('response_type') !== 'code' || p.get('code_challenge_method') !== 'S256' || !/^[A-Za-z0-9_-]{43}$/.test(challenge) || (p.has('resource') && p.get('resource') !== RESOURCE) || (p.get('scope') || '').split(' ').filter(Boolean).some(s => s !== SCOPE)) return json({ error: 'invalid_request' }, 400);
    const auth = { id: random(), client_id: client.id, redirect_uri: p.get('redirect_uri'), challenge, state: (p.get('state') || '').slice(0, 2048), csrf: random() };
    await db.batch([
      db.prepare('DELETE FROM auth_requests WHERE exp<?').bind(now()),
      db.prepare('DELETE FROM oauth_codes WHERE exp<?').bind(now()),
      db.prepare('DELETE FROM rate_limits WHERE exp<?').bind(now()),
      db.prepare('DELETE FROM oauth_tokens WHERE exp<?').bind(now()),
      db.prepare('INSERT INTO auth_requests (id,client_id,redirect_uri,challenge,state,csrf,exp) VALUES (?,?,?,?,?,?,?)').bind(auth.id, auth.client_id, auth.redirect_uri, challenge, auth.state, auth.csrf, now() + 600),
    ]);
    return loginPage(auth, client.name);
  }
  if (url.pathname === '/oauth/authorize' && request.method === 'POST') {
    if (request.headers.get('Origin') !== ORIGIN) return json({ error: 'invalid_request' }, 403);
    const ip = await ipKey(request);
    if (!await limit(db, 'login:' + ip, 10, 900)) return json({ error: 'rate_limited', error_description: 'Try again later.' }, 429);
    const form = new URLSearchParams(await boundedBody(request));
    const auth = await db.prepare('SELECT * FROM auth_requests WHERE id=? AND exp>?').bind(form.get('request_id'), now()).first();
    const cookie = (request.headers.get('Cookie') || '').split(';').map(s => s.trim()).find(s => s.startsWith('bridge_csrf='))?.slice(12);
    if (!auth || !cookie || !await equal(cookie, auth.csrf)) return json({ error: 'invalid_request' }, 403);
    if (!await equal(form.get('bridge_key') || '', env.BRIDGE_TOKEN)) return loginPage(auth, 'ChatGPT / Codex', '연결 키가 일치하지 않습니다. BRIDGE_TOKEN을 확인하세요.');
    const consumed = await db.prepare('DELETE FROM auth_requests WHERE id=? AND exp>? RETURNING id').bind(auth.id, now()).first();
    if (!consumed) return json({ error: 'invalid_request' }, 400);
    const code = random();
    await db.prepare('INSERT INTO oauth_codes (hash,client_id,redirect_uri,challenge,exp) VALUES (?,?,?,?,?)').bind(await sha(code), auth.client_id, auth.redirect_uri, auth.challenge, now() + 120).run();
    const destination = new URL(auth.redirect_uri);
    destination.searchParams.set('code', code);
    if (auth.state) destination.searchParams.set('state', auth.state);
    destination.searchParams.set('iss', ORIGIN);
    return new Response(null, { status: 303, headers: { Location: destination.href, 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer', 'Set-Cookie': 'bridge_csrf=; HttpOnly; Secure; SameSite=Strict; Path=/oauth/authorize; Max-Age=0' } });
  }
  if (url.pathname === '/oauth/token' && request.method === 'POST') {
    if (!await limit(db, 'token:' + await ipKey(request), 90, 60)) return json({ error: 'rate_limited' }, 429);
    const p = new URLSearchParams(await boundedBody(request));
    if (p.has('resource') && p.get('resource') !== RESOURCE) return json({ error: 'invalid_target' }, 400);
    if (p.get('grant_type') === 'authorization_code') {
      const verifier = p.get('code_verifier') || '';
      if (!/^[A-Za-z0-9._~-]{43,128}$/.test(verifier)) return json({ error: 'invalid_grant' }, 400);
      const code = await db.prepare('DELETE FROM oauth_codes WHERE hash=? AND client_id=? AND redirect_uri=? AND challenge=? AND exp>? RETURNING client_id').bind(await sha(p.get('code') || ''), p.get('client_id'), p.get('redirect_uri'), await pkce(verifier), now()).first();
      if (!code) return json({ error: 'invalid_grant' }, 400);
      return issueTokens(db, code.client_id);
    }
    if (p.get('grant_type') === 'refresh_token') {
      const token = await db.prepare("DELETE FROM oauth_tokens WHERE hash=? AND client_id=? AND kind='refresh' AND exp>? RETURNING client_id").bind(await sha(p.get('refresh_token') || ''), p.get('client_id'), now()).first();
      if (!token) return json({ error: 'invalid_grant' }, 400);
      return issueTokens(db, token.client_id);
    }
    return json({ error: 'unsupported_grant_type' }, 400);
  }
  return json({ error: 'Not found' }, 404);
}
const TOOLS = [
  { name: 'bridge_status', description: 'Check configuration without starting a Claude session.', inputSchema: { type: 'object', properties: {}, additionalProperties: false }, annotations: { readOnlyHint: true } },
  { name: 'start_development', description: 'Start one Claude Code subscription routine for insudock/AI-Development-Bridge. Creates a new session. Do not retry automatically.', inputSchema: { type: 'object', properties: { text: { type: 'string', minLength: 1, maxLength: 16000 } }, required: ['text'], additionalProperties: false }, annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true } },
];
async function authorized(request, env) {
  const header = request.headers.get('Authorization') || '';
  if (!header.startsWith('Bearer ') || !env.BRIDGE_TOKEN) return false;
  const token = header.slice(7);
  if (env.BRIDGE_TOKEN.length >= 32 && await equal(token, env.BRIDGE_TOKEN)) return true;
  if (!env.AUTH_DB || token.length > 512) return false;
  await init(env.AUTH_DB);
  return !!await env.AUTH_DB.prepare("SELECT hash FROM oauth_tokens WHERE hash=? AND kind='access' AND exp>?").bind(await sha(token), now()).first();
}
async function handle(request, env) {
  const url = new URL(request.url);
  if (request.method === 'GET' && url.pathname === '/health') return json({ service: 'AI Development Bridge', version: VERSION, ok: true });
  if (request.method === 'GET' && ['/\.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/mcp'].includes(url.pathname)) return json({ resource: RESOURCE, authorization_servers: [ORIGIN], scopes_supported: [SCOPE], bearer_methods_supported: ['header'] });
  if (request.method === 'GET' && ['/.well-known/oauth-authorization-server', '/.well-known/openid-configuration'].includes(url.pathname)) return json({ issuer: ORIGIN, authorization_endpoint: ORIGIN + '/oauth/authorize', token_endpoint: ORIGIN + '/oauth/token', registration_endpoint: ORIGIN + '/oauth/register', response_types_supported: ['code'], grant_types_supported: ['authorization_code', 'refresh_token'], token_endpoint_auth_methods_supported: ['none'], code_challenge_methods_supported: ['S256'], scopes_supported: [SCOPE], authorization_response_iss_parameter_supported: true });
  if (url.pathname.startsWith('/oauth/')) return oauth(request, env, url);
  if (url.pathname !== '/mcp') return json({ error: 'Not found' }, 404);
  if (!await authorized(request, env)) return json({ error: 'Unauthorized' }, 401, { 'WWW-Authenticate': `Bearer resource_metadata="${ORIGIN}/.well-known/oauth-protected-resource"` });
  if (request.method !== 'POST') return new Response(null, { status: 405, headers: { Allow: 'POST' } });
  let m;
  try { m = JSON.parse(await boundedBody(request)); } catch { return json({ error: 'Invalid or oversized JSON' }, 400); }
  if (!m || Array.isArray(m) || m.jsonrpc !== '2.0') return json({ error: 'Invalid request' }, 400);
  if (m.id === undefined) return new Response(null, { status: 202 });
  const reply = result => json({ jsonrpc: '2.0', id: m.id, result });
  const fail = (code, message) => json({ jsonrpc: '2.0', id: m.id, error: { code, message } });
  const content = value => ({ content: [{ type: 'text', text: JSON.stringify(value) }] });
  if (m.method === 'initialize') return reply({ protocolVersion: '2025-03-26', capabilities: { tools: {} }, serverInfo: { name: 'ai-development-bridge', version: VERSION } });
  if (m.method === 'ping') return reply({});
  if (m.method === 'tools/list') return reply({ tools: TOOLS });
  if (m.method !== 'tools/call') return fail(-32601, 'Method not found');
  const p = m.params || {};
  if (p.name === 'bridge_status') return reply(content({ configured: !!(env.ROUTINE_FIRE_URL && env.ROUTINE_FIRE_TOKEN), oauthConfigured: !!env.AUTH_DB, repository: 'insudock/AI-Development-Bridge', version: VERSION, billing: 'Claude subscription usage; no Platform API key', automaticRetries: false }));
  if (p.name !== 'start_development') return fail(-32602, 'Unknown tool');
  const text = p.arguments?.text;
  if (typeof text !== 'string' || !text.trim() || text.length > 16000) return fail(-32602, 'text must contain 1–16000 characters');
  if (!env.ROUTINE_FIRE_URL || !env.ROUTINE_FIRE_TOKEN) return reply({ ...content({ error: 'Routine secrets are not configured' }), isError: true });
  let target;
  try { target = new URL(env.ROUTINE_FIRE_URL); } catch { return fail(-32603, 'Invalid routine endpoint'); }
  if (target.origin !== 'https://api.anthropic.com' || !/^\/v1\/claude_code\/routines\/trig_[A-Za-z0-9_-]+\/fire$/.test(target.pathname) || target.search || target.hash || target.username || target.password) return fail(-32603, 'Invalid routine endpoint');
  if (env.AUTH_DB) {
    await init(env.AUTH_DB);
    if (!await limit(env.AUTH_DB, 'routine-fire-global', 10, 3600)) return reply({ ...content({ error: 'Bridge hourly execution limit reached', automaticRetry: false }), isError: true });
  }
  try {
    const response = await fetch(target.href, { method: 'POST', redirect: 'error', headers: { Authorization: 'Bearer ' + env.ROUTINE_FIRE_TOKEN, 'anthropic-version': '2026-10-21', 'Content-Type': 'application/json' }, body: JSON.stringify({ text }), signal: AbortSignal.timeout(20000) });
    if (!response.ok) return reply({ ...content({ error: 'Claude rejected the request', status: response.status, retryAfter: response.headers.get('Retry-After'), automaticRetry: false }), isError: true });
    const data = await response.json();
    return reply(content({ sessionId: data.claude_code_session_id, sessionUrl: data.claude_code_session_url, completed: false, message: 'Session created. This does not mean development is complete.' }));
  } catch { return reply({ ...content({ error: 'Request outcome unknown. Check Claude sessions before retrying.', automaticRetry: false }), isError: true }); }
}
export default { async fetch(request, env) { try { return await handle(request, env); } catch { return json({ error: 'Bridge temporarily unavailable' }, 503); } } };
