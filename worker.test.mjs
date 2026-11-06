import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import worker from './worker.mjs';

const BASE = 'https://ai-development-bridge.dlguddn1222.workers.dev';
const KEY = 'test-only-bridge-key-with-more-than-32-characters';
class DB {
  constructor() { this.db = new DatabaseSync(':memory:'); }
  prepare(sql) {
    const db = this.db;
    let args = [];
    const statement = { bind(...values) { args = values; return statement; }, async first() { return db.prepare(sql).get(...args) ?? null; }, async run() { return db.prepare(sql).run(...args); } };
    return statement;
  }
  async batch(statements) { this.db.exec('BEGIN'); try { const result = []; for (const s of statements) result.push(await s.run()); this.db.exec('COMMIT'); return result; } catch(e) { this.db.exec('ROLLBACK'); throw e; } }
}
function fixture() {
  const env = { AUTH_DB: new DB(), BRIDGE_TOKEN: KEY, ROUTINE_FIRE_URL: 'https://api.anthropic.com/v1/claude_code/routines/trig_test/fire', ROUTINE_FIRE_TOKEN: 'not-a-real-token' };
  const call = (path, options = {}) => worker.fetch(new Request(BASE + path, options), env);
  return { env, call };
}
const postJson = body => ({ method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
const postForm = (body, headers = {}) => ({ method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...headers }, body: new URLSearchParams(body) });
async function register(call, redirect = 'http://127.0.0.1:8123/callback') {
  const r = await call('/oauth/register', postJson({ client_name: 'Test Client', redirect_uris: [redirect], token_endpoint_auth_method: 'none' }));
  assert.equal(r.status, 201);
  return r.json();
}
async function authFlow(call, client, verifier = 'a'.repeat(50)) {
  const challenge = Buffer.from(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))).toString('base64url');
  const params = new URLSearchParams({ response_type: 'code', client_id: client.client_id, redirect_uri: client.redirect_uris[0], code_challenge: challenge, code_challenge_method: 'S256', scope: 'bridge:run', state: 'test-state', resource: BASE + '/mcp' });
  const page = await call('/oauth/authorize?' + params);
  assert.equal(page.status, 200);
  const cookie = page.headers.get('Set-Cookie').split(';')[0];
  const html = await page.text();
  const request_id = html.match(/name="request_id" value="([^"]+)"/)[1];
  return { verifier, cookie, request_id };
}
test('health and discovery expose no credentials', async () => {
  const { call } = fixture();
  for (const path of ['/health', '/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/mcp', '/.well-known/oauth-authorization-server']) {
    const r = await call(path); assert.equal(r.status, 200); const text = await r.text(); assert.ok(!text.includes(KEY)); assert.ok(!text.includes('not-a-real-token'));
  }
});
test('missing and incorrect credentials fail closed with discovery challenge', async () => {
  const { call } = fixture();
  for (const headers of [{}, { Authorization: 'Bearer incorrect' }]) { const r = await call('/mcp', { headers }); assert.equal(r.status, 401); assert.match(r.headers.get('WWW-Authenticate'), /resource_metadata/); }
});
test('MCP initialize, tool discovery and read-only configuration succeed', async () => {
  const { call } = fixture();
  for (const method of ['initialize', 'tools/list', 'tools/call']) {
    const options = postJson({ jsonrpc: '2.0', id: 1, method, params: { name: 'bridge_status', arguments: {} } }); options.headers.Authorization = 'Bearer ' + KEY;
    const r = await call('/mcp', options); assert.equal(r.status, 200); const data = await r.json(); assert.ok(data.result); assert.equal(data.error, undefined);
    if (method === 'tools/list') assert.equal(data.result.tools.length, 2);
  }
});
test('DCR rejects foreign, credential-bearing and fragment redirect URIs', async () => {
  const { call } = fixture();
  for (const uri of ['https://evil.example/callback', 'https://user:pass@chatgpt.com/callback', 'https://chatgpt.com/callback#fragment', 'http://chatgpt.com/callback']) {
    const r = await call('/oauth/register', postJson({ redirect_uris: [uri] })); assert.equal(r.status, 400);
  }
});
test('authorization requires registered redirect and S256', async () => {
  const { call } = fixture(); const client = await register(call);
  const r = await call('/oauth/authorize?' + new URLSearchParams({ client_id: client.client_id, redirect_uri: client.redirect_uris[0], response_type: 'code', code_challenge_method: 'plain', code_challenge: 'a'.repeat(43) })); assert.equal(r.status, 400);
});
test('login blocks cross-origin and missing CSRF cookie', async () => {
  const { call } = fixture(); const client = await register(call); const a = await authFlow(call, client);
  const body = { request_id: a.request_id, bridge_key: KEY };
  assert.equal((await call('/oauth/authorize', postForm(body, { Origin: 'https://evil.example', Cookie: a.cookie }))).status, 403);
  assert.equal((await call('/oauth/authorize', postForm(body, { Origin: BASE }))).status, 403);
});
test('PKCE, one-time codes, bearer access and refresh rotation work', async () => {
  const { call } = fixture(); const client = await register(call); const a = await authFlow(call, client);
  const response = await call('/oauth/authorize', postForm({ request_id: a.request_id, bridge_key: KEY }, { Origin: BASE, Cookie: a.cookie })); assert.equal(response.status, 303);
  const destination = new URL(response.headers.get('Location')); assert.equal(destination.searchParams.get('state'), 'test-state');
  const payload = { grant_type: 'authorization_code', client_id: client.client_id, redirect_uri: client.redirect_uris[0], code: destination.searchParams.get('code'), code_verifier: 'z'.repeat(50) };
  assert.equal((await call('/oauth/token', postForm(payload))).status, 400);
  payload.code_verifier = a.verifier;
  const tokenResponse = await call('/oauth/token', postForm(payload)); assert.equal(tokenResponse.status, 200); const tokens = await tokenResponse.json();
  assert.equal((await call('/oauth/token', postForm(payload))).status, 400);
  const options = postJson({ jsonrpc: '2.0', id: 2, method: 'tools/list' }); options.headers.Authorization = 'Bearer ' + tokens.access_token;
  assert.equal((await call('/mcp', options)).status, 200);
  const refresh = { grant_type: 'refresh_token', client_id: client.client_id, refresh_token: tokens.refresh_token };
  assert.equal((await call('/oauth/token', postForm(refresh))).status, 200);
  assert.equal((await call('/oauth/token', postForm(refresh))).status, 400);
});
test('request bodies are bounded', async () => {
  const { call } = fixture(); const r = await call('/mcp', { method: 'POST', headers: { Authorization: 'Bearer ' + KEY }, body: 'x'.repeat(70001) }); assert.equal(r.status, 400);
});
test('execution rejects empty prompts and invalid upstream endpoints without fetching', async () => {
  const { env, call } = fixture();
  for (const text of ['', 'valid prompt']) {
    env.ROUTINE_FIRE_URL = 'https://evil.example/fire';
    const options = postJson({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'start_development', arguments: { text } } }); options.headers.Authorization = 'Bearer ' + KEY;
    const data = await (await call('/mcp', options)).json(); assert.ok(data.error);
  }
});

