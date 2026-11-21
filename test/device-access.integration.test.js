const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { once } = require('node:events');
const WebSocket = require('ws');

test('HTTP, WebSocket and MCP enforce enrollment and a real sixty-second window', { timeout: 85000 }, async t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'device-admission-integration-'));
  const port = 13985;
  const base = `http://127.0.0.1:${port}`;
  const lan = '192.0.2.10';
  const wan = '198.51.100.15';
  let server;
  async function stop() {
    if (server && server.exitCode === null) { const exit = once(server, 'exit'); server.kill('SIGTERM'); await exit; }
  }
  async function start() {
    const env = { ...process.env, PORT: String(port), DATA_DIR: dir, ADMIN_PASSWORD: 'fixture-admin-password', DEVICE_ADMISSION_ENABLED: '1', DEVICE_LAN_CIDRS: '192.0.2.0/24', DEVICE_LAN_EXCLUDED_IPS: '192.0.2.1,192.0.2.2', DEVICE_ALLOWED_HOSTS: '127.0.0.1' };
    delete env.PUBLIC_MCP_URL;
    server = spawn(process.execPath, ['server.js'], { cwd: path.resolve(__dirname, '..'), env, stdio: ['ignore', 'ignore', 'pipe'] });
    for (let i = 0; i < 100; i++) {
      try { if ((await request('/api/health', { peer: lan })).ok) return; } catch (_) {}
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    throw new Error('isolated server failed to start');
  }
  t.after(async () => { await stop(); fs.rmSync(dir, { recursive: true, force: true }); });
  function request(url, { peer = wan, cookie = '', method = 'GET', body, headers = {} } = {}) {
    return fetch(base + url, { method, headers: { 'x-forwarded-for': peer, ...(cookie ? { cookie } : {}), ...(body !== undefined ? { 'content-type': 'application/json' } : {}), ...headers }, body: body !== undefined ? JSON.stringify(body) : undefined, redirect: 'manual' });
  }
  function pairs(response) { return response.headers.getSetCookie().map(value => value.split(';')[0]); }
  function websocket({ peer = wan, cookie = '', origin = base } = {}) {
    return new Promise((resolve, reject) => {
      let credential = ''; let welcome;
      const ws = new WebSocket(`ws://127.0.0.1:${port}/?deviceId=publicly-guessable-device-id`, { headers: { 'x-forwarded-for': peer, origin, ...(cookie ? { Cookie: cookie } : {}) } });
      const timer = setTimeout(() => { ws.terminate(); reject(new Error('websocket timeout')); }, 3000);
      ws.on('upgrade', res => { credential = (res.headers['set-cookie'] || []).map(x => x.split(';')[0]).find(x => x.startsWith('lan_chat_known_device=')) || ''; });
      ws.on('unexpected-response', (_, res) => { clearTimeout(timer); res.resume(); resolve({ denied: res.statusCode }); });
      ws.on('error', () => {});
      ws.on('message', raw => {
        const value = JSON.parse(raw);
        if (value.type === 'welcome') welcome = value;
        if (value.type === 'history-complete') { clearTimeout(timer); ws.close(); resolve({ welcome, cookie: credential }); }
      });
    });
  }

  await start();
  for (const url of ['/', '/app.js', '/api/config', '/api/health', '/admin', '/uploads/no-file', '/api/download/no-file']) {
    assert.equal((await request(url)).status, 403, url);
  }
  assert.equal((await request('/api/auth/login', { method: 'POST', body: { username: 'somebody', password: 'fixture-wrong-password' } })).status, 403);
  assert.equal((await request('/api/auth/anonymous', { method: 'POST' })).status, 403);
  assert.equal((await request('/mcp', { method: 'POST', body: { method: 'initialize' } })).status, 403);
  assert.equal((await websocket()).denied, 403);
  assert.equal((await websocket({ peer: lan, origin: 'https://attacker.invalid' })).denied, 403);

  assert.equal((await request('/api/auth/anonymous', { peer: lan, method: 'POST', headers: { origin: 'https://attacker.invalid' } })).status, 403);
  const anonymousLan = await websocket({ peer: lan });
  assert.ok(anonymousLan.welcome);
  assert.ok(anonymousLan.cookie);
  assert.equal((await request('/', { cookie: anonymousLan.cookie })).status, 200);
  assert.equal((await request('/api/access/window', { peer: lan, method: 'POST', body: {} })).status, 401);
  assert.equal((await request('/api/access/window', { cookie: anonymousLan.cookie, method: 'POST', body: { role: 'account' } })).status, 401);

  const account = { username: 'admission-test-account', password: 'fixture-user-password', passwordConfirmation: 'fixture-user-password' };
  const registration = await request('/api/auth/register', { peer: lan, method: 'POST', body: account });
  assert.equal(registration.status, 201);
  const cookies = pairs(registration).join('; ');
  const authOnly = pairs(registration).find(x => x.startsWith('lan_chat_session='));
  assert.equal((await request('/api/auth/login', { method: 'POST', body: account })).status, 403, 'valid password alone must not bypass admission');
  assert.equal((await request('/', { cookie: authOnly })).status, 403, 'account session alone is not a recognized device');
  assert.equal((await request('/api/access/window', { cookie: cookies, method: 'POST', body: {}, headers: { origin: 'https://attacker.invalid' } })).status, 403);
  const prompt = await (await request('/api/mcp/prompt', { cookie: cookies })).json();
  const token = prompt.prompt.match(/nchat_[A-Za-z0-9_-]+/)[0];
  const mcp = { authorization: `Bearer ${token}` };
  assert.equal((await request('/mcp', { method: 'POST', body: { method: 'initialize' }, headers: mcp })).status, 403);

  const opened = await request('/api/access/window', { cookie: cookies, method: 'POST', body: { duration: 999999999 }, headers: { origin: base } });
  assert.equal(opened.status, 200);
  const window = await opened.json();
  assert.ok(window.expiresAt - window.serverNow <= 60000 && window.expiresAt - window.serverNow > 59900);
  const visitor = await request('/');
  assert.equal(visitor.status, 200);
  assert.equal(pairs(visitor).length, 0, 'opening the page alone must not enroll');
  const anonymousLogin = await request('/api/auth/anonymous', { method: 'POST' });
  assert.equal(anonymousLogin.status, 200);
  const anonymousHttpCookie = pairs(anonymousLogin).find(x => x.startsWith('lan_chat_known_device='));
  assert.ok(anonymousHttpCookie);
  const newAnonymous = await websocket();
  assert.ok(newAnonymous.welcome);
  assert.ok(newAnonymous.cookie);
  const initialized = await request('/mcp', { method: 'POST', headers: mcp, body: { jsonrpc: '2.0', id: 1, method: 'initialize' } });
  assert.equal(initialized.status, 200);
  const mcpCookie = pairs(initialized).find(x => x.startsWith('lan_chat_known_device='));
  assert.ok(mcpCookie);

  await new Promise(resolve => setTimeout(resolve, Math.max(0, window.expiresAt - Date.now() + 120)));
  assert.equal((await request('/')).status, 403, 'unregistered visitor must be rejected after actual expiry');
  assert.equal((await websocket()).denied, 403);
  assert.equal((await request('/', { cookie: newAnonymous.cookie })).status, 200);
  assert.equal((await request('/', { cookie: anonymousHttpCookie })).status, 200);
  assert.ok((await websocket({ cookie: newAnonymous.cookie })).welcome);
  assert.equal((await request('/mcp', { method: 'POST', headers: mcp, body: { method: 'initialize' } })).status, 403);
  assert.equal((await request('/mcp', { cookie: mcpCookie, method: 'POST', headers: mcp, body: { method: 'initialize' } })).status, 200);
  await request('/api/auth/logout', { cookie: newAnonymous.cookie, method: 'POST' });
  assert.equal((await request('/', { cookie: newAnonymous.cookie })).status, 200, 'anonymous mode remains available after logout');

  await stop();
  await start();
  assert.equal((await request('/')).status, 403);
  assert.equal((await request('/', { cookie: newAnonymous.cookie })).status, 200, 'recognized device survives service restart');
});
