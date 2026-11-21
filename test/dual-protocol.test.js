const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const https = require('node:https');
const { spawn, execFileSync } = require('node:child_process');
const { once } = require('node:events');
const { test, before, after } = require('node:test');
const WebSocket = require('ws');

const appDir = path.resolve(__dirname, '..');
const testDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lan-chat-dual-test-'));
const port = 13982;
const base = `http://127.0.0.1:${port}`;
const certPath = path.join(testDir, 'cert.pem');
const keyPath = path.join(testDir, 'key.pem');
let server;
let ca;

function secureRequest(route, options = {}) {
  return new Promise((resolve, reject) => {
    const req = https.request(`https://127.0.0.1:${port}${route}`, { ca, ...options }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('error', reject);
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks), authorized: res.socket?.authorized ?? req.socket.authorized }));
    });
    req.on('error', reject);
    req.end(options.body);
  });
}
function receive(ws, predicate) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { cleanup(); reject(new Error('WebSocket timed out')); }, 3000);
    const handler = (raw) => { const message = JSON.parse(raw); if (predicate(message)) { cleanup(); resolve(message); } };
    const cleanup = () => { clearTimeout(timer); ws.off('message', handler); };
    ws.on('message', handler);
  });
}

before(async () => {
  const configPath = path.join(testDir, 'openssl.cnf');
  fs.writeFileSync(configPath, '[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=localhost\n[ext]\nsubjectAltName=IP:127.0.0.1,DNS:localhost\nbasicConstraints=critical,CA:TRUE\n');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', keyPath, '-out', certPath, '-days', '1', '-config', configPath], { stdio: 'ignore' });
  ca = fs.readFileSync(certPath);
  server = spawn(process.execPath, ['server.js'], {
    cwd: appDir,
    env: { ...process.env, PORT: String(port), DATA_DIR: path.join(testDir, 'data'), TLS_CERT_PATH: certPath, TLS_KEY_PATH: keyPath, CA_CERT_PATH: certPath, REQUIRE_HTTPS: '0', MAX_UPLOAD_BYTES: '0', ADMIN_PASSWORD: 'fixture-admin-password' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  for (let attempt = 0; attempt < 160; attempt++) {
    try { if ((await fetch(`${base}/api/health`)).ok) return; } catch (_) {}
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error('dual protocol test server did not start');
});
after(async () => {
  if (server && server.exitCode === null) { const exited = once(server, 'exit'); server.kill('SIGTERM'); await exited; }
  fs.rmSync(testDir, { recursive: true, force: true });
});

test('HTTP serves chat directly even with TLS enabled on the same port', async () => {
  const page = await fetch(`${base}/`, { redirect: 'manual' });
  assert.equal(page.status, 200); assert.equal(page.headers.get('location'), null);
  assert.match(await page.text(), /id="messages"/);
  const config = await fetch(`${base}/api/config`).then((res) => res.json());
  assert.equal(config.httpChatAllowed, true); assert.equal(config.httpsPort, port);
  const secure = await secureRequest('/');
  assert.equal(secure.status, 200); assert.equal(secure.authorized, true);
  assert.match(secure.body.toString(), /id="messages"/);
});

test('admin UI and APIs redirect to HTTPS and use a Secure session cookie', async () => {
  for (const route of ['/admin', '/admin.html', '/api/admin/state', '/api/admin/login']) {
    const res = await fetch(`${base}${route}`, { redirect: 'manual' });
    assert.equal(res.status, 307); assert.equal(res.headers.get('location'), `https://127.0.0.1:${port}${route}`);
  }
  const denied = await secureRequest('/api/admin/state'); assert.equal(denied.status, 401);
  const login = await secureRequest('/api/admin/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password: 'fixture-admin-password' }) });
  assert.equal(login.status, 200);
  const cookie = login.headers['set-cookie'][0];
  assert.match(cookie, /^__Secure-lan_admin=/); assert.match(cookie, /; Secure$/);
  const state = await secureRequest('/api/admin/state', { headers: { Cookie: cookie.split(';')[0] } }); assert.equal(state.status, 200);
});

test('DOC and 7z downloads retain names, byte integrity and Range on HTTP and HTTPS', async () => {
  for (const extension of ['doc', '7z']) {
    const bytes = Buffer.alloc(1024 * 1024 + 17, 0x61);
    const name = `问题反馈.${extension}`;
    const form = new FormData(); form.append('file', new Blob([bytes]), name);
    const uploaded = await fetch(`${base}/api/upload`, { method: 'POST', body: form }).then((res) => res.json());
    assert.equal(uploaded.name, name); assert.equal(uploaded.size, bytes.length);
    const route = `/api/download/${uploaded.url.split('/').pop()}?name=${encodeURIComponent(name)}`;
    const res = await fetch(`${base}${route}`, { redirect: 'manual' });
    assert.equal(res.status, 200); assert.match(res.headers.get('content-disposition'), /^attachment;/);
    assert.ok(res.headers.get('content-disposition').includes(encodeURIComponent(name)));
    assert.deepEqual(Buffer.from(await res.arrayBuffer()), bytes);
    const secure = await secureRequest(route); assert.equal(secure.status, 200); assert.equal(secure.authorized, true); assert.deepEqual(secure.body, bytes);
    const part = await fetch(`${base}${route}`, { headers: { Range: 'bytes=10-29' } });
    assert.equal(part.status, 206); assert.deepEqual(Buffer.from(await part.arrayBuffer()), bytes.subarray(10, 30));
  }
});

test('HTTP and HTTPS WebSockets share identity and deliver chat and voice-file messages', async (t) => {
  const plain = new WebSocket(`ws://127.0.0.1:${port}/?deviceId=dual-protocol-device-12345`);
  const secure = new WebSocket(`wss://127.0.0.1:${port}/?deviceId=dual-protocol-device-12345`, { ca });
  t.after(() => { plain.terminate(); secure.terminate(); });
  const [a, b] = await Promise.all([receive(plain, (m) => m.type === 'welcome'), receive(secure, (m) => m.type === 'welcome')]);
  assert.equal(a.self.profileId, b.self.profileId);
  const delivered = receive(secure, (m) => m.type === 'message' && m.text === 'HTTP to HTTPS');
  plain.send(JSON.stringify({ type: 'message', kind: 'text', groupId: 'lobby', text: 'HTTP to HTTPS' }));
  await delivered;
  const form = new FormData(); form.append('file', new Blob(['voice-fixture'], { type: 'audio/wav' }), '录音.wav');
  const file = await fetch(`${base}/api/upload`, { method: 'POST', body: form }).then((res) => res.json());
  const voice = receive(secure, (m) => m.type === 'message' && m.kind === 'audio');
  plain.send(JSON.stringify({ type: 'message', kind: 'audio', groupId: 'lobby', file }));
  assert.equal((await voice).file.name, '录音.wav');
  assert.equal((await fetch(`${base}${file.url}`)).status, 200);
});

test('HTTP voice fallback selects audio files without attempting microphone access', () => {
  const html = fs.readFileSync(path.join(appDir, 'public', 'index.html'), 'utf8');
  const script = fs.readFileSync(path.join(appDir, 'public', 'app.js'), 'utf8');
  assert.match(html, /id="voice-file-input"[^>]+accept="audio\//);
  assert.match(script, /if \(!canRecordInPage\(\)\) return;/);
  assert.match(script, /voiceFileInput\.click\(\)/);
  assert.match(script, /addFiles\(audioFiles, 'audio'\)/);
  assert.match(script, /局域网直连 · 明文传输/);
});
