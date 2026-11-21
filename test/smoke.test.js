const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { test, before, after } = require('node:test');
const WebSocket = require('ws');

const appDir = path.resolve(__dirname, '..');
const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lan-chat-test-'));
const port = 13981;
const base = `http://127.0.0.1:${port}`;
const adminPassword = 'fixture-admin-password';
let server;
let adminCookie = '';

async function waitForServer() {
  for (let attempt = 0; attempt < 160; attempt += 1) {
    try { const response = await fetch(`${base}/api/health`); if (response.ok) return; } catch (_) {}
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error('test server did not start');
}
function waitForMessage(ws, predicate, timeout = 3000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { cleanup(); reject(new Error('timed out waiting for websocket message')); }, timeout);
    const handler = (raw) => { const value = JSON.parse(raw.toString()); if (predicate(value)) { cleanup(); resolve(value); } };
    const cleanup = () => { clearTimeout(timer); ws.off('message', handler); };
    ws.on('message', handler);
  });
}
async function openClient(deviceId = 'test-device-000000000001', cookie = '') {
  const ws = new WebSocket(`ws://127.0.0.1:${port}/?deviceId=${deviceId}`, cookie ? { headers: { Cookie: cookie } } : undefined);
  return new Promise((resolve, reject) => {
    let welcome;
    const history = [];
    const timer = setTimeout(() => reject(new Error('client history timed out')), 3000);
    ws.on('message', (raw) => {
      const value = JSON.parse(raw.toString());
      if (value.type === 'welcome') welcome = value;
      if (value.type === 'history-message') history.push(value.message);
      if (value.type === 'history-complete') { clearTimeout(timer); resolve({ ws, welcome, history }); }
    });
    ws.on('error', reject);
  });
}

before(async () => {
  const env = { ...process.env, PORT: String(port), DATA_DIR: dataDir, ADMIN_PASSWORD: adminPassword };
  delete env.PUBLIC_MCP_URL;
  server = spawn(process.execPath, ['server.js'], { cwd: appDir, env, stdio: ['ignore', 'pipe', 'pipe'] });
  await waitForServer();
});
after(() => {
  if (server) server.kill('SIGTERM');
  fs.rmSync(dataDir, { recursive: true, force: true });
});

test('health and unlimited upload config', async () => {
  const health = await fetch(`${base}/api/health`).then((response) => response.json());
  const config = await fetch(`${base}/api/config`).then((response) => response.json());
  assert.equal(health.ok, true); assert.equal(health.version, '2.5.1'); assert.equal(config.maxUploadBytes, null); assert.equal(config.features.macIdentity, true); assert.equal(config.features.ipv6, true); assert.equal(config.features.accountAuth, true); assert.equal(config.features.multiDeviceAccounts, true); assert.equal(config.features.privateGroups, true); assert.equal(config.features.agentScope, true); assert.equal(config.features.mcp, true); assert.equal(config.features.longTextMarkdown, true);
});

test('streams an upload and serves it back', async () => {
  const bytes = new Uint8Array(Buffer.alloc(2 * 1024 * 1024 + 17, 0x5a));
  const form = new FormData(); form.append('file', new Blob([bytes], { type: 'application/octet-stream' }), 'large-test.bin');
  const response = await fetch(`${base}/api/upload`, { method: 'POST', body: form });
  assert.equal(response.status, 200);
  const uploaded = await response.json(); assert.equal(uploaded.size, bytes.length); assert.equal(uploaded.name, 'large-test.bin');
  const downloaded = new Uint8Array(await fetch(`${base}${uploaded.url}`).then((value) => value.arrayBuffer()));
  assert.deepEqual(downloaded, bytes);
});

test('forces reliable attachment downloads with ranges and UTF-8 filenames', async () => {
  const bytes = new TextEncoder().encode('download-range-check');
  const form = new FormData(); form.append('file', new Blob([bytes], { type: 'video/mp4' }), '测试视频.mp4');
  const response = await fetch(`${base}/api/upload`, { method: 'POST', body: form });
  assert.equal(response.status, 200);
  const uploaded = await response.json(); assert.equal(uploaded.name, '测试视频.mp4');
  const filename = uploaded.url.split('/').pop();
  const downloadUrl = `${base}/api/download/${filename}?name=${encodeURIComponent(uploaded.name)}`;
  const full = await fetch(downloadUrl);
  assert.equal(full.status, 200); assert.match(full.headers.get('content-disposition') || '', /^attachment;/);
  assert.deepEqual(new Uint8Array(await full.arrayBuffer()), bytes);
  const partial = await fetch(downloadUrl, { headers: { range: 'bytes=2-7' } });
  assert.equal(partial.status, 206); assert.equal(partial.headers.get('content-range'), `bytes 2-7/${bytes.length}`);
  assert.deepEqual(new Uint8Array(await partial.arrayBuffer()), bytes.slice(2, 8));
});

test('ships legacy mobile viewport and touch-scroll fallbacks', () => {
  const css = fs.readFileSync(path.join(appDir, 'public', 'style.css'), 'utf8');
  const script = fs.readFileSync(path.join(appDir, 'public', 'app.js'), 'utf8');
  assert.match(css, /height:\s*100vh;\s*height:\s*100dvh/);
  assert.match(css, /-webkit-overflow-scrolling:\s*touch/);
  assert.match(css, /touch-action:\s*pan-y/);
  assert.match(script, /function interruptAutoScroll\(\)/);
  assert.match(script, /scrollPinToken/);
});

test('creates group, sends and retracts a message', async () => {
  const { ws, welcome } = await openClient();
  assert.equal(welcome.self.ip, '127.0.0.1');
  assert.equal(welcome.self.name, '127.0.0.1');
  assert.equal(welcome.self.identityBasis, 'device');
  const groupPromise = waitForMessage(ws, (value) => value.type === 'group-created');
  ws.send(JSON.stringify({ type: 'create-group', name: '自动测试组' }));
  const group = (await groupPromise).group;
  const sentPromise = waitForMessage(ws, (value) => value.type === 'message' && value.text === '可以撤回');
  ws.send(JSON.stringify({ type: 'message', groupId: group.id, kind: 'text', text: '可以撤回' }));
  const sent = await sentPromise;
  const retractPromise = waitForMessage(ws, (value) => value.type === 'message-retracted' && value.messageId === sent.id);
  ws.send(JSON.stringify({ type: 'retract-message', messageId: sent.id }));
  await retractPromise;

  const deletedGroupPromise = waitForMessage(ws, (value) => value.type === 'group-created' && value.group.name === '待删除测试组');
  ws.send(JSON.stringify({ type: 'create-group', name: '待删除测试组' }));
  const deletedGroup = (await deletedGroupPromise).group;
  const doomedMessagePromise = waitForMessage(ws, (value) => value.type === 'message' && value.groupId === deletedGroup.id && value.text === '删除后消失');
  ws.send(JSON.stringify({ type: 'message', groupId: deletedGroup.id, kind: 'text', text: '删除后消失' }));
  await doomedMessagePromise;
  const groupDeletedPromise = waitForMessage(ws, (value) => value.type === 'group-deleted' && value.groupId === deletedGroup.id);
  ws.send(JSON.stringify({ type: 'delete-group', groupId: deletedGroup.id }));
  await groupDeletedPromise; ws.close();

  const fresh = await openClient('after-group-delete-0001');
  assert.equal(fresh.history.some((message) => message.text === '删除后消失'), false);
  fresh.ws.close();
});

test('uploads a custom avatar and persists a self-edited profile by device id', async () => {
  const png = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=', 'base64');
  const form = new FormData(); form.append('file', new Blob([png], { type: 'image/png' }), 'avatar.png');
  const avatarResponse = await fetch(`${base}/api/avatar`, { method: 'POST', body: form });
  assert.equal(avatarResponse.status, 200); const avatar = await avatarResponse.json();
  const first = await openClient();
  const updatedPromise = waitForMessage(first.ws, (value) => value.type === 'profile-updated');
  first.ws.send(JSON.stringify({ type: 'update-profile', alias: '个人名字', color: '#4f7569', avatarSeed: 'abcdef12', avatarUrl: avatar.url }));
  const updated = await updatedPromise; assert.equal(updated.profile.name, '个人名字'); assert.equal(updated.profile.avatarUrl, avatar.url); first.ws.close();
  const again = await openClient(); assert.equal(again.welcome.self.name, '个人名字'); assert.equal(again.welcome.self.avatarUrl, avatar.url); again.ws.close();
  const other = await openClient('test-device-000000000002'); assert.equal(other.welcome.self.name, '127.0.0.1'); other.ws.close();
});

test('supports multi-device account sessions and immutable message sender snapshots', async () => {
  const registration = await fetch(`${base}/api/auth/register`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: '多端用户', password: 'fixture-user-password', passwordConfirmation: 'fixture-user-password' }) });
  assert.equal(registration.status, 201);
  const account = await registration.json();
  assert.equal(account.account.username, '多端用户');
  const cookie = registration.headers.get('set-cookie').split(';')[0];
  const first = await openClient('account-device-00000001', cookie);
  const second = await openClient('account-device-00000002', cookie);
  assert.equal(first.welcome.self.identityBasis, 'account');
  assert.equal(first.welcome.self.profileId, second.welcome.self.profileId);
  assert.equal(first.welcome.self.name, '多端用户');

  const firstMessagePromise = waitForMessage(first.ws, (value) => value.type === 'message' && value.text === '旧身份消息');
  const secondMessagePromise = waitForMessage(second.ws, (value) => value.type === 'message' && value.text === '旧身份消息');
  first.ws.send(JSON.stringify({ type: 'message', groupId: 'lobby', kind: 'text', text: '旧身份消息' }));
  const firstMessage = await firstMessagePromise; const secondMessage = await secondMessagePromise;
  assert.equal(firstMessage.sender.name, '多端用户'); assert.equal(secondMessage.sender.name, '多端用户');

  const profileUpdate = waitForMessage(first.ws, (value) => value.type === 'profile-updated');
  first.ws.send(JSON.stringify({ type: 'update-profile', alias: '新的账号名字', color: '#4f7569', avatarSeed: 'abcdef12', avatarUrl: '' }));
  await profileUpdate;
  const newMessage = waitForMessage(first.ws, (value) => value.type === 'message' && value.text === '新身份消息');
  first.ws.send(JSON.stringify({ type: 'message', groupId: 'lobby', kind: 'text', text: '新身份消息' }));
  assert.equal((await newMessage).sender.name, '新的账号名字');
  const historyAgain = await openClient('account-device-00000003', cookie);
  assert.equal(historyAgain.history.find((message) => message.text === '旧身份消息').sender.name, '多端用户');
  assert.equal(historyAgain.history.find((message) => message.text === '新身份消息').sender.name, '新的账号名字');
  first.ws.close(); second.ws.close(); historyAgain.ws.close();
});

test('admin authentication and profile updates', async () => {
  const denied = await fetch(`${base}/api/admin/state`); assert.equal(denied.status, 401);
  const login = await fetch(`${base}/api/admin/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ password: adminPassword }) });
  assert.equal(login.status, 200); adminCookie = login.headers.get('set-cookie').split(';')[0];
  const state = await fetch(`${base}/api/admin/state`, { headers: { cookie: adminCookie } }).then((response) => response.json());
  assert.ok(state.profiles.some((profile) => profile.ip === '127.0.0.1'));
  const target = state.profiles.find((profile) => profile.name === '个人名字');
  assert.equal(target.identityType, 'device');
  const update = await fetch(`${base}/api/admin/profile`, { method: 'PUT', headers: { cookie: adminCookie, 'content-type': 'application/json' }, body: JSON.stringify({ key: target.key, alias: '测试设备', color: '#4f7569', avatarSeed: 'abcdef12', avatarUrl: target.avatarUrl }) });
  assert.equal(update.status, 200); assert.equal((await update.json()).profile.name, '测试设备');
});

test('filters group history by membership and supports private account groups', async () => {
  const owner = await openClient('membership-owner-000001');
  const groupPromise = waitForMessage(owner.ws, (value) => value.type === 'group-created' && value.group.name === '成员隔离测试组');
  owner.ws.send(JSON.stringify({ type: 'create-group', name: '成员隔离测试组' }));
  const group = (await groupPromise).group;
  const messagePromise = waitForMessage(owner.ws, (value) => value.type === 'message' && value.text === '只有成员看到');
  owner.ws.send(JSON.stringify({ type: 'message', groupId: group.id, kind: 'text', text: '只有成员看到' }));
  await messagePromise;
  const outsider = await openClient('membership-outsider-00001');
  assert.equal(outsider.history.some((message) => message.text === '只有成员看到'), false);
  const joinedHistory = waitForMessage(outsider.ws, (value) => value.type === 'group-history' && value.groupId === group.id);
  outsider.ws.send(JSON.stringify({ type: 'join-group', groupId: group.id }));
  const joined = await joinedHistory;
  assert.equal(joined.messages.some((message) => message.text === '只有成员看到'), true);
  const left = waitForMessage(outsider.ws, (value) => value.type === 'group-left' && value.groupId === group.id);
  outsider.ws.send(JSON.stringify({ type: 'leave-group', groupId: group.id }));
  await left;
  owner.ws.close(); outsider.ws.close();

  const registration = await fetch(`${base}/api/auth/register`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: '隐私群用户', password: 'fixture-user-password', passwordConfirmation: 'fixture-user-password' }) });
  assert.equal(registration.status, 201);
  const cookie = registration.headers.get('set-cookie').split(';')[0];
  const accountClient = await openClient('private-owner-000001', cookie);
  const hiddenGroup = waitForMessage(accountClient.ws, (value) => value.type === 'group-created' && value.group.isPrivate);
  accountClient.ws.send(JSON.stringify({ type: 'create-group', name: '只属于我的隐私群', privateGroup: true }));
  const privateGroup = (await hiddenGroup).group;
  assert.equal(privateGroup.isPrivate, true);
  const scope = await fetch(`${base}/api/me/agent-scope`, { headers: { cookie } }).then((response) => response.json());
  assert.ok(scope.groups.some((item) => item.id === privateGroup.id && item.isPrivate));
  const promptMessage = waitForMessage(accountClient.ws, (value) => value.type === 'message' && value.kind === 'system' && value.groupId === privateGroup.id);
  const savedScope = await fetch(`${base}/api/me/agent-scope`, { method: 'PUT', headers: { cookie, 'content-type': 'application/json' }, body: JSON.stringify({ groupIds: [privateGroup.id] }) }).then((response) => response.json());
  assert.deepEqual(savedScope.selectedGroupIds, [privateGroup.id]);
  await promptMessage;
  const mcpPrompt = await fetch(`${base}/api/mcp/prompt`, { headers: { cookie } }).then((response) => response.json());
  assert.match(mcpPrompt.prompt, /https:\/\/chat\.example\.com\/mcp/);
  const token = mcpPrompt.prompt.match(/nchat_[A-Za-z0-9_-]+/)[0];
  const mcpScope = await fetch(`${base}/mcp`, { method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'get_my_agent_scope', arguments: {} } }) }).then((response) => response.json());
  assert.equal(mcpScope.error, undefined); assert.match(mcpScope.result.content[0].text, /只属于我的隐私群/);
  const longMessagePromise = waitForMessage(accountClient.ws, (value) => value.type === 'message' && value.kind === 'long-text');
  accountClient.ws.send(JSON.stringify({ type: 'message', groupId: privateGroup.id, kind: 'text', text: '长消息'.repeat(1000) }));
  const longMessage = await longMessagePromise;
  assert.equal(longMessage.file.mime, 'text/markdown');
  const markdown = await fetch(`${base}${longMessage.file.url}`, { headers: { cookie } });
  assert.equal(markdown.status, 200); assert.match(await markdown.text(), /^长消息/);
  const disabled = waitForMessage(accountClient.ws, (value) => value.type === 'preferences-updated' && value.preferences.longMessageAsMarkdown === false);
  accountClient.ws.send(JSON.stringify({ type: 'update-preferences', longMessageAsMarkdown: false }));
  await disabled;
  const plainMessagePromise = waitForMessage(accountClient.ws, (value) => value.type === 'message' && value.text === '关掉自动 Markdown 后的长消息');
  accountClient.ws.send(JSON.stringify({ type: 'message', groupId: privateGroup.id, kind: 'text', text: '关掉自动 Markdown 后的长消息' }));
  assert.equal((await plainMessagePromise).kind, 'text');
  accountClient.ws.close();
});
