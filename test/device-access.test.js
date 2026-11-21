const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createDeviceAccess, WINDOW_MS } = require('../device-access');

// RFC 5737 / RFC 3849 documentation addresses. They are fixtures, not a deployment network.
const LAN_IP = '192.0.2.10';
const LAN_V6 = '2001:db8:1::123';

function fixture() {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'known-devices-unit-'));
  let time = 1_000_000;
  const config = { dataDir, lanCidrs: ['192.0.2.0/24', '2001:db8:1::/64'], excludedIps: ['192.0.2.1', '192.0.2.2', '192.0.2.3'], allowedHosts: ['chat.test'], now: () => time };
  return { dataDir, config, access: createDeviceAccess(config), advance: ms => time += ms, cleanup: () => fs.rmSync(dataDir, { recursive: true, force: true }) };
}
function req(ip, extra = {}) { return { socket: { remoteAddress: ip, localAddress: '192.0.2.2' }, headers: { host: 'chat.test:9900', ...extra } }; }
const cookiePair = cookie => cookie.split(';')[0];

test('trusts only configured LAN ranges and verified proxy addresses', () => {
  const f = fixture();
  try {
    assert.equal(f.access.isLan(req(`::ffff:${LAN_IP}`)), true);
    assert.equal(f.access.isLan(req(LAN_V6)), true);
    for (const ip of ['192.0.2.1', '192.0.2.2', '192.0.2.3', '203.0.113.2', '2001:db8:2::1', '198.51.100.8']) assert.equal(f.access.isLan(req(ip)), false);
    assert.equal(f.access.allowed(req('198.51.100.8', { 'x-forwarded-for': LAN_IP })), false);
    assert.equal(f.access.isLan(req('127.0.0.1', { 'x-forwarded-for': LAN_IP })), true);
    assert.equal(f.access.isLan(req('127.0.0.1', { 'x-forwarded-for': `${LAN_IP}, 198.51.100.1` })), false);
  } finally { f.cleanup(); }
});

test('a page visit, public device ID or account-shaped cookie does not enroll a device', () => {
  const f = fixture();
  try {
    assert.equal(f.access.allowed(req(LAN_IP)), true);
    assert.equal(fs.existsSync(path.join(f.dataDir, 'known-devices.json')), false);
    assert.equal(f.access.known(req(LAN_IP)), null);
    assert.equal(f.access.allowed(req('198.51.100.8', { cookie: 'lan_chat_device=public-device-id-12345; lan_chat_session=pretend-account' })), false);
  } finally { f.cleanup(); }
});

test('rejects DNS-rebinding hosts and cross-origin browser requests', () => {
  const f = fixture();
  try {
    const rebound = req(LAN_IP, { host: 'attacker.test:9900', origin: 'http://attacker.test:9900' });
    assert.equal(f.access.allowed(rebound), false);
    assert.equal(f.access.remember(rebound), null);
    assert.equal(f.access.sameOrigin(req(LAN_IP, { origin: 'http://attacker.test:9900' })), false);
    assert.equal(f.access.sameOrigin(req(LAN_IP, { origin: 'null' })), false);
    assert.equal(f.access.sameOrigin(req('127.0.0.1', { host: '127.0.0.1:9900', 'x-forwarded-host': 'chat.test:9900', origin: 'https://chat.test:9900' })), true);
  } finally { f.cleanup(); }
});

test('window lasts exactly one minute and admitted devices survive expiry and restart', () => {
  const f = fixture();
  try {
    assert.throws(() => f.access.openWindow(''), /authentication/);
    const status = f.access.openWindow('account-one');
    assert.equal(status.expiresAt - status.serverNow, WINDOW_MS);
    assert.equal(f.access.allowed(req('198.51.100.8')), true);
    f.advance(59_999);
    const cookie = f.access.remember(req('198.51.100.8'));
    assert.match(cookie, /HttpOnly; SameSite=Lax/);
    const recognized = req('203.0.113.9', { cookie: cookiePair(cookie) });
    f.advance(1);
    assert.equal(f.access.allowed(req('198.51.100.8')), false);
    assert.equal(f.access.remember(req('198.51.100.8')), null);
    assert.equal(f.access.allowed(recognized), true);
    const restarted = createDeviceAccess(f.config);
    assert.equal(restarted.allowed(recognized), true);
    assert.equal(restarted.allowed(req('198.51.100.8')), false);
    const saved = fs.readFileSync(path.join(f.dataDir, 'known-devices.json'), 'utf8');
    assert.equal(saved.includes(cookiePair(cookie).split('=')[1]), false);
    assert.equal(fs.statSync(path.join(f.dataDir, 'known-devices.json')).mode & 0o777, 0o600);
    assert.equal(restarted.allowed(req('198.51.100.8', { cookie: `${cookiePair(cookie)}x` })), false);
  } finally { f.cleanup(); }
});

test('LAN enrollment is independent of account logout and secures HTTPS cookies', () => {
  const f = fixture();
  try {
    const local = req(LAN_IP); local.socket.encrypted = true;
    const cookie = f.access.remember(local, { accountId: 'account-one', kind: 'account' });
    assert.match(cookie, /; Secure$/);
    assert.equal(f.access.allowed(req('198.51.100.8', { cookie: cookiePair(cookie) })), true);
    assert.equal(f.access.allowed(req('198.51.100.8', { cookie: 'lan_chat_known_device=' + 'a'.repeat(43) })), false);
  } finally { f.cleanup(); }
});
