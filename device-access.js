'use strict';
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const net = require('node:net');

const COOKIE = 'lan_chat_known_device';
const WINDOW_MS = 60_000;
function normalizeIp(value = '') {
  const ip = String(value).split('%')[0];
  return ip.startsWith('::ffff:') ? ip.slice(7) : ip;
}
function credential(req) {
  const part = String(req.headers.cookie || '').split(';').map(x => x.trim()).find(x => x.startsWith(`${COOKIE}=`));
  const value = part ? part.slice(COOKIE.length + 1) : '';
  return /^[A-Za-z0-9_-]{43}$/.test(value) ? value : '';
}
function digest(value) { return crypto.createHash('sha256').update(value).digest('hex'); }

function createDeviceAccess({ dataDir, lanCidrs, excludedIps = [], allowedHosts = [], trustedProxyIps = ['127.0.0.1', '::1'], now = Date.now }) {
  const file = path.join(dataDir, 'known-devices.json');
  const networks = new net.BlockList();
  const excluded = new Set(excludedIps.map(normalizeIp));
  const proxies = new Set(trustedProxyIps.map(normalizeIp));
  const hosts = new Set(allowedHosts.map(x => x.toLowerCase()));
  for (const cidr of lanCidrs) {
    const [address, bits] = cidr.split('/');
    const family = net.isIP(address);
    if (!family || bits === undefined) throw new Error('Invalid device-admission LAN CIDR');
    networks.addSubnet(address, Number(bits), family === 4 ? 'ipv4' : 'ipv6');
  }
  let records = {};
  if (fs.existsSync(file)) {
    const saved = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (saved.version !== 1 || !saved.devices || Array.isArray(saved.devices)) throw new Error('Invalid known-device store');
    records = saved.devices;
  }
  let windowUntil = 0;
  function save() {
    const temporary = `${file}.${crypto.randomUUID()}.tmp`;
    fs.writeFileSync(temporary, JSON.stringify({ version: 1, devices: records }, null, 2), { mode: 0o600, flag: 'wx' });
    fs.renameSync(temporary, file);
  }
  function proxyRequest(req) { return proxies.has(normalizeIp(req.socket.remoteAddress)); }
  function clientIp(req) {
    // Only the verified local proxy may supply one original peer address.
    if (proxyRequest(req)) {
      const forwarded = String(req.headers['x-forwarded-for'] || '').trim();
      if (net.isIP(forwarded)) return normalizeIp(forwarded);
    }
    return normalizeIp(req.socket.remoteAddress);
  }
  function requestHost(req) {
    return String(proxyRequest(req) && req.headers['x-forwarded-host'] || req.headers.host || '');
  }
  function validHost(req) {
    try {
      const hostname = new URL(`http://${requestHost(req)}`).hostname.replace(/^\[|\]$/g, '').toLowerCase();
      return hosts.has(hostname) || normalizeIp(hostname) === normalizeIp(req.socket.localAddress);
    } catch (_) { return false; }
  }
  function isLan(req) {
    const ip = clientIp(req);
    if (excluded.has(ip)) return false;
    const family = net.isIP(ip);
    return !!family && networks.check(ip, family === 4 ? 'ipv4' : 'ipv6');
  }
  function known(req) {
    const token = credential(req);
    return token && records[digest(token)] ? records[digest(token)] : null;
  }
  function status() {
    const serverNow = now();
    return { serverNow, expiresAt: windowUntil > serverNow ? windowUntil : 0, remainingSeconds: Math.max(0, Math.ceil((windowUntil - serverNow) / 1000)) };
  }
  function allowed(req) { return validHost(req) && (isLan(req) || !!known(req) || windowUntil > now()); }
  function remember(req, { accountId = '', kind = 'anonymous' } = {}) {
    if (!validHost(req)) return null;
    let token = credential(req);
    if (!known(req)) {
      if (!validHost(req) || !isLan(req) && windowUntil <= now()) return null;
      token = crypto.randomBytes(32).toString('base64url');
      records[digest(token)] = { id: crypto.randomUUID(), enrolledAt: new Date(now()).toISOString(), source: isLan(req) ? 'lan' : 'window', accountId, kind };
      save();
    }
    const secure = req.socket.encrypted || proxyRequest(req) && req.headers['x-forwarded-proto'] === 'https';
    return `${COOKIE}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=34560000${secure ? '; Secure' : ''}`;
  }
  function openWindow(accountId) {
    if (!accountId) throw new Error('Account authentication required');
    windowUntil = now() + WINDOW_MS;
    return status();
  }
  function sameOrigin(req) {
    const origin = req.headers.origin;
    if (!origin) return true; // Native authenticated clients need not send Origin.
    try {
      const parsed = new URL(origin);
      return ['http:', 'https:'].includes(parsed.protocol) && parsed.host.toLowerCase() === requestHost(req).toLowerCase();
    } catch (_) { return false; }
  }
  function deny(req, res) {
    res.setHeader('Cache-Control', 'no-store');
    if (String(req.headers.accept || '').includes('text/html')) {
      return res.status(403).type('html').send('<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>设备尚未获准访问</title><body><h1>这台设备尚未获准从外网访问</h1><p>请先在公司内网登录，或请已登录账号的同事点击“允许新设备接入 1 分钟”，然后在一分钟内刷新此页并登录。</p><p>若更换了浏览器、使用无痕模式或清除了网站数据，需要重新登记。内网 IP 与 DDNS 域名会分别保存凭证。</p><button onclick="location.reload()">重新检查</button></body></html>');
    }
    return res.status(403).json({ error: '这台设备尚未获准从外网访问。请先在内网登录，或在账号用户开启的 1 分钟窗口内登录。', code: 'DEVICE_NOT_RECOGNIZED' });
  }
  return { isLan, known, allowed, remember, openWindow, status, sameOrigin, deny };
}
module.exports = { createDeviceAccess, COOKIE, WINDOW_MS };
