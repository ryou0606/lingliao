const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { execFileSync } = require('node:child_process');
const express = require('express');
const multer = require('multer');
const httpolyglot = require('@httptoolkit/httpolyglot');
const { WebSocketServer, WebSocket } = require('ws');

const PORT = Number(process.env.PORT || 3080);
const APP_VERSION = '2.5.1';
const { createDeviceAccess } = require('./device-access');
const DEVICE_ADMISSION_ENABLED = process.env.DEVICE_ADMISSION_ENABLED === '1';
const PUBLIC_MCP_URL = String(process.env.PUBLIC_MCP_URL || 'https://chat.example.com/mcp').trim();
const LONG_TEXT_CHAR_LIMIT = 2000;
const LONG_TEXT_LINE_LIMIT = 80;
const DATA_DIR = process.env.DATA_DIR ? path.resolve(process.env.DATA_DIR) : path.join(__dirname, 'data');
const UPLOAD_DIR = path.join(DATA_DIR, 'uploads');
const GROUPS_FILE = path.join(DATA_DIR, 'groups.json');
const MESSAGES_FILE = path.join(DATA_DIR, 'messages.json');
const PROFILES_FILE = path.join(DATA_DIR, 'profiles.json');
const ACCOUNTS_FILE = path.join(DATA_DIR, 'accounts.json');
const AUTH_SESSIONS_FILE = path.join(DATA_DIR, 'auth-sessions.json');
const AUTH_KEY_FILE = path.join(DATA_DIR, 'auth-session.key');
const ADMIN_KEY_FILE = path.join(DATA_DIR, 'admin-session.key');
const ADMIN_CREDENTIALS_FILE = path.join(DATA_DIR, 'admin-credentials.json');
const ADMIN_PASSWORD_FILE = path.join(DATA_DIR, 'admin-password.txt');
const MAX_UPLOAD_BYTES = Math.max(0, Number(process.env.MAX_UPLOAD_BYTES || 0));
const TRUST_PROXY = process.env.TRUST_PROXY === '1';
const TLS_CERT_PATH = process.env.TLS_CERT_PATH ? path.resolve(process.env.TLS_CERT_PATH) : '';
const TLS_KEY_PATH = process.env.TLS_KEY_PATH ? path.resolve(process.env.TLS_KEY_PATH) : '';
const CA_CERT_PATH = process.env.CA_CERT_PATH ? path.resolve(process.env.CA_CERT_PATH) : '';
const SESSION_TTL_SECONDS = 12 * 60 * 60;
const AUTH_SESSION_TTL_SECONDS = 30 * 24 * 60 * 60;
const COLORS = ['#4f6f8f', '#6f6654', '#765d69', '#4f7569', '#6c648c', '#7a604b', '#4d7180', '#7b5960'];
const TLS_ENABLED = !!(TLS_CERT_PATH && TLS_KEY_PATH && fs.existsSync(TLS_CERT_PATH) && fs.existsSync(TLS_KEY_PATH));
const REQUIRE_HTTPS = process.env.REQUIRE_HTTPS === '1';
const ADMIN_COOKIE = TLS_ENABLED ? '__Secure-lan_admin' : 'lan_admin';
const AUTH_COOKIE = TLS_ENABLED ? '__Secure-lan_chat_session' : 'lan_chat_session';

fs.mkdirSync(UPLOAD_DIR, { recursive: true });
const deviceAccess = DEVICE_ADMISSION_ENABLED ? createDeviceAccess({
  dataDir: DATA_DIR,
  // No CIDR is trusted until DEVICE_LAN_CIDRS is set. Exclusions are operator-configured too.
  lanCidrs: String(process.env.DEVICE_LAN_CIDRS || '').split(',').map(x => x.trim()).filter(Boolean),
  allowedHosts: String(process.env.DEVICE_ALLOWED_HOSTS || '').split(',').map(x => x.trim()).filter(Boolean),
  excludedIps: String(process.env.DEVICE_LAN_EXCLUDED_IPS || '').split(',').map(x => x.trim()).filter(Boolean),
}) : null;
function rememberDevice(req, res, options) {
  if (!deviceAccess) return;
  const cookie = deviceAccess.remember(req, options);
  if (cookie) { res.append('Set-Cookie', cookie); res.setHeader('Cache-Control', 'no-store'); }
}

function readJson(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch (_) { return fallback; }
}
function writeJson(file, value) {
  const temporaryFile = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(temporaryFile, JSON.stringify(value, null, 2));
  fs.renameSync(temporaryFile, file);
}
function cleanText(value, max = 8000) { return typeof value === 'string' ? value.trim().slice(0, max) : ''; }
function normalizeIp(ip = '') {
  const value = String(ip).trim();
  if (value.startsWith('::ffff:')) return value.slice(7);
  return value === '::1' ? '127.0.0.1' : value;
}
function requestIp(req) {
  const peer = normalizeIp(req.socket.remoteAddress);
  if (TRUST_PROXY && (peer === '127.0.0.1' || peer === '::1')) {
    const forwarded = String(req.headers['x-forwarded-for'] || '').trim();
    if (require('node:net').isIP(forwarded)) return normalizeIp(forwarded);
  }
  return peer;
}
function safeFilename(name) {
  return path.basename(String(name || 'file')).replace(/[\u0000-\u001f<>:"/\\|?*]/g, '_').trim().slice(0, 180) || 'file';
}
function repairMultipartFilename(name) {
  const original = String(name || 'file');
  if (![...original].every((character) => character.codePointAt(0) <= 0xff) || !/[\u0080-\u009f]/.test(original)) return original;
  const repaired = Buffer.from(original, 'latin1').toString('utf8');
  return repaired.includes('\ufffd') ? original : repaired;
}
function storedFilenameFromUrl(url) {
  const match = String(url || '').match(/^\/uploads\/([A-Za-z0-9%_.-]+)$/);
  if (!match) return '';
  try {
    const filename = decodeURIComponent(match[1]);
    return /^[A-Za-z0-9_.-]+$/.test(filename) && path.basename(filename) === filename ? filename : '';
  } catch (_) { return ''; }
}
function safeMime(value) {
  const mime = cleanText(value, 120).toLowerCase();
  return /^[a-z0-9.+-]+\/[a-z0-9.+-]+$/.test(mime) ? mime : 'application/octet-stream';
}
function randomSeed() { return crypto.randomBytes(8).toString('hex'); }
function colorForIdentity(identity) {
  const number = crypto.createHash('sha256').update(identity).digest().readUInt32BE(0);
  return COLORS[number % COLORS.length];
}
function normalizeMac(value = '') {
  const compact = String(value).trim().toLowerCase().replace(/-/g, ':');
  return /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(compact) && compact !== '00:00:00:00:00:00' ? compact : '';
}
const macCache = new Map();
function resolveMac(ip) {
  if (!ip || ip === '127.0.0.1' || ip === '::1') return '';
  const cached = macCache.get(ip);
  if (cached && cached.expiresAt > Date.now()) return cached.mac;
  let mac = '';
  try {
    if (process.platform === 'linux' && !ip.includes(':')) {
      const rows = fs.readFileSync('/proc/net/arp', 'utf8').split(/\r?\n/).slice(1);
      const row = rows.map((line) => line.trim().split(/\s+/)).find((parts) => parts[0] === ip);
      mac = normalizeMac(row && row[3]);
    }
    if (!mac && process.platform === 'linux') {
      const output = execFileSync('/usr/bin/ip', ['neigh', 'show', 'to', ip], { encoding: 'utf8', timeout: 800 });
      mac = normalizeMac((output.match(/\blladdr\s+([0-9a-f:-]{17})/i) || [])[1]);
    }
    if (!mac && process.platform === 'darwin' && !ip.includes(':')) {
      const output = execFileSync('/usr/sbin/arp', ['-n', ip], { encoding: 'utf8', timeout: 800, stdio: ['ignore', 'pipe', 'ignore'] });
      mac = normalizeMac((output.match(/\bat\s+([0-9a-f:-]{11,17})/i) || [])[1]);
    }
  } catch (_) {}
  macCache.set(ip, { mac, expiresAt: Date.now() + 5 * 60 * 1000 });
  return mac;
}
function requestedDeviceId(req) {
  try {
    const value = new URL(req.url || '/', 'http://localhost').searchParams.get('deviceId') || '';
    return /^[a-zA-Z0-9_-]{16,80}$/.test(value) ? value : '';
  } catch (_) { return ''; }
}
function validAvatarUrl(value) {
  const url = cleanText(value, 300);
  return !url || /^\/uploads\/[A-Za-z0-9%_.-]+$/.test(url) ? url : '';
}

let groups = readJson(GROUPS_FILE, []);
if (!Array.isArray(groups)) groups = [];
if (!groups.some((group) => group && group.id === 'lobby')) {
  groups.unshift({ id: 'lobby', name: '公共大厅', createdAt: new Date().toISOString(), createdBy: 'system' });
}
groups = groups.filter((group) => group && typeof group.id === 'string' && typeof group.name === 'string');
for (const group of groups) {
  group.visibility = group.visibility === 'private' ? 'private' : 'public';
  group.createdByAccountId = cleanText(group.createdByAccountId, 80);
}

let messageHistory = readJson(MESSAGES_FILE, []);
if (!Array.isArray(messageHistory)) messageHistory = [];
messageHistory = messageHistory.filter((message) => message && message.type === 'message' && typeof message.id === 'string');
let repairedMessageNames = false;
for (const message of messageHistory) {
  if (!message.file || typeof message.file.name !== 'string') continue;
  const repaired = safeFilename(repairMultipartFilename(message.file.name));
  if (repaired !== message.file.name) { message.file.name = repaired; repairedMessageNames = true; }
}
if (repairedMessageNames) writeJson(MESSAGES_FILE, messageHistory);

let profiles = readJson(PROFILES_FILE, {});
if (!profiles || Array.isArray(profiles) || typeof profiles !== 'object') profiles = {};
let accounts = readJson(ACCOUNTS_FILE, {});
if (!accounts || Array.isArray(accounts) || typeof accounts !== 'object') accounts = {};
let authSessions = readJson(AUTH_SESSIONS_FILE, {});
if (!authSessions || Array.isArray(authSessions) || typeof authSessions !== 'object') authSessions = {};

function saveGroups() { writeJson(GROUPS_FILE, groups); }
function saveMessages() { writeJson(MESSAGES_FILE, messageHistory); }
function saveProfiles() { writeJson(PROFILES_FILE, profiles); }
function saveAccounts() { writeJson(ACCOUNTS_FILE, accounts); }
function saveAuthSessions() { writeJson(AUTH_SESSIONS_FILE, authSessions); }
function ensureProfile(ip, deviceId = '', allowMac = true) {
  const mac = allowMac ? resolveMac(ip) : '';
  const key = mac ? `mac:${mac}` : deviceId ? `device:${deviceId}` : `ip:${ip}`;
  let sourceKey = key;
  let existing = profiles[key] && typeof profiles[key] === 'object' ? profiles[key] : null;
  if (!existing) {
    sourceKey = [ip, `ip:${ip}`].find((candidate) => profiles[candidate] && typeof profiles[candidate] === 'object') || key;
    existing = profiles[sourceKey] && typeof profiles[sourceKey] === 'object' ? profiles[sourceKey] : {};
  }
  const groupIds = new Set(Array.isArray(existing.groups) ? existing.groups : ['lobby']);
  groupIds.add('lobby');
  const profile = {
    key,
    publicId: existing.publicId || crypto.createHash('sha256').update(key).digest('hex').slice(0, 24),
    identityType: mac ? 'mac' : deviceId ? 'device' : 'ip',
    mac,
    ip,
    alias: cleanText(existing.alias, 40),
    color: /^#[0-9a-f]{6}$/i.test(existing.color || '') ? existing.color : colorForIdentity(key),
    avatarSeed: /^[a-f0-9]{8,64}$/i.test(existing.avatarSeed || '') ? existing.avatarSeed : randomSeed(),
    avatarUrl: validAvatarUrl(existing.avatarUrl),
    groups: [...groupIds].filter((id) => groups.some((group) => group.id === id)),
    longMessageAsMarkdown: existing.longMessageAsMarkdown !== false,
    createdAt: existing.createdAt || new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
  const changed = JSON.stringify(existing) !== JSON.stringify(profile);
  profiles[key] = profile;
  if (sourceKey !== key) delete profiles[sourceKey];
  if (changed) saveProfiles();
  return profile;
}
function publicProfile(profile) {
  return { profileId: profile.publicId, ip: profile.ip, name: profile.alias || profile.ip, alias: profile.alias, username: profile.username || '', color: profile.color, avatarSeed: profile.avatarSeed, avatarUrl: profile.avatarUrl || '', identityType: profile.identityType || 'device' };
}
function normalizeAccountName(value) { return cleanText(value, 32).toLocaleLowerCase(); }
function validAccountName(value) { return /^[\p{L}\p{N}_-]{3,32}$/u.test(String(value || '')); }
function publicAccount(account) {
  return { accountId: account.id, publicId: account.publicId, username: account.username, name: account.alias || account.username, alias: account.alias, color: account.color, avatarSeed: account.avatarSeed, avatarUrl: account.avatarUrl || '' };
}
function findAccountByUsername(username) {
  const usernameKey = normalizeAccountName(username);
  return Object.values(accounts).find((account) => account && account.usernameKey === usernameKey) || null;
}
function accountProfile(account, ip) {
  const groupIds = new Set(Array.isArray(account.groups) ? account.groups : ['lobby']);
  groupIds.add('lobby');
  return {
    key: `account:${account.id}`,
    publicId: account.publicId,
    identityType: 'account',
    accountId: account.id,
    username: account.username,
    ip,
    alias: account.alias || account.username,
    color: account.color,
    avatarSeed: account.avatarSeed,
    avatarUrl: validAvatarUrl(account.avatarUrl),
    groups: [...groupIds].filter((id) => groups.some((group) => group.id === id)),
    longMessageAsMarkdown: account.longMessageAsMarkdown !== false,
    createdAt: account.createdAt,
    updatedAt: account.updatedAt,
  };
}

function isPrivateGroup(group) { return !!group && group.visibility === 'private'; }
function groupOwnerForClient(group, client) {
  if (!group || !client) return false;
  if (isPrivateGroup(group)) return !!client.account && group.createdByAccountId === client.account.id;
  if (client.account && group.createdByAccountId) return group.createdByAccountId === client.account.id;
  return !!client.profile && group.createdBy === client.profile.publicId;
}
function groupForId(groupId) { return groups.find((group) => group.id === groupId) || null; }
function groupVisibleToClient(group, client) {
  if (!group || !client) return false;
  return !isPrivateGroup(group) || groupOwnerForClient(group, client);
}
function groupJoinedByClient(groupId, client) { return !!client && client.groups.has(groupId); }
function groupReadableByClient(groupId, client) {
  const group = groupForId(groupId);
  return groupVisibleToClient(group, client) && groupJoinedByClient(groupId, client);
}
function visibleGroupsForClient(client) {
  return groups.filter((group) => groupVisibleToClient(group, client));
}
function publicGroup(group, client) {
  return {
    id: group.id,
    name: group.name,
    createdAt: group.createdAt,
    createdBy: group.createdBy,
    visibility: group.visibility,
    isPrivate: isPrivateGroup(group),
    isOwner: groupOwnerForClient(group, client),
  };
}
function longTextNeedsMarkdown(text) {
  const value = String(text || '');
  return value.length > LONG_TEXT_CHAR_LIMIT || value.split(/\r?\n/).length > LONG_TEXT_LINE_LIMIT;
}
function accountAgentGroupIds(account, includePrivate = true) {
  if (!account) return [];
  const joinedIds = new Set(Array.isArray(account.groups) ? account.groups : []);
  return [...new Set(Array.isArray(account.agentGroupIds) ? account.agentGroupIds : [])].filter((id) => {
    const group = groupForId(id);
    return joinedIds.has(id) && group && (!isPrivateGroup(group) || includePrivate && group.createdByAccountId === account.id);
  });
}
function agentGroupOptions(account, includePrivate = true) {
  if (!account) return [];
  const selected = new Set(accountAgentGroupIds(account, includePrivate));
  return (Array.isArray(account.groups) ? account.groups : []).map((id) => groupForId(id)).filter((group) => group && (!isPrivateGroup(group) || includePrivate && group.createdByAccountId === account.id)).map((group) => ({
    ...publicGroup(group, { account, profile: accountProfile(account, '') }),
    selected: selected.has(group.id),
    ownCreated: group.createdByAccountId ? group.createdByAccountId === account.id : group.createdBy === account.publicId,
  }));
}
function publicPreferences(client) {
  return { longMessageAsMarkdown: client && client.account ? client.account.longMessageAsMarkdown !== false : client && client.profile ? client.profile.longMessageAsMarkdown !== false : true };
}
function systemSender() {
  return { profileId: 'system', publicId: 'system', identityType: 'system', name: '邻聊助手', alias: '邻聊助手', username: '', color: '#2f6e59', avatarSeed: '2f6e5900', avatarUrl: '' };
}
function agentPromptText() {
  return `${deviceAccess ? '外网 MCP 同样需要设备登记：请在已登录账号的用户打开 1 分钟接入窗口后初始化连接，保存服务返回的设备 Cookie，并在后续每次请求中携带。更换客户端或清空 Cookie 后需要重新登记。\n\n' : ''}请帮我接入邻聊 MCP。\n\n请使用我当前的邻聊账号完成绑定，并读取我在“Agent 读取范围”中选中的群组。\n\n如果你不在邻聊服务器所在的局域网内，请使用公网 MCP 地址：${PUBLIC_MCP_URL}\n\n默认先读取每个群组最新的 20 条文字消息。只有在当前内容不足时，再按关键词或时间范围继续读取历史消息。\n\n目前只读取文字内容，不读取录音、图片和普通文件。`;
}
for (const account of Object.values(accounts)) {
  if (!account || typeof account !== 'object' || !account.id || !account.usernameKey) continue;
  account.groups = [...new Set([...(Array.isArray(account.groups) ? account.groups : []), 'lobby'])].filter((id) => groups.some((group) => group.id === id));
  account.agentGroupIds = [...new Set(Array.isArray(account.agentGroupIds) ? account.agentGroupIds : [])].filter((id) => account.groups.includes(id) && groups.some((group) => group.id === id));
  account.longMessageAsMarkdown = account.longMessageAsMarkdown !== false;
  account.mcpTokenHash = typeof account.mcpTokenHash === 'string' ? account.mcpTokenHash : '';
  account.alias = cleanText(account.alias || account.username, 40) || account.username;
  account.color = /^#[0-9a-f]{6}$/i.test(account.color || '') ? account.color : colorForIdentity(`account:${account.id}`);
  account.avatarSeed = /^[a-f0-9]{8,64}$/i.test(account.avatarSeed || '') ? account.avatarSeed : randomSeed();
  account.avatarUrl = validAvatarUrl(account.avatarUrl);
}
saveAccounts();
function ensureAuthSessionKey() {
  try {
    const existing = fs.readFileSync(AUTH_KEY_FILE, 'utf8').trim();
    if (existing) return existing;
  } catch (_) {}
  const key = crypto.randomBytes(32).toString('hex');
  fs.writeFileSync(AUTH_KEY_FILE, `${key}\n`, { mode: 0o600 });
  return key;
}
const authSessionKey = ensureAuthSessionKey();
function signAuthSession(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = crypto.createHmac('sha256', authSessionKey).update(body).digest('base64url');
  return `${body}.${signature}`;
}
function verifyAuthSession(token) {
  const [body, signature] = String(token || '').split('.');
  if (!body || !signature) return null;
  const expected = crypto.createHmac('sha256', authSessionKey).update(body).digest('base64url');
  if (!safeEqual(signature, expected)) return null;
  try {
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString());
    const session = authSessions[payload.sessionId];
    const account = accounts[payload.accountId];
    if (payload.role !== 'account' || !session || !account || account.disabled || session.accountId !== account.id) return null;
    if (Number(session.expiresAt) <= Date.now()) return null;
    return { session, account };
  } catch (_) { return null; }
}
function authContext(req) { return verifyAuthSession(parseCookies(req)[AUTH_COOKIE]); }
function setAuthCookie(res, token) {
  res.setHeader('Set-Cookie', `${AUTH_COOKIE}=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${AUTH_SESSION_TTL_SECONDS}${TLS_ENABLED ? '; Secure' : ''}`);
}
function clearAuthCookie(res) {
  res.setHeader('Set-Cookie', `${AUTH_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${TLS_ENABLED ? '; Secure' : ''}`);
}
function createAuthSession(account, deviceId) {
  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  authSessions[id] = { id, accountId: account.id, deviceId: cleanText(deviceId, 80), createdAt: now, lastSeenAt: now, expiresAt: Date.now() + AUTH_SESSION_TTL_SECONDS * 1000 };
  saveAuthSessions();
  return signAuthSession({ role: 'account', sessionId: id, accountId: account.id, secure: TLS_ENABLED });
}
for (const [id, session] of Object.entries(authSessions)) {
  if (!session || Number(session.expiresAt) <= Date.now() || !accounts[session.accountId]) delete authSessions[id];
}
saveAuthSessions();
const authFailures = new Map();
function authAttemptAllowed(ip) {
  const now = Date.now();
  const entry = authFailures.get(ip);
  if (!entry || entry.resetAt <= now) { authFailures.set(ip, { count: 0, resetAt: now + 15 * 60 * 1000 }); return true; }
  return entry.count < 15;
}
function recordAuthFailure(ip) {
  const entry = authFailures.get(ip) || { count: 0, resetAt: Date.now() + 15 * 60 * 1000 };
  entry.count += 1; authFailures.set(ip, entry);
}
function clearAuthFailures(ip) { authFailures.delete(ip); }
function findProfileReference(body = {}) {
  const key = cleanText(body.key, 180);
  if (key && profiles[key]) return profiles[key];
  const ip = cleanText(body.ip, 100);
  return Object.values(profiles).find((profile) => profile.ip === ip) || null;
}
for (const profile of Object.values(profiles)) {
  if (profile && profile.ip && !profile.key) ensureProfile(profile.ip, '', false);
}
function safeEqual(a, b) {
  const left = Buffer.from(String(a)); const right = Buffer.from(String(b));
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}
function ensureAdminCredentials() {
  let sessionKey;
  try { sessionKey = fs.readFileSync(ADMIN_KEY_FILE, 'utf8').trim(); } catch (_) {}
  if (!sessionKey) {
    sessionKey = crypto.randomBytes(32).toString('hex');
    fs.writeFileSync(ADMIN_KEY_FILE, `${sessionKey}\n`, { mode: 0o600 });
  }
  const envPassword = process.env.ADMIN_PASSWORD;
  if (envPassword) return { sessionKey, verify: (password) => safeEqual(String(password || ''), envPassword), source: 'environment' };
  let credentials = readJson(ADMIN_CREDENTIALS_FILE, null);
  if (!credentials || !credentials.salt || !credentials.hash) {
    const initialPassword = `lan-${crypto.randomBytes(9).toString('base64url')}`;
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.scryptSync(initialPassword, salt, 32).toString('hex');
    credentials = { salt, hash, createdAt: new Date().toISOString() };
    writeJson(ADMIN_CREDENTIALS_FILE, credentials);
    fs.writeFileSync(ADMIN_PASSWORD_FILE, `${initialPassword}\n`, { mode: 0o600 });
  }
  return {
    sessionKey,
    verify: (password) => {
      const hash = crypto.scryptSync(String(password || ''), credentials.salt, 32).toString('hex');
      return safeEqual(hash, credentials.hash);
    },
    source: ADMIN_PASSWORD_FILE,
  };
}
const adminCredentials = ensureAdminCredentials();
function parseCookies(req) {
  return Object.fromEntries(String(req.headers.cookie || '').split(';').map((part) => part.trim().split(/=(.*)/s).slice(0, 2)).filter(([key]) => key));
}
function signSession(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = crypto.createHmac('sha256', adminCredentials.sessionKey).update(body).digest('base64url');
  return `${body}.${signature}`;
}
function verifySession(token) {
  const [body, signature] = String(token || '').split('.');
  if (!body || !signature) return false;
  const expected = crypto.createHmac('sha256', adminCredentials.sessionKey).update(body).digest('base64url');
  if (!safeEqual(signature, expected)) return false;
  try {
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString());
    return payload.role === 'admin' && payload.secure === TLS_ENABLED && Number(payload.expiresAt) > Date.now();
  } catch (_) { return false; }
}
function requireAdmin(req, res, next) {
  if (!verifySession(parseCookies(req)[ADMIN_COOKIE])) return res.status(401).json({ error: '请先登录管理员后台。' });
  next();
}
function requireAccount(req, res, next) {
  const context = authContext(req);
  if (!context) return res.status(401).json({ error: '请先登录注册账号。' });
  req.accountContext = context;
  next();
}
function issueMcpToken(account) {
  const token = `nchat_${crypto.randomBytes(30).toString('base64url')}`;
  account.mcpTokenHash = crypto.createHash('sha256').update(token).digest('hex');
  account.mcpTokenCreatedAt = new Date().toISOString();
  account.updatedAt = new Date().toISOString();
  saveAccounts();
  return token;
}
function accountFromMcpRequest(req) {
  const authorization = cleanText(req.headers.authorization, 300);
  const match = authorization.match(/^Bearer\s+(.+)$/i);
  if (!match) return null;
  const hash = crypto.createHash('sha256').update(match[1].trim()).digest('hex');
  return Object.values(accounts).find((account) => account && account.mcpTokenHash && safeEqual(account.mcpTokenHash, hash) && !account.disabled) || null;
}
function mcpJsonRpc(res, id, result, error) {
  if (error) return res.status(200).json({ jsonrpc: '2.0', id: id ?? null, error });
  return res.status(200).json({ jsonrpc: '2.0', id: id ?? null, result });
}
function mcpTextResult(value, isError = false) {
  return { content: [{ type: 'text', text: typeof value === 'string' ? value : JSON.stringify(value, null, 2) }], isError };
}
function mcpSelectedGroups(account) {
  const ids = new Set(accountAgentGroupIds(account, true));
  return [...ids].map((id) => groupForId(id)).filter(Boolean);
}
function mcpMessageSummary(message, full = false) {
  const isText = message.kind === 'text' || message.kind === 'long-text' || message.kind === 'system';
  const text = isText ? String(message.text || '') : '';
  const item = { id: message.id, groupId: message.groupId, kind: message.kind, sentAt: message.sentAt, sender: message.sender, hasText: !!text };
  if (full || message.kind !== 'long-text') item.text = text;
  else { item.textPreview = text.slice(0, 800); item.hasFullText = true; }
  if (message.kind === 'long-text') item.markdownFile = { name: message.file && message.file.name, manualDownload: true };
  return item;
}
function mcpScopeAllows(account, groupId) { return accountAgentGroupIds(account, true).includes(groupId); }
function mcpGroupMessages(account, groupIds) {
  const allowed = new Set(accountAgentGroupIds(account, true));
  const selected = (Array.isArray(groupIds) && groupIds.length ? groupIds : [...allowed]).filter((id) => allowed.has(id));
  return messageHistory.filter((message) => selected.includes(message.groupId) && (message.kind === 'text' || message.kind === 'long-text' || message.kind === 'system'));
}
function mcpTools() {
  return [
    { name: 'get_my_agent_scope', description: '获取当前邻聊账号已经授权给 Agent 的群组。', inputSchema: { type: 'object', properties: {} } },
    { name: 'list_recent_neighbor_messages', description: '按最新优先读取已授权群组的文字消息。长消息默认返回摘要，需要时用 get_neighbor_message 获取全文。', inputSchema: { type: 'object', properties: { groupIds: { type: 'array', items: { type: 'string' } }, limit: { type: 'integer', minimum: 1, maximum: 100 } } } },
    { name: 'search_neighbor_messages', description: '在已授权群组的文字消息中按关键词搜索。', inputSchema: { type: 'object', required: ['query'], properties: { query: { type: 'string' }, groupIds: { type: 'array', items: { type: 'string' } }, limit: { type: 'integer', minimum: 1, maximum: 50 } } } },
    { name: 'get_neighbor_message', description: '获取一条已授权文字消息的完整内容。', inputSchema: { type: 'object', required: ['messageId'], properties: { messageId: { type: 'string' } } } },
  ];
}
function mcpCall(account, name, args = {}) {
  if (name === 'get_my_agent_scope') {
    return mcpTextResult({ publicMcpUrl: PUBLIC_MCP_URL, groups: mcpSelectedGroups(account).map((group) => ({ id: group.id, name: group.name, isPrivate: isPrivateGroup(group), createdAt: group.createdAt })) });
  }
  if (name === 'list_recent_neighbor_messages') {
    const limit = Math.max(1, Math.min(100, Number(args.limit) || 20));
    const items = mcpGroupMessages(account, args.groupIds).slice(-limit).reverse().map((message) => mcpMessageSummary(message));
    return mcpTextResult({ messages: items, hasMore: false, softGuidance: '默认先读取最新消息；如需更多上下文，请使用搜索或按消息 ID 获取全文。' });
  }
  if (name === 'search_neighbor_messages') {
    const query = cleanText(args.query, 200).toLocaleLowerCase();
    if (!query) return mcpTextResult('query 不能为空。', true);
    const limit = Math.max(1, Math.min(50, Number(args.limit) || 20));
    const items = mcpGroupMessages(account, args.groupIds).filter((message) => String(message.text || '').toLocaleLowerCase().includes(query)).slice(-limit).reverse().map((message) => mcpMessageSummary(message));
    return mcpTextResult({ messages: items, hasMore: false });
  }
  if (name === 'get_neighbor_message') {
    const message = messageHistory.find((item) => item.id === cleanText(args.messageId, 100));
    if (!message || !mcpScopeAllows(account, message.groupId) || !['text', 'long-text', 'system'].includes(message.kind)) return mcpTextResult('消息不存在、未授权或不是文字消息。', true);
    return mcpTextResult(mcpMessageSummary(message, true));
  }
  return mcpTextResult(`未知工具：${name}`, true);
}
function accountForAgentRequest(req) {
  const context = authContext(req);
  if (context) return { account: context.account, profile: accountProfile(context.account, requestIp(req)) };
  const deviceId = requestedDeviceId(req) || parseCookies(req).lan_chat_device || '';
  const profile = ensureProfile(requestIp(req), deviceId);
  return { profile };
}
function requestCanReadGroup(req, groupId) {
  const viewer = accountForAgentRequest(req);
  if (viewer.account) return viewer.account.groups.includes(groupId) && groupVisibleToClient(groupForId(groupId), { account: viewer.account, profile: accountProfile(viewer.account, requestIp(req)) });
  return !!viewer.profile && viewer.profile.groups.includes(groupId) && groupVisibleToClient(groupForId(groupId), { profile: viewer.profile });
}
function messageUploadFilename(message) {
  return message && message.file ? storedFilenameFromUrl(message.file.url) : '';
}
function referencedUploadFilenames(excludedGroupId = '') {
  return new Set(messageHistory.map((message) => message.groupId === excludedGroupId ? '' : messageUploadFilename(message)).filter(Boolean));
}
function deleteMessageArtifacts(removedMessages, keptFilenames) {
  for (const message of removedMessages) {
    removeGeneratedMarkdown(message);
    const filename = messageUploadFilename(message);
    if (filename && !keptFilenames.has(filename)) {
      try { fs.rmSync(path.join(UPLOAD_DIR, filename), { force: true }); } catch (_) {}
    }
  }
}
function deleteGroupAndData(groupId, deletedBy) {
  const group = groupForId(groupId);
  if (!group) return { status: 404, error: '群组不存在。' };
  if (group.id === 'lobby') return { status: 400, error: '公共大厅不能删除。' };

  const keptFilenames = referencedUploadFilenames(groupId);
  const removedMessages = messageHistory.filter((message) => message.groupId === groupId);
  groups = groups.filter((item) => item.id !== groupId);
  messageHistory = messageHistory.filter((message) => message.groupId !== groupId);

  let changedProfiles = false;
  for (const profile of Object.values(profiles)) {
    if (!profile || !Array.isArray(profile.groups) || !profile.groups.includes(groupId)) continue;
    profile.groups = profile.groups.filter((id) => id !== groupId);
    if (!profile.groups.includes('lobby')) profile.groups.unshift('lobby');
    profile.updatedAt = new Date().toISOString();
    changedProfiles = true;
  }

  let changedAccounts = false;
  for (const account of Object.values(accounts)) {
    if (!account || typeof account !== 'object') continue;
    const nextGroups = Array.isArray(account.groups) ? account.groups.filter((id) => id !== groupId) : ['lobby'];
    const nextAgentGroupIds = Array.isArray(account.agentGroupIds) ? account.agentGroupIds.filter((id) => id !== groupId) : [];
    if (JSON.stringify(nextGroups) !== JSON.stringify(account.groups) || JSON.stringify(nextAgentGroupIds) !== JSON.stringify(account.agentGroupIds)) {
      account.groups = nextGroups.includes('lobby') ? nextGroups : ['lobby', ...nextGroups];
      account.agentGroupIds = nextAgentGroupIds;
      account.updatedAt = new Date().toISOString();
      changedAccounts = true;
    }
  }

  saveGroups(); saveMessages();
  if (changedProfiles) saveProfiles();
  if (changedAccounts) saveAccounts();
  deleteMessageArtifacts(removedMessages, keptFilenames);

  for (const client of clients.values()) {
    if (client.groups.has(groupId)) client.groups.delete(groupId);
    if (!client.groups.has('lobby')) client.groups.add('lobby');
    if (client.account) {
      client.account = accounts[client.account.id] || client.account;
      client.profile = accountProfile(client.account, client.ip);
      client.groups = new Set(client.profile.groups);
    }
  }

  broadcast({ type: 'group-deleted', groupId, groupName: group.name, deletedBy, removedMessages: removedMessages.length });
  broadcastState();
  return { ok: true, group, removedMessages: removedMessages.length };
}

const storage = multer.diskStorage({
  destination: (_, __, callback) => callback(null, UPLOAD_DIR),
  filename: (_, file, callback) => {
    const extension = path.extname(safeFilename(file.originalname)).slice(0, 20);
    callback(null, `${Date.now()}-${crypto.randomBytes(8).toString('hex')}${extension}`);
  },
});
const uploadOptions = { storage, limits: { files: 1 } };
if (MAX_UPLOAD_BYTES > 0) uploadOptions.limits.fileSize = MAX_UPLOAD_BYTES;
const upload = multer(uploadOptions);
const avatarUpload = multer({
  storage,
  limits: { files: 1, fileSize: 8 * 1024 * 1024 },
  fileFilter: (_, file, callback) => callback(null, /^image\/(?:png|jpe?g|webp|gif)$/i.test(file.mimetype || '')),
});

const app = express();
app.disable('x-powered-by');
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'same-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(self), geolocation=()');
  next();
});
app.use((req, res, next) => {
  if (!deviceAccess) return next();
  if (!deviceAccess.allowed(req)) return deviceAccess.deny(req, res);
  if (!['GET', 'HEAD', 'OPTIONS'].includes(req.method) && !deviceAccess.sameOrigin(req)) return res.status(403).json({ error: '不允许跨站修改邻聊状态。', code: 'CROSS_ORIGIN_DENIED' });
  if (deviceAccess.known(req)) rememberDevice(req, res);
  next();
});
app.use((req, res, next) => {
  if (!TLS_ENABLED || req.socket.encrypted) return next();
  if (req.path === '/lan-chat-ca.crt' || req.path === '/api/health') return next();
  // LAN chat can use HTTP without enrolling every device's certificate store.
  // Keep administrator credentials on HTTPS when TLS is configured.
  const adminRequest = /^\/(?:admin(?:\.html)?|api\/admin)(?:\/|$)/.test(req.path);
  if (!REQUIRE_HTTPS && !adminRequest) return next();
  if (req.path === '/' && req.method === 'GET') return res.sendFile(path.join(__dirname, 'public', 'secure-setup.html'));
  const host = cleanText(req.headers.host, 240) || `127.0.0.1:${PORT}`;
  return res.redirect(307, `https://${host}${req.originalUrl}`);
});
app.use(express.json({ limit: '1mb' }));
app.get('/api/access/window', requireAccount, (req, res) => {
  if (!deviceAccess) return res.status(404).json({ error: '设备登记功能未启用。' });
  res.setHeader('Cache-Control', 'no-store');
  res.json(deviceAccess.status());
});
app.post('/api/access/window', requireAccount, (req, res) => {
  if (!deviceAccess) return res.status(404).json({ error: '设备登记功能未启用。' });
  if (!deviceAccess.sameOrigin(req)) return res.status(403).json({ error: '不允许跨站开启接入窗口。' });
  res.setHeader('Cache-Control', 'no-store');
  res.json(deviceAccess.openWindow(req.accountContext.account.id));
});
app.get('/api/auth/state', (req, res) => {
  const context = authContext(req);
  if (context && deviceAccess && deviceAccess.isLan(req)) rememberDevice(req, res, { accountId: context.account.id, kind: 'account' });
  res.json({ authenticated: !!context, account: context ? publicAccount(context.account) : null, deviceAccessEnabled: !!deviceAccess });
});
app.post('/api/auth/register', (req, res) => {
  const ip = requestIp(req);
  if (!authAttemptAllowed(ip)) return res.status(429).json({ error: '登录或注册尝试过于频繁，请 15 分钟后再试。' });
  const username = cleanText(req.body && req.body.username, 32);
  const password = String((req.body && req.body.password) || '');
  const passwordConfirmation = String((req.body && req.body.passwordConfirmation) || '');
  if (!validAccountName(username)) return res.status(400).json({ error: '账号名需为 3–32 个中文、字母、数字、下划线或短横线。' });
  if (password.length < 6 || password.length > 128) return res.status(400).json({ error: '密码长度需为 6–128 位。' });
  if (password !== passwordConfirmation) return res.status(400).json({ error: '两次输入的密码不一致。' });
  if (findAccountByUsername(username)) return res.status(409).json({ error: '这个账号名已经被注册了。' });
  const id = crypto.randomUUID();
  const salt = crypto.randomBytes(16).toString('hex');
  const account = {
    id,
    publicId: crypto.createHash('sha256').update(`account:${id}`).digest('hex').slice(0, 24),
    username,
    usernameKey: normalizeAccountName(username),
    alias: username,
    color: colorForIdentity(`account:${id}`),
    avatarSeed: randomSeed(),
    avatarUrl: '',
    groups: ['lobby'],
    agentGroupIds: [],
    longMessageAsMarkdown: true,
    mcpTokenHash: '',
    passwordSalt: salt,
    passwordHash: crypto.scryptSync(password, salt, 32).toString('hex'),
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    disabled: false,
  };
  accounts[id] = account; saveAccounts(); clearAuthFailures(ip);
  setAuthCookie(res, createAuthSession(account, requestedDeviceId(req)));
  rememberDevice(req, res, { accountId: account.id, kind: 'account' });
  res.status(201).json({ ok: true, account: publicAccount(account) });
});
app.post('/api/auth/login', (req, res) => {
  const ip = requestIp(req);
  if (!authAttemptAllowed(ip)) return res.status(429).json({ error: '登录或注册尝试过于频繁，请 15 分钟后再试。' });
  const username = cleanText(req.body && req.body.username, 32);
  const password = String((req.body && req.body.password) || '');
  const account = findAccountByUsername(username);
  let valid = !!account && !account.disabled;
  if (valid) {
    const hash = crypto.scryptSync(password, account.passwordSalt, 32).toString('hex');
    valid = safeEqual(hash, account.passwordHash);
  }
  if (!valid) { recordAuthFailure(ip); return res.status(401).json({ error: '账号名或密码不正确。' }); }
  clearAuthFailures(ip);
  setAuthCookie(res, createAuthSession(account, requestedDeviceId(req)));
  rememberDevice(req, res, { accountId: account.id, kind: 'account' });
  res.json({ ok: true, account: publicAccount(account) });
});
app.post('/api/auth/anonymous', (req, res) => {
  clearAuthCookie(res);
  rememberDevice(req, res, { kind: 'anonymous' });
  res.json({ ok: true, anonymous: true });
});
app.post('/api/auth/logout', (req, res) => {
  const context = authContext(req);
  if (context) { delete authSessions[context.session.id]; saveAuthSessions(); }
  clearAuthCookie(res); res.json({ ok: true });
});
app.get('/api/me/agent-scope', requireAccount, (req, res) => {
  const account = req.accountContext.account;
  res.json({ groups: agentGroupOptions(account, true), selectedGroupIds: accountAgentGroupIds(account, true), publicMcpUrl: PUBLIC_MCP_URL, prompt: agentPromptText() });
});
app.put('/api/me/agent-scope', requireAccount, (req, res) => {
  const account = req.accountContext.account;
  const requested = Array.isArray(req.body && req.body.groupIds) ? [...new Set(req.body.groupIds.map((id) => cleanText(id, 80)).filter(Boolean))] : [];
  const allowed = new Set(agentGroupOptions(account, true).map((item) => item.id));
  if (requested.some((id) => !allowed.has(id))) return res.status(400).json({ error: '只能授权自己已经加入的群组。' });
  const previous = new Set(accountAgentGroupIds(account, true));
  account.agentGroupIds = requested;
  account.updatedAt = new Date().toISOString(); saveAccounts();
  const newlyAdded = requested.filter((id) => !previous.has(id));
  newlyAdded.forEach((groupId) => recordAgentPromptMessage(account, groupId));
  broadcastState();
  res.json({ ok: true, groups: agentGroupOptions(account, true), selectedGroupIds: accountAgentGroupIds(account, true) });
});
app.get('/api/mcp/prompt', requireAccount, (req, res) => {
  const account = req.accountContext.account;
  const token = issueMcpToken(account);
  const prompt = `${agentPromptText()}\n\nMCP 接入令牌（请只提供给你自己的 Agent，不要发到群里）：\n${token}`;
  res.json({ prompt, publicMcpUrl: PUBLIC_MCP_URL });
});
app.get('/.well-known/neighbor-chat-mcp', (_, res) => res.json({ name: '邻聊 MCP', url: PUBLIC_MCP_URL, transport: 'streamable-http', authentication: 'bearer', textOnly: true }));
app.post('/mcp', (req, res) => {
  const account = accountFromMcpRequest(req);
  if (!account) return res.status(401).json({ error: 'MCP 需要注册账号的授权令牌。' });
  rememberDevice(req, res, { accountId: account.id, kind: 'mcp' });
  const body = req.body && typeof req.body === 'object' ? req.body : {};
  const id = body.id ?? null;
  if (body.method === 'initialize') return mcpJsonRpc(res, id, { protocolVersion: body.params && body.params.protocolVersion || '2024-11-05', capabilities: { tools: {} }, serverInfo: { name: 'neighbor-chat', version: APP_VERSION } });
  if (body.method === 'notifications/initialized') return res.status(202).end();
  if (body.method === 'ping') return mcpJsonRpc(res, id, {});
  if (body.method === 'tools/list') return mcpJsonRpc(res, id, { tools: mcpTools() });
  if (body.method === 'tools/call') {
    const name = cleanText(body.params && body.params.name, 100);
    return mcpJsonRpc(res, id, mcpCall(account, name, body.params && body.params.arguments || {}));
  }
  return mcpJsonRpc(res, id, null, { code: -32601, message: `不支持的方法：${body.method || ''}` });
});
app.get('/api/health', (_, res) => res.json({ ok: true, version: APP_VERSION, uptime: Math.floor(process.uptime()) }));
app.get('/api/config', (_, res) => res.json({
  maxUploadBytes: MAX_UPLOAD_BYTES || null,
  uploadLimitLabel: MAX_UPLOAD_BYTES ? `${MAX_UPLOAD_BYTES} bytes` : 'unlimited',
  features: { voice: true, retract: true, groups: true, profiles: true, customAvatar: true, macIdentity: true, ipv6: true, accountAuth: true, multiDeviceAccounts: true, privateGroups: true, agentScope: true, mcp: true, longTextMarkdown: true },
  futureAccess: { mode: 'lan-and-ipv6-ddns', publicMcpUrl: PUBLIC_MCP_URL, publicAuthReady: true },
  httpsPort: TLS_ENABLED ? PORT : null,
  unifiedSecurePort: TLS_ENABLED,
  httpChatAllowed: !TLS_ENABLED || !REQUIRE_HTTPS,
  caCertificateUrl: TLS_ENABLED && CA_CERT_PATH ? '/lan-chat-ca.crt' : null,
}));
app.post('/api/upload', (req, res) => {
  upload.single('file')(req, res, (error) => {
    if (error) {
      const message = error.code === 'LIMIT_FILE_SIZE' ? '文件超过了服务器设定的上传限制。' : '上传失败，请重试。';
      return res.status(400).json({ error: message });
    }
    if (!req.file) return res.status(400).json({ error: '请选择文件。' });
    res.json({
      url: `/uploads/${encodeURIComponent(req.file.filename)}`,
      name: safeFilename(repairMultipartFilename(req.file.originalname)),
      mime: safeMime(req.file.mimetype),
      size: req.file.size,
    });
  });
});
app.post('/api/avatar', (req, res) => {
  avatarUpload.single('file')(req, res, (error) => {
    if (error) return res.status(400).json({ error: error.code === 'LIMIT_FILE_SIZE' ? '头像文件不能超过 8MB。' : '头像上传失败。' });
    if (!req.file) return res.status(400).json({ error: '请选择 PNG、JPG、WebP 或 GIF 图片。' });
    res.json({ url: `/uploads/${encodeURIComponent(req.file.filename)}` });
  });
});

app.post('/api/admin/login', (req, res) => {
  if (!adminCredentials.verify(req.body && req.body.password)) return res.status(401).json({ error: '管理员密码不正确。' });
  const token = signSession({ role: 'admin', secure: TLS_ENABLED, expiresAt: Date.now() + SESSION_TTL_SECONDS * 1000 });
  res.setHeader('Set-Cookie', `${ADMIN_COOKIE}=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${SESSION_TTL_SECONDS}${TLS_ENABLED ? '; Secure' : ''}`);
  rememberDevice(req, res, { kind: 'admin' });
  res.json({ ok: true });
});
app.post('/api/admin/logout', (_, res) => {
  res.setHeader('Set-Cookie', `${ADMIN_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${TLS_ENABLED ? '; Secure' : ''}`);
  res.json({ ok: true });
});
app.get('/api/admin/state', requireAdmin, (_, res) => {
  const onlineByKey = {};
  const publicGroupIds = new Set(groups.filter((group) => !isPrivateGroup(group)).map((group) => group.id));
  for (const client of clients.values()) onlineByKey[client.profile.key] = (onlineByKey[client.profile.key] || 0) + 1;
  res.json({
    profiles: Object.values(profiles).map((profile) => ({ ...publicProfile(profile), key: profile.key, mac: profile.mac || '', identityType: profile.identityType, groups: profile.groups, online: onlineByKey[profile.key] || 0 })),
    accounts: Object.values(accounts).map((account) => ({ ...publicAccount(account), groups: account.groups.filter((id) => publicGroupIds.has(id)), agentGroupIds: accountAgentGroupIds(account, false), disabled: !!account.disabled, online: [...clients.values()].filter((client) => client.account && client.account.id === account.id).length })),
    groups: groups.filter((group) => !isPrivateGroup(group)),
    stats: { onlineConnections: clients.size, knownDevices: Object.keys(profiles).length, knownAccounts: Object.keys(accounts).length, knownIps: Object.keys(profiles).length, messages: messageHistory.length, files: countFiles() },
  });
});
app.get('/api/admin/accounts/:accountId/agent-scope', requireAdmin, (req, res) => {
  const account = accounts[cleanText(req.params.accountId, 80)];
  if (!account) return res.status(404).json({ error: '账号不存在。' });
  res.json({ account: publicAccount(account), groups: agentGroupOptions(account, false), selectedGroupIds: accountAgentGroupIds(account, false) });
});
app.put('/api/admin/accounts/:accountId/agent-scope', requireAdmin, (req, res) => {
  const account = accounts[cleanText(req.params.accountId, 80)];
  if (!account) return res.status(404).json({ error: '账号不存在。' });
  const requested = Array.isArray(req.body && req.body.groupIds) ? [...new Set(req.body.groupIds.map((id) => cleanText(id, 80)).filter(Boolean))] : [];
  const allowed = new Set(agentGroupOptions(account, false).map((item) => item.id));
  if (requested.some((id) => !allowed.has(id))) return res.status(400).json({ error: '管理员只能管理该账号已加入的普通群组。' });
  const previous = new Set(accountAgentGroupIds(account, false));
  account.agentGroupIds = [...new Set([...(accountAgentGroupIds(account, true).filter((id) => !allowed.has(id))), ...requested])];
  account.updatedAt = new Date().toISOString(); saveAccounts();
  requested.filter((id) => !previous.has(id)).forEach((groupId) => recordAgentPromptMessage(account, groupId));
  broadcastState();
  res.json({ ok: true, groups: agentGroupOptions(account, false), selectedGroupIds: accountAgentGroupIds(account, false) });
});
app.put('/api/admin/profile', requireAdmin, (req, res) => {
  const profile = findProfileReference(req.body);
  if (!profile) return res.status(404).json({ error: '没有找到这个设备档案。' });
  profile.alias = cleanText(req.body.alias, 40);
  if (/^#[0-9a-f]{6}$/i.test(req.body.color || '')) profile.color = req.body.color.toLowerCase();
  if (/^[a-f0-9]{8,64}$/i.test(req.body.avatarSeed || '')) profile.avatarSeed = req.body.avatarSeed.toLowerCase();
  profile.avatarUrl = validAvatarUrl(req.body.avatarUrl);
  profile.updatedAt = new Date().toISOString();
  saveProfiles(); refreshConnectedProfiles(profile.key); broadcastState();
  res.json({ profile: { ...publicProfile(profile), key: profile.key, mac: profile.mac || '', identityType: profile.identityType } });
});
app.post('/api/admin/profile/randomize', requireAdmin, (req, res) => {
  const profile = findProfileReference(req.body);
  if (!profile) return res.status(404).json({ error: '没有找到这个设备档案。' });
  profile.avatarSeed = randomSeed(); profile.color = COLORS[crypto.randomInt(COLORS.length)]; profile.avatarUrl = '';
  profile.updatedAt = new Date().toISOString();
  saveProfiles(); refreshConnectedProfiles(profile.key); broadcastState();
  res.json({ profile: { ...publicProfile(profile), key: profile.key, mac: profile.mac || '', identityType: profile.identityType } });
});
app.delete('/api/admin/message/:id', requireAdmin, (req, res) => {
  const message = messageHistory.find((item) => item.id === req.params.id);
  if (!message) return res.status(404).json({ error: '消息不存在。' });
  retractMessage(message, 'admin');
  res.json({ ok: true });
});
app.delete('/api/admin/groups/:groupId', requireAdmin, (req, res) => {
  const groupId = cleanText(req.params.groupId, 80);
  const group = groupForId(groupId);
  if (group && isPrivateGroup(group)) return res.status(403).json({ error: '管理员后台不管理隐私群。' });
  const result = deleteGroupAndData(groupId, 'admin');
  if (!result.ok) return res.status(result.status || 400).json({ error: result.error || '删除群组失败。' });
  res.json(result);
});

if (CA_CERT_PATH && fs.existsSync(CA_CERT_PATH)) app.get('/lan-chat-ca.crt', (_, res) => res.download(CA_CERT_PATH, 'lan-chat-ca.crt'));

app.get('/api/message-download/:messageId', (req, res) => {
  const message = messageHistory.find((item) => item.id === cleanText(req.params.messageId, 100));
  if (!message || message.kind !== 'long-text') return res.status(404).json({ error: '长消息不存在。' });
  if (!requestCanReadGroup(req, message.groupId)) return res.status(403).json({ error: '请先加入这个群组。' });
  const filename = generatedMarkdownPath(message.id);
  if (!fs.existsSync(filename)) return res.status(404).json({ error: 'Markdown 文件不存在。' });
  return res.download(filename, message.file && message.file.name || `邻聊长消息-${message.id.slice(0, 8)}.md`, { acceptRanges: true, cacheControl: false });
});
app.get('/api/download/:filename', (req, res) => {
  const filename = storedFilenameFromUrl(`/uploads/${req.params.filename}`);
  if (!filename) return res.status(400).json({ error: '文件地址无效。' });
  const references = messageHistory.filter((message) => message.file && storedFilenameFromUrl(message.file.url) === filename);
  if (references.length && !references.some((message) => requestCanReadGroup(req, message.groupId))) return res.status(403).json({ error: '请先加入文件所在的群组。' });
  const fullPath = path.join(UPLOAD_DIR, filename);
  const downloadName = safeFilename(repairMultipartFilename(req.query.name || filename));
  res.download(fullPath, downloadName, { acceptRanges: true, cacheControl: false }, (error) => {
    if (!error) return;
    if (error.code !== 'ECONNABORTED') console.error(`Download failed for ${filename}:`, error.message);
    if (!res.headersSent) res.status(error.statusCode || 500).json({ error: error.statusCode === 404 ? '文件不存在。' : '文件下载失败。' });
  });
});
app.use('/uploads', (req, res, next) => {
  const filename = storedFilenameFromUrl(`/uploads/${req.path.replace(/^\//, '')}`);
  if (!filename) return next();
  const references = messageHistory.filter((message) => message.file && storedFilenameFromUrl(message.file.url) === filename);
  if (references.length && !references.some((message) => requestCanReadGroup(req, message.groupId))) return res.status(403).json({ error: '请先加入文件所在的群组。' });
  return next();
}, express.static(UPLOAD_DIR, { fallthrough: false, index: false, maxAge: '1h', acceptRanges: true }));
app.get('/admin', (_, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.use(express.static(path.join(__dirname, 'public')));
app.use((error, _, res, __) => { console.error(error); if (!res.headersSent) res.status(500).json({ error: '服务器发生错误。' }); });

const server = TLS_ENABLED ? httpolyglot.createServer({ tls: { cert: fs.readFileSync(TLS_CERT_PATH), key: fs.readFileSync(TLS_KEY_PATH) }, http: { requestTimeout: 0 } }, app) : http.createServer(app);
server.requestTimeout = 0;
if (server._httpServer) server._httpServer.requestTimeout = 0;
const wss = new WebSocketServer({ server, maxPayload: 2 * 1024 * 1024, ...(deviceAccess ? {
  verifyClient(info, done) {
    if (!deviceAccess.sameOrigin(info.req) || !deviceAccess.allowed(info.req)) return done(false, 403, 'Device not recognized');
    try {
      const context = authContext(info.req);
      info.req.deviceAdmissionCookie = deviceAccess.remember(info.req, { accountId: context ? context.account.id : '', kind: context ? 'account' : 'anonymous' });
      if (!info.req.deviceAdmissionCookie) return done(false, 403, 'Device not recognized');
      done(true);
    } catch (_) { done(false, 503, 'Device registration unavailable'); }
  },
} : {}) });
wss.on('headers', (headers, req) => {
  if (req.deviceAdmissionCookie) headers.push(`Set-Cookie: ${req.deviceAdmissionCookie}`);
});
const clients = new Map();

function countFiles() {
  try { return fs.readdirSync(UPLOAD_DIR, { withFileTypes: true }).filter((entry) => entry.isFile()).length; } catch (_) { return 0; }
}
function clientCanSeeClient(viewer, other) {
  if (viewer === other) return true;
  return [...viewer.groups].some((groupId) => groupReadableByClient(groupId, viewer) && other.groups.has(groupId));
}
function clientList(viewer) {
  return [...clients.values()].filter((client) => clientCanSeeClient(viewer, client)).map((client) => ({ id: client.id, ...publicProfile(client.profile), groups: [...client.groups].filter((id) => viewer.groups.has(id) && groupVisibleToClient(groupForId(id), viewer)) }));
}
function send(ws, message) { if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(message)); }
function broadcast(message, recipients = clients.keys()) {
  const serialized = JSON.stringify(message);
  for (const ws of recipients) if (ws.readyState === WebSocket.OPEN) ws.send(serialized);
}
function sendState(client) {
  const visibleGroups = visibleGroupsForClient(client);
  const visibleClients = clientList(client);
  const visibleProfiles = visibleClients.map((item) => item).filter((item, index, all) => all.findIndex((candidate) => candidate.profileId === item.profileId) === index);
  send(client.ws, { type: 'state', groups: visibleGroups.map((group) => publicGroup(group, client)), clients: visibleClients, profiles: visibleProfiles });
}
function broadcastState() { for (const client of clients.values()) sendState(client); }
function refreshConnectedProfiles(key) {
  for (const client of clients.values()) {
    if (client.profile.key !== key) continue;
    Object.assign(client.profile, profiles[key]);
    client.preferences = publicPreferences(client);
    send(client.ws, { type: 'preferences-updated', preferences: client.preferences });
  }
}
function refreshConnectedAccount(accountId) {
  const account = accounts[accountId];
  if (!account) return;
  for (const client of clients.values()) {
    if (!client.account || client.account.id !== accountId) continue;
    client.account = account;
    client.profile = accountProfile(account, client.ip);
    client.groups = new Set(client.profile.groups);
    client.preferences = publicPreferences(client);
    send(client.ws, { type: 'preferences-updated', preferences: client.preferences });
  }
}
function saveClientGroups(client) {
  if (client.account) {
    client.account.groups = [...client.groups];
    client.account.updatedAt = new Date().toISOString();
    saveAccounts(); refreshConnectedAccount(client.account.id);
  } else {
    client.profile.groups = [...client.groups];
    client.profile.updatedAt = new Date().toISOString();
    saveProfiles();
  }
}
function updateClientProfile(client, data) {
  const alias = cleanText(data.alias, 40);
  const color = /^#[0-9a-f]{6}$/i.test(data.color || '') ? data.color.toLowerCase() : client.profile.color;
  const avatarSeed = /^[a-f0-9]{8,64}$/i.test(data.avatarSeed || '') ? data.avatarSeed.toLowerCase() : client.profile.avatarSeed;
  const avatarUrl = validAvatarUrl(data.avatarUrl);
  if (client.account) {
    const account = accounts[client.account.id];
    account.alias = alias || account.username;
    account.color = color; account.avatarSeed = avatarSeed; account.avatarUrl = avatarUrl; account.updatedAt = new Date().toISOString();
    saveAccounts(); refreshConnectedAccount(account.id);
    return client.profile;
  }
  client.profile.alias = alias; client.profile.color = color; client.profile.avatarSeed = avatarSeed; client.profile.avatarUrl = avatarUrl; client.profile.updatedAt = new Date().toISOString();
  saveProfiles(); refreshConnectedProfiles(client.profile.key);
  return client.profile;
}
function groupRecipients(groupId) {
  return [...clients.entries()].filter(([, client]) => groupReadableByClient(groupId, client)).map(([ws]) => ws);
}
function generatedMarkdownPath(messageId) { return path.join(UPLOAD_DIR, `long-message-${messageId}.md`); }
function writeGeneratedMarkdown(messageId, text) {
  const content = String(text || '');
  const filename = generatedMarkdownPath(messageId);
  fs.writeFileSync(filename, content, 'utf8');
  return { url: `/api/message-download/${encodeURIComponent(messageId)}`, name: `邻聊长消息-${messageId.slice(0, 8)}.md`, mime: 'text/markdown', size: Buffer.byteLength(content) };
}
function removeGeneratedMarkdown(message) {
  if (message && message.kind === 'long-text') {
    try { fs.rmSync(generatedMarkdownPath(message.id), { force: true }); } catch (_) {}
  }
}
function recordAgentPromptMessage(account, groupId) {
  const group = groupForId(groupId);
  if (!account || !group || !account.groups.includes(groupId)) return null;
  const message = { type: 'message', id: crypto.randomUUID(), groupId, kind: 'system', sender: systemSender(), sentAt: new Date().toISOString(), text: agentPromptText(), agentPromptForAccountId: account.id };
  messageHistory.push(message); saveMessages();
  broadcast(message, groupRecipients(groupId));
  return message;
}
function sendGroupHistory(client, groupId) {
  if (!groupReadableByClient(groupId, client)) return;
  send(client.ws, { type: 'group-history', groupId, messages: messageHistory.filter((message) => message.groupId === groupId) });
}
function retractMessage(message, by) {
  if (message.retractedAt) return;
  removeGeneratedMarkdown(message);
  message.retractedAt = new Date().toISOString();
  message.retractedBy = by;
  delete message.text; delete message.file;
  message.kind = 'retracted';
  saveMessages();
  broadcast({ type: 'message-retracted', messageId: message.id, groupId: message.groupId, retractedAt: message.retractedAt }, groupRecipients(message.groupId));
}

function handleConnection(ws, req) {
  if (TLS_ENABLED && REQUIRE_HTTPS && !req.socket.encrypted) return ws.close(1008, '请使用 HTTPS 安全地址');
  const ip = requestIp(req);
  const deviceId = requestedDeviceId(req);
  const context = authContext(req);
  const account = context ? context.account : null;
  const profile = account ? accountProfile(account, ip) : ensureProfile(ip, deviceId);
  const client = { id: crypto.randomUUID(), ws, ip, deviceId, account, session: context && context.session, profile, groups: new Set(profile.groups), preferences: publicPreferences({ account, profile }) };
  clients.set(ws, client);
  send(ws, { type: 'welcome', self: { id: client.id, ...publicProfile(profile), identityBasis: profile.identityType, groups: [...client.groups].filter((id) => groupVisibleToClient(groupForId(id), client) && groupForId(id)), preferences: client.preferences } });
  for (const message of messageHistory) if (groupReadableByClient(message.groupId, client)) send(ws, { type: 'history-message', message });
  send(ws, { type: 'history-complete' });
  broadcastState();

  ws.on('message', (raw) => {
    let data; try { data = JSON.parse(raw.toString()); } catch (_) { return; }
    if (!data || typeof data.type !== 'string') return;
    if (data.type === 'update-profile') {
      updateClientProfile(client, data); broadcastState();
      return send(ws, { type: 'profile-updated', profile: publicProfile(client.profile) });
    }
    if (data.type === 'update-preferences') {
      const enabled = data.longMessageAsMarkdown !== false;
      if (client.account) {
        const accountRecord = accounts[client.account.id];
        accountRecord.longMessageAsMarkdown = enabled; accountRecord.updatedAt = new Date().toISOString(); saveAccounts(); refreshConnectedAccount(accountRecord.id);
      } else {
        client.profile.longMessageAsMarkdown = enabled; client.preferences = publicPreferences(client); client.profile.updatedAt = new Date().toISOString(); saveProfiles();
        send(ws, { type: 'preferences-updated', preferences: client.preferences });
      }
      return;
    }
    if (data.type === 'create-group') {
      const name = cleanText(data.name, 40);
      if (!name) return send(ws, { type: 'error', message: '请输入群组名称。' });
      if (groups.some((group) => group.name.toLocaleLowerCase() === name.toLocaleLowerCase())) return send(ws, { type: 'error', message: '该群组已存在。' });
      const makePrivate = data.privateGroup === true;
      if (makePrivate && !client.account) return send(ws, { type: 'error', message: '隐私群只对注册账号开放，请先登录账号。' });
      const group = { id: crypto.randomUUID(), name, createdAt: new Date().toISOString(), createdBy: profile.publicId, createdByAccountId: makePrivate ? client.account.id : client.account ? client.account.id : '', visibility: makePrivate ? 'private' : 'public' };
      groups.push(group); client.groups.add(group.id); saveGroups(); saveClientGroups(client);
      broadcast({ type: 'notice', groupId: group.id, text: `${profile.alias || ip} 创建并加入了群组「${name}」。` }, groupRecipients(group.id));
      broadcastState();
      return send(ws, { type: 'group-created', group: publicGroup(group, client) });
    }
    if (data.type === 'join-group') {
      const groupId = cleanText(data.groupId, 80);
      const group = groupForId(groupId);
      if (!group || isPrivateGroup(group)) return send(ws, { type: 'error', message: '这个群组不存在，或它是其他用户的隐私群。' });
      client.groups.add(groupId); saveClientGroups(client);
      sendGroupHistory(client, groupId);
      broadcast({ type: 'notice', groupId, text: `${profile.alias || ip} 加入了群组。` }, groupRecipients(groupId));
      return broadcastState();
    }
    if (data.type === 'leave-group') {
      const groupId = cleanText(data.groupId, 80);
      if (groupId === 'lobby') return send(ws, { type: 'error', message: '公共大厅不能退出。' });
      const group = groupForId(groupId);
      if (!group || !client.groups.has(groupId)) return send(ws, { type: 'error', message: '你还没有加入这个群组。' });
      if (isPrivateGroup(group)) return send(ws, { type: 'error', message: '隐私群不能退出；如需停用，请后续删除这个隐私群。' });
      const leavingRecipients = groupRecipients(groupId);
      client.groups.delete(groupId); saveClientGroups(client);
      send(ws, { type: 'group-left', groupId });
      if (client.account && client.account.agentGroupIds.includes(groupId)) {
        client.account.agentGroupIds = client.account.agentGroupIds.filter((id) => id !== groupId); saveAccounts(); refreshConnectedAccount(client.account.id);
      }
      broadcast({ type: 'notice', groupId, text: `${profile.alias || ip} 离开了群组。` }, leavingRecipients);
      return broadcastState();
    }
    if (data.type === 'delete-group') {
      const groupId = cleanText(data.groupId, 80);
      const group = groupForId(groupId);
      if (!group) return send(ws, { type: 'error', message: '群组不存在。' });
      if (group.id === 'lobby') return send(ws, { type: 'error', message: '公共大厅不能删除。' });
      if (!groupOwnerForClient(group, client)) return send(ws, { type: 'error', message: '只有群组创建者可以删除这个群组。' });
      const result = deleteGroupAndData(groupId, client.account ? client.account.username : client.profile.publicId);
      if (!result.ok) return send(ws, { type: 'error', message: result.error || '删除群组失败。' });
      return;
    }
    if (data.type === 'message') {
      const groupId = cleanText(data.groupId, 80);
      const kind = ['text', 'image', 'file', 'audio'].includes(data.kind) ? data.kind : 'text';
      if (!client.groups.has(groupId)) return send(ws, { type: 'error', message: '请先加入该群组。' });
      if (!groups.some((group) => group.id === groupId)) return send(ws, { type: 'error', message: '群组不存在。' });
      const message = { type: 'message', id: crypto.randomUUID(), groupId, kind, sender: publicProfile(client.profile), sentAt: new Date().toISOString() };
      if (kind === 'text') {
        message.text = cleanText(data.text);
        if (!message.text) return;
        if (client.preferences.longMessageAsMarkdown && longTextNeedsMarkdown(message.text)) {
          message.kind = 'long-text';
          message.file = writeGeneratedMarkdown(message.id, message.text);
        }
      } else {
        const file = data.file || {};
        if (typeof file.url !== 'string' || !/^\/uploads\/[A-Za-z0-9%_.-]+$/.test(file.url)) return send(ws, { type: 'error', message: '文件地址无效。' });
        message.file = { url: file.url, name: safeFilename(file.name), mime: safeMime(file.mime), size: Math.max(0, Number(file.size) || 0) };
        if (kind === 'audio') message.duration = Math.max(0, Math.min(Number(data.duration) || 0, 24 * 60 * 60));
      }
      messageHistory.push(message); saveMessages();
      return broadcast(message, groupRecipients(groupId));
    }
    if (data.type === 'retract-message') {
      const id = cleanText(data.messageId, 80);
      const message = messageHistory.find((item) => item.id === id);
      if (!message) return send(ws, { type: 'error', message: '消息不存在或已清理。' });
      if (!groupReadableByClient(message.groupId, client)) return send(ws, { type: 'error', message: '请先加入消息所在的群组。' });
      const ownsMessage = message.sender.profileId ? message.sender.profileId === client.profile.publicId : message.sender.ip === ip;
      if (!ownsMessage) return send(ws, { type: 'error', message: '只能撤回自己发送的消息。' });
      retractMessage(message, ip);
    }
  });
  ws.on('close', () => { clients.delete(ws); broadcastState(); });
  ws.on('error', () => {});
}
wss.on('connection', handleConnection);

function getLanIps() {
  const ips = [];
  for (const addresses of Object.values(os.networkInterfaces())) for (const address of addresses || []) if (!address.internal) ips.push(address.address);
  return ips;
}
server.listen(PORT, '::', () => {
  console.log(`LAN Chat is running on unified port ${PORT}`);
  console.log(`${TLS_ENABLED ? 'Secure' : 'Local'}: ${TLS_ENABLED ? 'https' : 'http'}://127.0.0.1:${PORT}`);
  getLanIps().forEach((ip) => console.log(`LAN:   ${TLS_ENABLED ? 'https' : 'http'}://${ip.includes(':') ? `[${ip}]` : ip}:${PORT}`));
  console.log(`Admin credentials: ${adminCredentials.source}`);
});
function shutdown() {
  console.log('\nShutting down…');
  wss.clients.forEach((socket) => socket.close());
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 3000).unref();
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
