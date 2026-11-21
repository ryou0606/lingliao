const $ = (selector) => document.querySelector(selector);
const groupsEl = $('#groups');
const messagesEl = $('#messages');
const groupNameEl = $('#group-name');
const groupMetaEl = $('#group-meta');
const myNameEl = $('#my-name');
const myIpEl = $('#my-ip');
const myAvatarEl = $('#my-avatar');
const inputEl = $('#message-input');
const composer = $('#composer');
const fileInput = $('#file-input');
const sendButton = $('#send-button');
const voiceButton = $('#voice-button');
const voiceFileInput = $('#voice-file-input');
const groupAction = $('#group-action');
const dialog = $('#group-dialog');
const groupForm = $('#group-form');
const groupInput = $('#group-input');
const attachmentTray = $('#attachment-tray');
const dropOverlay = $('#drop-overlay');
const progressEl = $('#upload-progress');
const progressBar = $('#progress-bar');
const progressText = $('#progress-text');
const recordingPanel = $('#recording-panel');
const recordingTime = $('#recording-time');
const memberAvatars = $('#member-avatars');
const profileDialog = $('#profile-dialog');
const profileForm = $('#profile-form');
const profileNameInput = $('#profile-name');
const profileColorInput = $('#profile-color');
const profileAvatarInput = $('#profile-avatar-input');
const profileAvatarPreview = $('#profile-avatar-preview');
const authScreen = $('#auth-screen');
const appShell = document.querySelector('.app-shell');
const authChoice = $('#auth-choice');
const authLoginForm = $('#auth-login-form');
const authRegisterForm = $('#auth-register-form');
const longTextToggle = $('#long-text-toggle');
const agentScopeButton = $('#agent-scope-button');
const allowDeviceButton = $('#allow-new-device-button');
const deviceWindowStatus = $('#device-window-status');
const agentScopeDialog = $('#agent-scope-dialog');
const agentScopeForm = $('#agent-scope-form');
const agentScopeGroups = $('#agent-scope-groups');
const agentScopeError = $('#agent-scope-error');
const agentScopeSave = $('#agent-scope-save');
const privateGroupInput = $('#private-group-input');

let socket;
let reconnectTimer;
let self = null;
let groups = [];
let clients = [];
let profiles = new Map();
let activeGroupId = 'lobby';
let messages = new Map();
let incomingHistory = null;
let pendingFiles = [];
let sendingFiles = false;
let dragDepth = 0;
let recorder = null;
let recordingStream = null;
let recordingChunks = [];
let recordingStartedAt = 0;
let recordingTimer = null;
let recordPointerDown = false;
let recordCanceled = false;
let recordStartPoint = null;
let profileDraft = null;
let profileUpdateWaiter = null;
let followLatest = true;
let forceScrollToLatest = true;
let autoScrolling = false;
let scrollSettleTimer = null;
let scrollPinToken = 0;
let authMode = '';
let chatStarted = false;
let agentScope = null;
let agentScopeLoading = false;
let deviceAccessEnabled = false;
let deviceWindowTimer = null;
let deviceWindowLoaded = false;

function randomId() {
  if (window.crypto && crypto.randomUUID) return crypto.randomUUID();
  const bytes = new Uint8Array(20); if (window.crypto) crypto.getRandomValues(bytes);
  else for (let index = 0; index < bytes.length; index += 1) bytes[index] = Math.floor(Math.random() * 256);
  return [...bytes].map((value) => value.toString(16).padStart(2, '0')).join('');
}
function getDeviceId() {
  try {
    const cookieValue = (document.cookie.match(/(?:^|;\s*)lan_chat_device=([a-zA-Z0-9_-]{16,80})/) || [])[1];
    let value = cookieValue || localStorage.getItem('lan-chat-device-id');
    if (!/^[a-zA-Z0-9_-]{16,80}$/.test(value || '')) value = randomId();
    localStorage.setItem('lan-chat-device-id', value);
    document.cookie = `lan_chat_device=${value}; Path=/; Max-Age=315360000; SameSite=Strict`;
    return value;
  } catch (_) { return randomId(); }
}
const deviceId = getDeviceId();
function wsUrl() { return `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/?deviceId=${encodeURIComponent(deviceId)}`; }
const AUTH_MODE_KEY = 'lan-chat-identity-mode';
function setAuthPanel(panel) {
  authScreen.hidden = false; appShell.hidden = true;
  authChoice.hidden = panel !== 'choice'; authLoginForm.hidden = panel !== 'login'; authRegisterForm.hidden = panel !== 'register';
  if (panel === 'login') $('#login-username').focus();
  if (panel === 'register') $('#register-username').focus();
}
function stopChat() {
  clearInterval(deviceWindowTimer); deviceWindowTimer = null; deviceWindowLoaded = false;
  if (allowDeviceButton) allowDeviceButton.hidden = true;
  if (deviceWindowStatus) deviceWindowStatus.hidden = true;
  chatStarted = false; clearTimeout(reconnectTimer);
  if (socket) { socket.onclose = null; socket.onerror = null; socket.close(); socket = null; }
  self = null; groups = []; clients = []; profiles = new Map(); messages = new Map(); incomingHistory = null; agentScope = null;
}
function startChat(mode) {
  authMode = mode; localStorage.setItem(AUTH_MODE_KEY, mode); authScreen.hidden = true; appShell.hidden = false; chatStarted = true; connect();
}
async function chooseAnonymous() {
  if (deviceAccessEnabled) {
    try {
      const response = await fetch('/api/auth/anonymous', { method: 'POST' });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || '此设备暂时不能接入。');
    } catch (error) { showChoice(); showToast(error.message, true); return; }
  } else {
    try { await fetch('/api/auth/logout', { method: 'POST' }); } catch (_) {}
  }
  startChat('anonymous');
}
function authError(errorEl, message) { errorEl.textContent = message || '操作失败，请稍后重试。'; }
async function submitAuth(form, endpoint, errorEl) {
  const submit = form.querySelector('button[type="submit"]'); submit.disabled = true; errorEl.textContent = '';
  try {
    const body = Object.fromEntries(new FormData(form).entries());
    const response = await fetch(endpoint, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ ...body, deviceId }) });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(result.error || '操作失败，请稍后重试。');
    form.reset(); startChat('account');
  } catch (error) { authError(errorEl, error.message); }
  finally { submit.disabled = false; }
}
function showChoice() { $('#login-error').textContent = ''; $('#register-error').textContent = ''; setAuthPanel('choice'); }
async function bootAuth() {
  let state = { authenticated: false };
  try { state = await fetch(`/api/auth/state?deviceId=${encodeURIComponent(deviceId)}`).then((response) => response.json()); } catch (_) {}
  deviceAccessEnabled = state.deviceAccessEnabled === true;
  const storedMode = localStorage.getItem(AUTH_MODE_KEY);
  if (storedMode === 'account' && state.authenticated) return startChat('account');
  if (storedMode === 'account') return setAuthPanel('login');
  if (storedMode === 'anonymous') return chooseAnonymous();
  if (state.authenticated) return startChat('account');
  showChoice();
}
function transmit(value) {
  if (!socket || socket.readyState !== WebSocket.OPEN) { showToast('连接尚未恢复，请稍后再试。', true); return false; }
  socket.send(JSON.stringify(value)); return true;
}
function groupById(id) { return groups.find((group) => group.id === id); }
function joined(groupId) { return !!(self && self.groups && self.groups.includes(groupId)); }
function members(groupId) { return clients.filter((client) => client.groups.includes(groupId)); }
function profileFor(sender) {
  if (sender && sender.identityType === 'account') return sender;
  return profiles.get(sender && sender.profileId) || profiles.get(sender && sender.ip) || sender || { name: '未知设备', ip: '' };
}
function shortSize(bytes) {
  if (!Number.isFinite(Number(bytes)) || Number(bytes) < 0) return '';
  const units = ['B', 'KB', 'MB', 'GB', 'TB']; let i = 0; let value = Number(bytes);
  while (value >= 1024 && i < units.length - 1) { value /= 1024; i += 1; }
  return `${value.toFixed(i && value < 100 ? 1 : 0)} ${units[i]}`;
}
function timestamp(iso) {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return '';
  const today = new Date();
  const sameDay = date.toDateString() === today.toDateString();
  return new Intl.DateTimeFormat('zh-CN', sameDay ? { hour: '2-digit', minute: '2-digit', hour12: false } : { month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false }).format(date);
}
function durationLabel(seconds) {
  const whole = Math.max(0, Math.round(Number(seconds) || 0));
  return `${Math.floor(whole / 60)}:${String(whole % 60).padStart(2, '0')}`;
}
function makeAvatar(profile, target) {
  const seed = String((profile && profile.avatarSeed) || '00000000').padEnd(8, '0');
  const color = (profile && profile.color) || '#547363';
  target.style.setProperty('--avatar-color', color);
  target.replaceChildren();
  if (profile && profile.avatarUrl) {
    const image = document.createElement('img'); image.src = profile.avatarUrl; image.alt = ''; image.loading = 'lazy'; target.append(image); return;
  }
  const bits = [...seed].map((char) => parseInt(char, 16)).flatMap((number) => [number & 1, number & 2, number & 4, number & 8]);
  const pattern = [bits[0], bits[1], bits[0], bits[2], bits[3], bits[2], bits[4], bits[5], bits[4]];
  pattern.forEach((on) => { const cell = document.createElement('span'); if (on) cell.className = 'on'; target.append(cell); });
  target.title = (profile && profile.name) || '';
}
function createAvatar(profile, className = '') {
  const avatar = document.createElement('div'); avatar.className = `avatar ${className}`.trim(); makeAvatar(profile, avatar); return avatar;
}
function showToast(message, error = false) {
  const toast = document.createElement('div'); toast.className = `toast${error ? ' error' : ''}`; toast.textContent = message;
  $('#toast-region').append(toast);
  setTimeout(() => toast.remove(), 4200);
}
function isNearLatest() {
  return messagesEl.scrollHeight - messagesEl.scrollTop - messagesEl.clientHeight < 160;
}
function scrollToLatest() {
  clearTimeout(scrollSettleTimer);
  const token = ++scrollPinToken;
  followLatest = true; autoScrolling = true; messagesEl.classList.add('pinning-latest');
  const apply = () => { if (token === scrollPinToken) messagesEl.scrollTop = messagesEl.scrollHeight; };
  apply();
  requestAnimationFrame(() => { apply(); requestAnimationFrame(apply); });
  scrollSettleTimer = setTimeout(() => {
    if (token !== scrollPinToken) return;
    apply(); messagesEl.classList.remove('pinning-latest'); autoScrolling = false; followLatest = isNearLatest();
  }, 450);
}
function interruptAutoScroll() {
  clearTimeout(scrollSettleTimer); scrollPinToken += 1; autoScrolling = false; followLatest = false;
  messagesEl.classList.remove('pinning-latest');
}
messagesEl.addEventListener('touchstart', interruptAutoScroll, { passive: true });
messagesEl.addEventListener('pointerdown', (event) => { if (event.pointerType !== 'mouse') interruptAutoScroll(); }, { passive: true });
messagesEl.addEventListener('wheel', interruptAutoScroll, { passive: true });
messagesEl.addEventListener('scroll', () => {
  if (!autoScrolling) followLatest = isNearLatest();
}, { passive: true });

function renderIdentity() {
  if (!self) return;
  const profile = profileFor(self);
  myNameEl.textContent = profile.name || self.ip;
  myIpEl.textContent = self.identityType === 'account' ? `账号身份 · ${self.ip}` : (profile.alias ? self.ip : '默认名称 · 当前 IP');
  makeAvatar(profile, myAvatarEl);
  const accountIdentity = self.identityType === 'account';
  agentScopeButton.hidden = !accountIdentity;
  if (allowDeviceButton) {
    allowDeviceButton.hidden = !accountIdentity || !deviceAccessEnabled;
    if (accountIdentity && deviceAccessEnabled && !deviceWindowLoaded) {
      deviceWindowLoaded = true;
      fetch('/api/access/window').then(r => r.ok ? r.json() : null).then(value => { if (value && authMode === 'account') renderDeviceWindow(value); }).catch(() => {});
    }
  }
  if (longTextToggle && self.preferences) longTextToggle.checked = self.preferences.longMessageAsMarkdown !== false;
  if (privateGroupInput) {
    privateGroupInput.disabled = !accountIdentity;
    if (!accountIdentity) privateGroupInput.checked = false;
  }
}
function renderGroups() {
  groupsEl.replaceChildren();
  groups.forEach((group) => {
    const row = document.createElement('div');
    row.className = `group-row${group.id === activeGroupId ? ' active' : ''}`;
    const button = document.createElement('button');
    button.type = 'button'; button.className = `group${group.id === activeGroupId ? ' active' : ''}`; button.title = group.name;
    const hash = document.createElement('span'); hash.className = 'group-hash'; hash.textContent = '#';
    const name = document.createElement('span'); name.className = 'group-name'; name.textContent = group.name;
    const count = document.createElement('span'); count.className = 'member-count'; count.textContent = `${members(group.id).length} 在线`;
    if (group.isPrivate) { hash.textContent = '▣'; name.title = '隐私群 · 只有你能看到'; }
    button.append(hash, name, count);
    button.onclick = () => {
      if (activeGroupId === group.id) return;
      activeGroupId = group.id; followLatest = true; forceScrollToLatest = true; render();
    };
    row.append(button);
    if (group.id !== 'lobby' && group.isOwner) {
      const deleteButton = document.createElement('button');
      deleteButton.type = 'button';
      deleteButton.className = 'group-delete';
      deleteButton.textContent = '删除';
      deleteButton.title = `删除群组「${group.name}」`;
      deleteButton.onclick = () => deleteGroup(group);
      row.append(deleteButton);
    }
    groupsEl.append(row);
  });
}
function renderHeader() {
  const group = groupById(activeGroupId) || { name: '群组' };
  const isJoined = joined(activeGroupId);
  const online = members(activeGroupId);
  groupNameEl.textContent = group.name;
  groupMetaEl.textContent = `${online.length} 台设备在线${group.isPrivate ? ' · 隐私群' : isJoined ? ' · 已加入' : ' · 加入后才能查看和发送'}`;
  groupAction.textContent = activeGroupId === 'lobby' ? '公共大厅' : group.isPrivate ? '隐私群' : (isJoined ? '退出群组' : '加入群组');
  groupAction.disabled = activeGroupId === 'lobby' || !!group.isPrivate;
  inputEl.disabled = !isJoined;
  sendButton.disabled = !isJoined || sendingFiles;
  voiceButton.disabled = !isJoined || sendingFiles;
  memberAvatars.replaceChildren();
  online.slice(0, 5).reverse().forEach((client) => memberAvatars.append(createAvatar(client)));
  if (online.length > 5) { const more = document.createElement('span'); more.className = 'member-overflow'; more.textContent = `+${online.length - 5}`; memberAvatars.prepend(more); }
}
function copyButtonAction(button, value) {
  return async () => {
    try { await navigator.clipboard.writeText(value); }
    catch (_) {
      const area = document.createElement('textarea'); area.value = value; document.body.append(area); area.select(); document.execCommand('copy'); area.remove();
    }
    const original = button.textContent; button.textContent = '已复制'; setTimeout(() => { button.textContent = original; }, 1300);
  };
}
async function copyText(value) {
  try { await navigator.clipboard.writeText(value); return; }
  catch (_) {
    const area = document.createElement('textarea'); area.value = value; document.body.append(area); area.select(); document.execCommand('copy'); area.remove();
  }
}
function renderMessageContent(message, body) {
  if (message.kind === 'retracted' || message.retractedAt) {
    body.classList.add('retracted'); body.textContent = '这条消息已撤回'; return '';
  }
  if (message.kind === 'system') {
    const card = document.createElement('div'); card.className = 'agent-prompt-card';
    const title = document.createElement('strong'); title.textContent = '邻聊 Agent 接入提示';
    const text = document.createElement('p'); text.textContent = message.text || '';
    const copy = document.createElement('button'); copy.type = 'button'; copy.textContent = self && self.identityType === 'account' ? '复制我的接入提示词' : '注册账号后复制接入提示词';
    copy.disabled = !self || self.identityType !== 'account';
    copy.onclick = async () => {
      try {
        const response = await fetch('/api/mcp/prompt'); const value = await response.json();
        if (!response.ok) throw new Error(value.error || '无法生成接入提示词。');
        await copyText(value.prompt); showToast('已复制包含当前账号授权信息的提示词，请只发给自己的 Agent。');
      } catch (error) { showToast(error.message, true); }
    };
    card.append(title, text, copy); body.append(card); return message.text || '';
  }
  if (message.kind === 'long-text') {
    const file = message.file || {};
    const downloadUrl = `${file.url || ''}${String(file.url || '').includes('?') ? '&' : '?'}deviceId=${encodeURIComponent(deviceId)}`;
    const link = document.createElement('a'); link.className = 'file-card'; link.href = downloadUrl; link.download = file.name || '邻聊长消息.md'; link.title = '点击查看或下载完整 Markdown';
    const icon = document.createElement('span'); icon.className = 'file-icon'; icon.textContent = 'MD';
    const detail = document.createElement('span'); detail.className = 'file-card-detail';
    const title = document.createElement('strong'); title.textContent = file.name || '邻聊长消息.md';
    const size = document.createElement('small'); size.textContent = `${shortSize(file.size) || 'Markdown'} · 手动查看`;
    const download = document.createElement('span'); download.className = 'file-download'; download.textContent = '↓';
    detail.append(title, size); link.append(icon, detail, download); body.append(link);
    return message.text || '';
  }
  if (message.kind === 'text') { body.textContent = message.text || ''; return message.text || ''; }
  if (message.kind === 'image') {
    const image = document.createElement('img');
    image.src = message.file.url; image.alt = message.file.name || '聊天图片'; image.loading = 'lazy'; image.draggable = true;
    image.title = '点击查看原图，也可拖到其他应用';
    image.onclick = () => window.open(message.file.url, '_blank', 'noopener');
    image.ondragstart = (event) => {
      const url = new URL(message.file.url, location.href).href;
      event.dataTransfer.effectAllowed = 'copy';
      event.dataTransfer.setData('text/uri-list', url); event.dataTransfer.setData('text/plain', url);
      event.dataTransfer.setData('DownloadURL', `${message.file.mime || 'image/*'}:${message.file.name}:${url}`);
    };
    body.append(image); return new URL(message.file.url, location.href).href;
  }
  if (message.kind === 'audio') {
    const wrap = document.createElement('div'); wrap.className = 'audio-message';
    const audio = document.createElement('audio'); audio.controls = true; audio.preload = 'metadata'; audio.src = message.file.url;
    const meta = document.createElement('div'); meta.className = 'audio-meta';
    const label = document.createElement('span'); label.textContent = '语音消息';
    const duration = document.createElement('span'); duration.textContent = message.duration ? durationLabel(message.duration) : '录音文件';
    audio.addEventListener('loadedmetadata', () => { if (Number.isFinite(audio.duration)) duration.textContent = durationLabel(audio.duration); });
    const save = document.createElement('a'); save.textContent = '下载录音'; save.download = message.file.name;
    save.href = `/api/download/${String(message.file.url).replace(/^\/uploads\//, '')}?name=${encodeURIComponent(message.file.name || 'audio')}`;
    meta.append(save);
    meta.append(label, duration); wrap.append(audio, meta); body.append(wrap);
    return new URL(message.file.url, location.href).href;
  }
  const storedName = String(message.file.url || '').replace(/^\/uploads\//, '');
  const downloadUrl = `/api/download/${storedName}?name=${encodeURIComponent(message.file.name || 'file')}`;
  const link = document.createElement('a'); link.className = 'file-card'; link.href = downloadUrl; link.download = message.file.name; link.title = '点击下载文件';
  const icon = document.createElement('span'); icon.className = 'file-icon'; icon.textContent = String((message.file.name || 'FILE').split('.').pop() || 'FILE').slice(0, 4).toUpperCase();
  const detail = document.createElement('span'); detail.className = 'file-card-detail';
  const title = document.createElement('strong'); title.textContent = message.file.name || '文件';
  const size = document.createElement('small'); size.textContent = shortSize(message.file.size) || '文件';
  const download = document.createElement('span'); download.className = 'file-download'; download.textContent = '↓';
  detail.append(title, size); link.append(icon, detail, download); body.append(link);
  return new URL(message.file.url, location.href).href;
}
function renderMessages() {
  const shouldFollowLatest = forceScrollToLatest || followLatest || isNearLatest();
  if (shouldFollowLatest) autoScrolling = true;
  messagesEl.replaceChildren();
  const items = messages.get(activeGroupId) || [];
  if (!items.length) {
    const empty = document.createElement('p'); empty.className = 'empty';
    empty.textContent = joined(activeGroupId) ? '这里还没有消息。输入一句话，或直接把文件拖进窗口。' : '你还没有加入这个群组。点击右上角加入后即可参与聊天。';
    messagesEl.append(empty);
    if (!incomingHistory) forceScrollToLatest = false;
    autoScrolling = false; return;
  }
  items.forEach((message) => {
    const node = $('#message-template').content.firstElementChild.cloneNode(true);
    const mine = !!(self && message.sender && ((message.sender.profileId && message.sender.profileId === self.profileId) || (!message.sender.profileId && message.sender.ip === self.ip)));
    if (mine) node.classList.add('mine');
    node.dataset.messageId = message.id;
    // Messages carry a sender snapshot. Never resolve historical messages through
    // the current profile map, otherwise later nickname/avatar changes rewrite history.
    const resolved = message.sender || { name: '未知用户', ip: '' };
    makeAvatar(resolved, node.querySelector('.message-avatar'));
    node.querySelector('.message-head strong').textContent = resolved.name || message.sender.ip;
    const senderIp = node.querySelector('.sender-ip'); senderIp.textContent = resolved.identityType === 'account' ? '' : (resolved.alias ? message.sender.ip : '');
    node.querySelector('time').textContent = timestamp(message.sentAt);
    const body = node.querySelector('.message-body');
    const copyValue = renderMessageContent(message, body);
    const copyButton = node.querySelector('.copy-message');
    copyButton.hidden = !copyValue; if (copyValue) copyButton.onclick = copyButtonAction(copyButton, copyValue);
    const retractButton = node.querySelector('.retract-message');
    retractButton.hidden = !mine || message.kind === 'retracted' || !!message.retractedAt;
    retractButton.onclick = () => {
      if (retractButton.dataset.confirm !== 'yes') {
        retractButton.dataset.confirm = 'yes'; retractButton.textContent = '再次点击确认';
        setTimeout(() => { retractButton.dataset.confirm = ''; retractButton.textContent = '撤回'; }, 3000); return;
      }
      transmit({ type: 'retract-message', messageId: message.id });
    };
    messagesEl.append(node);
    node.querySelectorAll('img, audio, video').forEach((media) => {
      const eventName = media.tagName === 'IMG' ? 'load' : 'loadedmetadata';
      media.addEventListener(eventName, () => { if (followLatest) scrollToLatest(); }, { once: true });
    });
  });
  forceScrollToLatest = false;
  if (shouldFollowLatest || incomingHistory) scrollToLatest(); else autoScrolling = false;
}
function render() { renderIdentity(); renderGroups(); renderHeader(); renderMessages(); }
function addMessage(message) {
  const list = messages.get(message.groupId) || [];
  if (list.some((item) => item.id === message.id)) return;
  list.push(message); messages.set(message.groupId, list);
  const sentByMe = !!(self && message.sender && ((message.sender.profileId && message.sender.profileId === self.profileId) || (!message.sender.profileId && message.sender.ip === self.ip)));
  if (sentByMe) { followLatest = true; forceScrollToLatest = true; }
  if (message.groupId === activeGroupId) renderMessages();
}
function retractLocal(id, groupId, retractedAt) {
  const item = (messages.get(groupId) || []).find((message) => message.id === id);
  if (!item) return;
  item.kind = 'retracted'; item.retractedAt = retractedAt; delete item.text; delete item.file;
  if (groupId === activeGroupId) renderMessages();
}
function deleteGroup(group) {
  if (!group || group.id === 'lobby') return;
  if (!confirm(`确定删除群组「${group.name}」吗？这个群组里的消息和附件会被清理，成员与 Agent 授权也会被移除。`)) return;
  transmit({ type: 'delete-group', groupId: group.id });
}

function connect() {
  if (!chatStarted) return;
  clearTimeout(reconnectTimer);
  socket = new WebSocket(wsUrl());
  socket.onopen = () => { $('#connection-banner').hidden = true; };
  socket.onclose = () => { if (!chatStarted) return; $('#connection-banner').hidden = false; reconnectTimer = setTimeout(connect, 1500); };
  socket.onerror = () => socket.close();
  socket.onmessage = ({ data }) => {
    let message; try { message = JSON.parse(data); } catch (_) { return; }
    if (message.type === 'welcome') {
      self = message.self; self.preferences = message.self.preferences || { longMessageAsMarkdown: true }; incomingHistory = new Map(); followLatest = true; forceScrollToLatest = true; myIpEl.textContent = self.ip; renderIdentity();
    } else if (message.type === 'state') {
      groups = message.groups || []; clients = message.clients || [];
      profiles = new Map();
      (message.profiles || []).forEach((profile) => { if (profile.profileId) profiles.set(profile.profileId, profile); if (!profiles.has(profile.ip)) profiles.set(profile.ip, profile); });
      const mine = clients.find((client) => self && client.id === self.id);
      if (self && mine) self = { ...self, ...mine };
      if (self) for (const groupId of messages.keys()) if (!self.groups.includes(groupId)) messages.delete(groupId);
      if (!groupById(activeGroupId)) activeGroupId = 'lobby';
      render();
    } else if (message.type === 'history-message' && incomingHistory) {
      const item = message.message; const list = incomingHistory.get(item.groupId) || []; list.push(item); incomingHistory.set(item.groupId, list);
    } else if (message.type === 'history-complete' && incomingHistory) {
      messages = incomingHistory; incomingHistory = null; followLatest = true; forceScrollToLatest = true; renderMessages();
    } else if (message.type === 'group-history') {
      messages.set(message.groupId, Array.isArray(message.messages) ? message.messages : []);
      if (message.groupId === activeGroupId) { followLatest = true; forceScrollToLatest = true; renderMessages(); }
    } else if (message.type === 'group-left') {
      messages.delete(message.groupId); if (message.groupId === activeGroupId) renderMessages();
    } else if (message.type === 'group-deleted') {
      messages.delete(message.groupId);
      if (message.groupId === activeGroupId) { activeGroupId = 'lobby'; followLatest = true; forceScrollToLatest = true; }
      showToast(`群组「${message.groupName || '已删除群组'}」已删除。`);
    } else if (message.type === 'message') addMessage(message);
    else if (message.type === 'profile-updated') {
      self = { ...self, ...message.profile }; render(); showToast('个人资料已保存。');
      if (profileUpdateWaiter) { profileUpdateWaiter.resolve(message.profile); profileUpdateWaiter = null; }
    }
    else if (message.type === 'preferences-updated') { self = { ...self, preferences: message.preferences }; renderIdentity(); }
    else if (message.type === 'message-retracted') retractLocal(message.messageId, message.groupId, message.retractedAt);
    else if (message.type === 'group-created') { activeGroupId = message.group.id; followLatest = true; forceScrollToLatest = true; render(); }
    else if (message.type === 'notice' && message.groupId === activeGroupId) showToast(message.text);
    else if (message.type === 'error') showToast(message.message, true);
  };
}

function previewName(file) {
  const extension = file.name && file.name.includes('.') ? file.name.split('.').pop() : 'FILE';
  return extension.slice(0, 4).toUpperCase();
}
function addFiles(fileList, kind = '') {
  const files = [...fileList].filter((file) => file instanceof File || file instanceof Blob);
  if (!files.length) return;
  if (!joined(activeGroupId)) return showToast('请先加入当前群组。', true);
  for (const file of files) {
    const item = { id: randomId(), file, kind, url: '' };
    if (file.type && file.type.startsWith('image/')) item.url = URL.createObjectURL(file);
    pendingFiles.push(item);
  }
  renderAttachments();
}
function renderAttachments() {
  attachmentTray.replaceChildren(); attachmentTray.hidden = !pendingFiles.length;
  pendingFiles.forEach((item) => {
    const node = document.createElement('div'); node.className = 'attachment';
    const preview = document.createElement('div'); preview.className = 'attachment-preview';
    if (item.url) { const image = document.createElement('img'); image.src = item.url; image.alt = ''; preview.append(image); }
    else preview.textContent = previewName(item.file);
    const info = document.createElement('span'); info.className = 'attachment-info';
    const name = document.createElement('strong'); name.textContent = item.file.name || '语音消息';
    const size = document.createElement('small'); size.textContent = shortSize(item.file.size);
    const remove = document.createElement('button'); remove.type = 'button'; remove.className = 'attachment-remove'; remove.textContent = '×'; remove.title = '移除';
    remove.onclick = () => { if (item.url) URL.revokeObjectURL(item.url); pendingFiles = pendingFiles.filter((entry) => entry.id !== item.id); renderAttachments(); };
    info.append(name, size); node.append(preview, info, remove); attachmentTray.append(node);
  });
}
function uploadOne(file, name, onProgress) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest(); xhr.open('POST', '/api/upload'); xhr.responseType = 'json';
    xhr.upload.onprogress = (event) => { if (event.lengthComputable) onProgress(event.loaded / event.total); };
    xhr.onload = () => {
      const response = xhr.response || (() => { try { return JSON.parse(xhr.responseText); } catch (_) { return {}; } })();
      if (xhr.status >= 200 && xhr.status < 300) resolve(response); else reject(new Error(response.error || `上传失败（${xhr.status}）`));
    };
    xhr.onerror = () => reject(new Error('网络中断，文件未上传完成。'));
    const data = new FormData(); data.append('file', file, name || file.name || 'file'); xhr.send(data);
  });
}
async function sendPendingFiles(groupId) {
  const queue = pendingFiles; pendingFiles = []; renderAttachments();
  if (!queue.length) return;
  sendingFiles = true; renderHeader(); progressEl.hidden = false;
  const failures = [];
  for (let index = 0; index < queue.length; index += 1) {
    const item = queue[index]; const file = item.file; const name = file.name || `file-${Date.now()}`;
    progressEl.querySelector('span').textContent = `${index + 1}/${queue.length} · ${name}`;
    progressBar.style.width = '0%'; progressText.textContent = '准备中';
    try {
      const uploaded = await uploadOne(file, name, (ratio) => { const percent = Math.round(ratio * 100); progressBar.style.width = `${percent}%`; progressText.textContent = `${percent}%`; });
      const kind = item.kind || (file.type && file.type.startsWith('image/') ? 'image' : 'file');
      transmit({ type: 'message', groupId, kind, file: uploaded });
    } catch (error) { failures.push(`${name}：${error.message}`); }
    if (item.url) URL.revokeObjectURL(item.url);
  }
  sendingFiles = false; progressEl.hidden = true; renderHeader();
  if (failures.length) showToast(`有 ${failures.length} 个文件发送失败：${failures[0]}`, true);
}

composer.onsubmit = (event) => {
  event.preventDefault();
  if (!joined(activeGroupId) || sendingFiles) return;
  const text = inputEl.value.trim(); const groupId = activeGroupId;
  if (!text && !pendingFiles.length) return;
  if (text) { transmit({ type: 'message', groupId, kind: 'text', text }); inputEl.value = ''; inputEl.style.height = ''; }
  if (pendingFiles.length) sendPendingFiles(groupId);
};
inputEl.onkeydown = (event) => { if (event.key === 'Enter' && !event.shiftKey && !event.isComposing) { event.preventDefault(); composer.requestSubmit(); } };
inputEl.oninput = () => { inputEl.style.height = 'auto'; inputEl.style.height = `${Math.min(inputEl.scrollHeight, 132)}px`; };
fileInput.onchange = () => { addFiles(fileInput.files); fileInput.value = ''; };
voiceFileInput.onchange = () => {
  const audioFiles = [...voiceFileInput.files].filter((file) => file.type.startsWith('audio/') || /\.(m4a|mp3|wav|ogg|webm|aac|amr|3gp)$/i.test(file.name));
  if (audioFiles.length) addFiles(audioFiles, 'audio');
  else if (voiceFileInput.files.length) showToast('请选择录音文件。', true);
  voiceFileInput.value = '';
};
window.addEventListener('paste', (event) => {
  if (!event.clipboardData) return;
  const files = [...event.clipboardData.items].filter((item) => item.kind === 'file').map((item) => item.getAsFile()).filter(Boolean);
  if (files.length) { event.preventDefault(); addFiles(files); }
});
function containsFiles(event) { return event.dataTransfer && [...(event.dataTransfer.types || [])].includes('Files'); }
window.addEventListener('dragenter', (event) => { if (!containsFiles(event)) return; event.preventDefault(); dragDepth += 1; dropOverlay.hidden = false; });
window.addEventListener('dragover', (event) => { if (!containsFiles(event)) return; event.preventDefault(); event.dataTransfer.dropEffect = 'copy'; });
window.addEventListener('dragleave', (event) => { if (!containsFiles(event)) return; event.preventDefault(); dragDepth = Math.max(0, dragDepth - 1); if (!dragDepth) dropOverlay.hidden = true; });
window.addEventListener('drop', (event) => { if (!containsFiles(event)) return; event.preventDefault(); dragDepth = 0; dropOverlay.hidden = true; addFiles(event.dataTransfer.files); });

function preferredAudioMime() {
  const options = ['audio/webm;codecs=opus', 'audio/mp4;codecs=mp4a.40.2', 'audio/mp4', 'audio/webm'];
  return options.find((type) => window.MediaRecorder && MediaRecorder.isTypeSupported(type)) || '';
}
function stopTracks() { if (recordingStream) recordingStream.getTracks().forEach((track) => track.stop()); recordingStream = null; }
function canRecordInPage() { return !!(window.isSecureContext && navigator.mediaDevices && navigator.mediaDevices.getUserMedia && window.MediaRecorder); }
async function startRecording(event) {
  // Leave the ordinary click intact for HTTP and browsers without MediaRecorder.
  if (!canRecordInPage()) return;
  if (event.pointerType === 'mouse' && event.button !== 0) return;
  event.preventDefault();
  if (!joined(activeGroupId) || sendingFiles) return;
  recordPointerDown = true; recordCanceled = false; recordStartPoint = { x: event.clientX, y: event.clientY };
  try { voiceButton.setPointerCapture(event.pointerId); } catch (_) {}
  try {
    const stream = await navigator.mediaDevices.getUserMedia({ audio: { echoCancellation: true, noiseSuppression: true }, video: false });
    if (!recordPointerDown) { stream.getTracks().forEach((track) => track.stop()); return; }
    recordingStream = stream; recordingChunks = [];
    const mimeType = preferredAudioMime(); recorder = mimeType ? new MediaRecorder(stream, { mimeType }) : new MediaRecorder(stream);
    recorder.ondataavailable = (chunk) => { if (chunk.data && chunk.data.size) recordingChunks.push(chunk.data); };
    recorder.onstop = async () => {
      clearInterval(recordingTimer); recordingPanel.hidden = true; voiceButton.classList.remove('recording');
      const elapsed = (Date.now() - recordingStartedAt) / 1000; const type = recorder.mimeType || mimeType || 'audio/webm';
      const chunks = recordingChunks; stopTracks(); recorder = null;
      if (recordCanceled || elapsed < .35 || !chunks.length) { if (elapsed >= .35 && recordCanceled) showToast('已取消录音。'); return; }
      const extension = type.includes('mp4') ? 'm4a' : type.includes('ogg') ? 'ogg' : 'webm';
      const blob = new Blob(chunks, { type }); const name = `语音-${new Date().toISOString().replace(/[:.]/g, '-')}.${extension}`;
      sendingFiles = true; renderHeader(); progressEl.hidden = false; progressEl.querySelector('span').textContent = '正在发送语音';
      try {
        const uploaded = await uploadOne(blob, name, (ratio) => { const percent = Math.round(ratio * 100); progressBar.style.width = `${percent}%`; progressText.textContent = `${percent}%`; });
        transmit({ type: 'message', groupId: activeGroupId, kind: 'audio', file: uploaded, duration: elapsed });
      } catch (error) { showToast(`语音发送失败：${error.message}`, true); }
      sendingFiles = false; progressEl.hidden = true; renderHeader();
    };
    recordingPanel.querySelector('span:last-child').textContent = '松开发送 · 向外滑动取消';
    recordingStartedAt = Date.now(); recorder.start(250); voiceButton.classList.add('recording'); recordingPanel.hidden = false;
    recordingTime.textContent = '0:00'; recordingTimer = setInterval(() => { recordingTime.textContent = durationLabel((Date.now() - recordingStartedAt) / 1000); }, 250);
  } catch (error) {
    recordPointerDown = false; stopTracks();
    showToast(error && error.name === 'NotAllowedError' ? '没有获得麦克风权限，请在浏览器地址栏中允许后重试。' : '无法启动录音，请检查麦克风是否可用。', true);
  }
}
function finishRecording(cancel = false) {
  recordPointerDown = false; recordCanceled = recordCanceled || cancel;
  if (recorder && recorder.state !== 'inactive') recorder.stop();
}
voiceButton.addEventListener('pointerdown', startRecording);
voiceButton.addEventListener('click', () => {
  if (!canRecordInPage() && joined(activeGroupId) && !sendingFiles) voiceFileInput.click();
});
voiceButton.addEventListener('pointerup', () => finishRecording(false));
voiceButton.addEventListener('pointercancel', () => finishRecording(true));
voiceButton.addEventListener('pointermove', (event) => {
  if (!recordPointerDown || !recordStartPoint) return;
  if (Math.hypot(event.clientX - recordStartPoint.x, event.clientY - recordStartPoint.y) > 110) { recordCanceled = true; recordingPanel.querySelector('span:last-child').textContent = '松开取消'; }
});
voiceButton.addEventListener('contextmenu', (event) => event.preventDefault());

function randomAvatarSeed() {
  const bytes = new Uint8Array(8); crypto.getRandomValues(bytes);
  return [...bytes].map((value) => value.toString(16).padStart(2, '0')).join('');
}
function clearDraftPreview() {
  if (profileDraft && profileDraft.previewObjectUrl) URL.revokeObjectURL(profileDraft.previewObjectUrl);
  if (profileDraft) profileDraft.previewObjectUrl = '';
}
function renderProfileDraft() {
  if (!profileDraft) return;
  makeAvatar({ color: profileDraft.color, avatarSeed: profileDraft.avatarSeed, avatarUrl: profileDraft.previewObjectUrl || profileDraft.avatarUrl }, profileAvatarPreview);
  profileColorInput.value = profileDraft.color;
}
function imageElement(url) {
  return new Promise((resolve, reject) => {
    const image = new Image(); image.onload = () => resolve(image); image.onerror = () => reject(new Error('无法读取这张图片。')); image.src = url;
  });
}
async function prepareAvatar(file) {
  if (!file || !/^image\/(?:png|jpe?g|webp|gif)$/i.test(file.type || '')) throw new Error('请选择 PNG、JPG、WebP 或 GIF 图片。');
  const sourceUrl = URL.createObjectURL(file);
  try {
    const image = await imageElement(sourceUrl); const size = Math.min(image.naturalWidth, image.naturalHeight);
    const sourceX = (image.naturalWidth - size) / 2; const sourceY = (image.naturalHeight - size) / 2;
    const canvas = document.createElement('canvas'); canvas.width = 256; canvas.height = 256;
    canvas.getContext('2d').drawImage(image, sourceX, sourceY, size, size, 0, 0, 256, 256);
    return await new Promise((resolve, reject) => canvas.toBlob((blob) => blob ? resolve(blob) : reject(new Error('头像处理失败。')), 'image/jpeg', .88));
  } finally { URL.revokeObjectURL(sourceUrl); }
}
$('#edit-profile').onclick = () => {
  if (!self) return;
  const current = profileFor(self);
  profileDraft = { alias: current.alias || '', color: current.color || '#4f6f8f', avatarSeed: current.avatarSeed || randomAvatarSeed(), avatarUrl: current.avatarUrl || '', avatarBlob: null, previewObjectUrl: '' };
  profileNameInput.value = profileDraft.alias; $('#profile-error').textContent = '';
  $('#profile-identity-hint').textContent = self.identityBasis === 'account' ? `账号身份：${self.username || self.name} · 多台设备共享此昵称和头像` : self.identityBasis === 'mac' ? `绑定方式：局域网 MAC · 当前 IP ${self.ip}` : self.identityBasis === 'device' ? `绑定方式：浏览器设备 ID · 当前 IP ${self.ip}` : `绑定方式：当前 IP ${self.ip}`;
  renderProfileDraft(); profileDialog.showModal(); profileNameInput.focus();
};
profileColorInput.oninput = () => { if (profileDraft) { profileDraft.color = profileColorInput.value; renderProfileDraft(); } };
$('#random-avatar').onclick = () => {
  if (!profileDraft) return;
  clearDraftPreview(); profileDraft.avatarBlob = null; profileDraft.avatarUrl = ''; profileDraft.avatarSeed = randomAvatarSeed();
  const colors = ['#4f6f8f', '#6f6654', '#765d69', '#4f7569', '#6c648c', '#7a604b', '#4d7180', '#7b5960'];
  profileDraft.color = colors[Math.floor(Math.random() * colors.length)]; renderProfileDraft();
};
$('#clear-avatar').onclick = () => { if (profileDraft) { clearDraftPreview(); profileDraft.avatarBlob = null; profileDraft.avatarUrl = ''; renderProfileDraft(); } };
profileAvatarInput.onchange = async () => {
  const file = profileAvatarInput.files && profileAvatarInput.files[0]; profileAvatarInput.value = ''; if (!file || !profileDraft) return;
  const errorEl = $('#profile-error'); errorEl.textContent = '正在处理头像…';
  try {
    const blob = await prepareAvatar(file); clearDraftPreview(); profileDraft.avatarBlob = blob; profileDraft.previewObjectUrl = URL.createObjectURL(blob); errorEl.textContent = ''; renderProfileDraft();
  } catch (error) { errorEl.textContent = error.message; }
};
profileForm.onsubmit = async (event) => {
  if (event.submitter && event.submitter.value === 'cancel') { event.preventDefault(); profileDialog.close(); return; }
  event.preventDefault(); if (!profileDraft) return;
  const save = profileForm.querySelector('.send'); const errorEl = $('#profile-error'); save.disabled = true; errorEl.textContent = '';
  try {
    let avatarUrl = profileDraft.avatarUrl;
    if (profileDraft.avatarBlob) {
      const data = new FormData(); data.append('file', profileDraft.avatarBlob, `avatar-${Date.now()}.jpg`);
      const response = await fetch('/api/avatar', { method: 'POST', body: data }); const uploaded = await response.json();
      if (!response.ok) throw new Error(uploaded.error || '头像上传失败。'); avatarUrl = uploaded.url;
    }
    if (!socket || socket.readyState !== WebSocket.OPEN) throw new Error('连接尚未恢复，请稍后再试。');
    const confirmed = new Promise((resolve, reject) => {
      const timer = setTimeout(() => { if (profileUpdateWaiter) profileUpdateWaiter = null; reject(new Error('服务器没有确认保存，请重试。')); }, 5000);
      profileUpdateWaiter = { resolve: (value) => { clearTimeout(timer); resolve(value); } };
    });
    socket.send(JSON.stringify({ type: 'update-profile', alias: profileNameInput.value.trim(), color: profileDraft.color, avatarSeed: profileDraft.avatarSeed, avatarUrl }));
    await confirmed; clearDraftPreview(); profileDraft = null; profileDialog.close();
  } catch (error) { errorEl.textContent = error.message; } finally { save.disabled = false; }
};
profileDialog.addEventListener('close', () => { clearDraftPreview(); profileDraft = null; });
$('#profile-cancel').onclick = () => profileDialog.close();
$('#switch-identity').onclick = async () => {
  profileDialog.close();
  if (authMode === 'account') {
    try { await fetch('/api/auth/logout', { method: 'POST' }); } catch (_) {}
  }
  localStorage.removeItem(AUTH_MODE_KEY); stopChat(); authMode = ''; showChoice();
};

function renderAgentScopeOptions(value) {
  const items = Array.isArray(value && value.groups) ? value.groups : [];
  agentScopeGroups.replaceChildren();
  if (!items.length) { const empty = document.createElement('p'); empty.className = 'scope-empty'; empty.textContent = '请先加入至少一个普通群组或创建一个隐私群。'; agentScopeGroups.append(empty); return; }
  const sections = [
    ['我创建的群组', items.filter((item) => item.ownCreated)],
    ['他人创建的群组', items.filter((item) => !item.ownCreated)],
  ];
  sections.forEach(([title, sectionItems]) => {
    if (!sectionItems.length) return;
    const section = document.createElement('section'); section.className = 'scope-section';
    const heading = document.createElement('h3'); heading.textContent = title; section.append(heading);
    sectionItems.forEach((item) => {
      const label = document.createElement('label'); label.className = 'scope-item';
      const input = document.createElement('input'); input.type = 'checkbox'; input.value = item.id; input.checked = !!item.selected;
      const copy = document.createElement('span'); copy.className = 'scope-item-copy';
      const name = document.createElement('strong'); name.textContent = `${item.isPrivate ? '▣ ' : '# '}${item.name}`;
      const meta = document.createElement('small'); meta.textContent = item.isPrivate ? '隐私群 · 只有你能看到' : item.isOwner ? '已加入' : '已加入 · 他人创建';
      copy.append(name, meta); label.append(input, copy); section.append(label);
    });
    agentScopeGroups.append(section);
  });
}
async function openAgentScope() {
  if (!self || self.identityType !== 'account' || agentScopeLoading) return;
  agentScopeLoading = true; agentScopeError.textContent = ''; agentScopeGroups.innerHTML = '<p class="scope-empty">正在加载群组…</p>'; agentScopeDialog.showModal();
  try {
    const response = await fetch('/api/me/agent-scope'); const value = await response.json();
    if (!response.ok) throw new Error(value.error || '读取 Agent 范围失败。');
    agentScope = value; renderAgentScopeOptions(value);
  } catch (error) { agentScopeError.textContent = error.message; }
  finally { agentScopeLoading = false; }
}
agentScopeButton.onclick = openAgentScope;
$('#agent-scope-cancel').onclick = () => agentScopeDialog.close();
agentScopeForm.onsubmit = async (event) => {
  if (event.submitter && event.submitter.value === 'cancel') { event.preventDefault(); agentScopeDialog.close(); return; }
  event.preventDefault(); if (!agentScope) return;
  agentScopeSave.disabled = true; agentScopeError.textContent = '';
  try {
    const groupIds = [...agentScopeGroups.querySelectorAll('input[type="checkbox"]:checked')].map((input) => input.value);
    const response = await fetch('/api/me/agent-scope', { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ groupIds }) });
    const value = await response.json(); if (!response.ok) throw new Error(value.error || '保存 Agent 范围失败。');
    agentScope = value; agentScopeDialog.close(); showToast('Agent 读取范围已保存。');
  } catch (error) { agentScopeError.textContent = error.message; }
  finally { agentScopeSave.disabled = false; }
};
$('#new-group').onclick = () => { privateGroupInput.checked = false; privateGroupInput.disabled = !self || self.identityType !== 'account'; dialog.showModal(); groupInput.focus(); };
$('#group-cancel').onclick = () => dialog.close();
groupForm.onsubmit = (event) => {
  if (event.submitter && event.submitter.value === 'cancel') { event.preventDefault(); dialog.close(); return; }
  event.preventDefault(); const name = groupInput.value.trim();
  if (name && transmit({ type: 'create-group', name, privateGroup: !!privateGroupInput.checked })) { groupInput.value = ''; privateGroupInput.checked = false; dialog.close(); }
};
groupAction.onclick = () => {
  if (activeGroupId !== 'lobby') transmit({ type: joined(activeGroupId) ? 'leave-group' : 'join-group', groupId: activeGroupId });
};
longTextToggle.onchange = () => {
  const enabled = longTextToggle.checked;
  if (!transmit({ type: 'update-preferences', longMessageAsMarkdown: enabled })) longTextToggle.checked = !enabled;
};

$('#transport-hint').textContent = location.protocol === 'http:' ? '局域网直连 · 明文传输' : 'HTTPS 加密连接';
if (!canRecordInPage()) {
  voiceButton.title = '选择录音文件，添加后点击发送';
  voiceButton.setAttribute('aria-label', '选择录音文件');
  $('#voice-security-hint').hidden = false;
}
fetch('/api/config').then((response) => response.json()).then((config) => {
  if (config.maxUploadBytes) $('#composer-hint').textContent += ` · 单文件上限 ${shortSize(config.maxUploadBytes)}`;
  if (!window.isSecureContext && config.httpsPort) {
    $('#https-link').href = '/secure-setup.html';
    $('#https-link').hidden = false;
  }
  if (location.protocol === 'https:' && config.httpChatAllowed) {
    const httpUrl = new URL(location.href); httpUrl.protocol = 'http:'; httpUrl.pathname = '/'; httpUrl.search = ''; httpUrl.hash = '';
    $('#http-link').href = httpUrl.href; $('#http-link').hidden = false;
  }
}).catch(() => {});
$('#anonymous-button').onclick = chooseAnonymous;
$('#show-login').onclick = () => setAuthPanel('login');
$('#show-register').onclick = () => setAuthPanel('register');
$('#login-back').onclick = showChoice;
$('#register-back').onclick = showChoice;
authLoginForm.onsubmit = (event) => { event.preventDefault(); submitAuth(authLoginForm, '/api/auth/login', $('#login-error')); };
authRegisterForm.onsubmit = (event) => { event.preventDefault(); submitAuth(authRegisterForm, '/api/auth/register', $('#register-error')); };
bootAuth();


function renderDeviceWindow(value) {
  clearInterval(deviceWindowTimer);
  const deadline = performance.now() + Math.max(0, value.expiresAt - value.serverNow);
  function tick() {
    const remaining = Math.max(0, Math.ceil((deadline - performance.now()) / 1000));
    if (!self || self.identityType !== 'account') { clearInterval(deviceWindowTimer); deviceWindowStatus.hidden = true; return; }
    deviceWindowStatus.hidden = false;
    deviceWindowStatus.textContent = remaining ? `新设备可接入：剩余 ${remaining} 秒，登录后会被记住。` : '外网陌生设备默认拒绝。';
    allowDeviceButton.textContent = remaining ? '重新开放 1 分钟' : '允许新设备接入 1 分钟';
    if (!remaining) clearInterval(deviceWindowTimer);
  }
  tick();
  if (value.expiresAt > value.serverNow) deviceWindowTimer = setInterval(tick, 1000);
}
if (allowDeviceButton) allowDeviceButton.onclick = async () => {
  allowDeviceButton.disabled = true;
  try {
    const response = await fetch('/api/access/window', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
    const value = await response.json();
    if (!response.ok) throw new Error(value.error || '无法开放新设备接入。');
    renderDeviceWindow(value);
    showToast('已开放 1 分钟，请让新设备现在打开外网地址并登录。');
  } catch (error) { showToast(error.message, true); }
  finally { allowDeviceButton.disabled = false; }
};
