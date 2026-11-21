const $ = (selector) => document.querySelector(selector);
const loginView = $('#login-view');
const dashboard = $('#dashboard');
const logoutButton = $('#logout');
const profileList = $('#profile-list');
const accountList = $('#account-list');
const groupAdminList = $('#group-admin-list');
let state = null;

function showToast(message, error = false) {
  const toast = document.createElement('div'); toast.className = `toast${error ? ' error' : ''}`; toast.textContent = message;
  $('#toast-region').append(toast); setTimeout(() => toast.remove(), 3800);
}
async function api(url, options = {}) {
  const response = await fetch(url, { ...options, headers: { 'Content-Type': 'application/json', ...(options.headers || {}) } });
  const value = await response.json().catch(() => ({}));
  if (!response.ok) { const error = new Error(value.error || '请求失败。'); error.status = response.status; throw error; }
  return value;
}
function makeAvatar(profile, target) {
  const seed = String(profile.avatarSeed || '00000000').padEnd(8, '0');
  target.style.setProperty('--avatar-color', profile.color || '#547363'); target.replaceChildren();
  if (profile.avatarUrl) { const image = document.createElement('img'); image.src = profile.avatarUrl; image.alt = ''; target.append(image); return; }
  const bits = [...seed].map((char) => parseInt(char, 16)).flatMap((number) => [number & 1, number & 2, number & 4, number & 8]);
  [bits[0], bits[1], bits[0], bits[2], bits[3], bits[2], bits[4], bits[5], bits[4]].forEach((on) => { const cell = document.createElement('span'); if (on) cell.className = 'on'; target.append(cell); });
}
function renderStats() {
  const labels = [['onlineConnections', '在线连接'], ['knownDevices', '已知设备'], ['messages', '消息总数'], ['files', '文件总数']];
  $('#stats').replaceChildren(...labels.map(([key, label]) => {
    const card = document.createElement('article'); card.className = 'stat';
    const name = document.createElement('span'); name.textContent = label;
    const value = document.createElement('strong'); value.textContent = Number(state.stats[key] || 0).toLocaleString('zh-CN');
    card.append(name, value); return card;
  }));
}
function renderProfiles() {
  const query = $('#profile-search').value.trim().toLocaleLowerCase();
  const items = [...state.profiles].sort((a, b) => (b.online - a.online) || a.ip.localeCompare(b.ip)).filter((profile) => !query || profile.ip.toLocaleLowerCase().includes(query) || profile.name.toLocaleLowerCase().includes(query) || (profile.mac || '').includes(query));
  profileList.replaceChildren(); $('#profile-count').textContent = `${state.profiles.length} 个档案`; $('#profile-empty').hidden = !!items.length;
  items.forEach((profile) => {
    const row = $('#profile-template').content.firstElementChild.cloneNode(true); row.dataset.key = profile.key;
    makeAvatar(profile, row.querySelector('.admin-avatar'));
    row.querySelector('.profile-address strong').textContent = profile.ip;
    row.querySelector('.profile-address small').textContent = profile.mac ? `MAC ${profile.mac}` : profile.identityType === 'device' ? '浏览器设备 ID' : 'IP 回退身份';
    const online = row.querySelector('.profile-address span'); online.textContent = profile.online ? `${profile.online} 个连接在线` : '当前离线'; if (profile.online) online.classList.add('online');
    const alias = row.elements.alias; alias.value = profile.alias || '';
    const color = row.elements.color; color.value = profile.color;
    color.oninput = () => { profile.color = color.value; makeAvatar(profile, row.querySelector('.admin-avatar')); };
    row.onsubmit = async (event) => {
      event.preventDefault(); const button = row.querySelector('.save-button'); button.disabled = true;
      try {
        const value = await api('/api/admin/profile', { method: 'PUT', body: JSON.stringify({ key: profile.key, alias: alias.value, color: color.value, avatarSeed: profile.avatarSeed, avatarUrl: profile.avatarUrl || '' }) });
        Object.assign(profile, value.profile); showToast(`已保存 ${profile.ip} 的档案。`);
      } catch (error) { showToast(error.message, true); } finally { button.disabled = false; }
    };
    row.querySelector('.random-button').onclick = async () => {
      const button = row.querySelector('.random-button'); button.disabled = true;
      try {
        const value = await api('/api/admin/profile/randomize', { method: 'POST', body: JSON.stringify({ key: profile.key }) });
        Object.assign(profile, value.profile); color.value = profile.color; makeAvatar(profile, row.querySelector('.admin-avatar')); showToast(`已为 ${profile.ip} 生成新头像。`);
      } catch (error) { showToast(error.message, true); } finally { button.disabled = false; }
    };
    profileList.append(row);
  });
}
function renderAccounts() {
  const accounts = Array.isArray(state.accounts) ? state.accounts : [];
  const groups = Array.isArray(state.groups) ? state.groups : [];
  accountList.replaceChildren(); $('#account-empty').hidden = !!accounts.length;
  accounts.forEach((account) => {
    const row = $('#account-template').content.firstElementChild.cloneNode(true); row.dataset.accountId = account.accountId;
    row.querySelector('.account-copy strong').textContent = account.name || account.username;
    row.querySelector('.account-copy small').textContent = `${account.username} · ${account.online ? `${account.online} 个连接在线` : '当前离线'}`;
    const groupBox = row.querySelector('.account-groups');
    const selected = new Set(account.agentGroupIds || []);
    groups.filter((group) => (account.groups || []).includes(group.id)).forEach((group) => {
      const label = document.createElement('label'); label.className = 'account-group-check';
      const input = document.createElement('input'); input.type = 'checkbox'; input.value = group.id; input.checked = selected.has(group.id);
      const text = document.createElement('span'); text.textContent = group.name;
      label.append(input, text); groupBox.append(label);
    });
    if (!groupBox.children.length) { const empty = document.createElement('small'); empty.className = 'account-no-groups'; empty.textContent = '该账号还没有加入普通群组'; groupBox.append(empty); }
    row.onsubmit = async (event) => {
      event.preventDefault(); const button = row.querySelector('.save-account-button'); button.disabled = true;
      try {
        const groupIds = [...groupBox.querySelectorAll('input:checked')].map((input) => input.value);
        const value = await api(`/api/admin/accounts/${encodeURIComponent(account.accountId)}/agent-scope`, { method: 'PUT', body: JSON.stringify({ groupIds }) });
        account.agentGroupIds = value.selectedGroupIds; showToast(`已保存 ${account.name || account.username} 的 Agent 读取范围。`);
      } catch (error) { showToast(error.message, true); } finally { button.disabled = false; }
    };
    accountList.append(row);
  });
}
function renderGroupAdmin() {
  const groups = (Array.isArray(state.groups) ? state.groups : []).filter((group) => group.id !== 'lobby');
  groupAdminList.replaceChildren(); $('#group-admin-empty').hidden = !!groups.length;
  groups.forEach((group) => {
    const row = $('#group-admin-template').content.firstElementChild.cloneNode(true);
    row.dataset.groupId = group.id;
    row.querySelector('.group-admin-copy strong').textContent = group.name;
    row.querySelector('.group-admin-copy small').textContent = `创建时间 ${group.createdAt ? new Date(group.createdAt).toLocaleString('zh-CN') : '未知'} · 普通群组`;
    row.querySelector('.delete-group-button').onclick = async () => {
      if (!confirm(`确定删除群组「${group.name}」吗？其中消息、附件、成员归属和 Agent 授权都会被清理。`)) return;
      const button = row.querySelector('.delete-group-button'); button.disabled = true;
      try {
        const result = await api(`/api/admin/groups/${encodeURIComponent(group.id)}`, { method: 'DELETE' });
        showToast(`已删除「${result.group.name}」，清理 ${result.removedMessages} 条消息。`);
        await loadState();
      } catch (error) { showToast(error.message, true); button.disabled = false; }
    };
    groupAdminList.append(row);
  });
}
async function loadState() {
  try {
    state = await api('/api/admin/state'); loginView.hidden = true; dashboard.hidden = false; logoutButton.hidden = false; renderStats(); renderProfiles(); renderAccounts(); renderGroupAdmin();
  } catch (error) {
    if (error.status === 401) { loginView.hidden = false; dashboard.hidden = true; logoutButton.hidden = true; return; }
    showToast(error.message, true);
  }
}
$('#login-form').onsubmit = async (event) => {
  event.preventDefault(); const errorEl = $('#login-error'); errorEl.textContent = '';
  try { await api('/api/admin/login', { method: 'POST', body: JSON.stringify({ password: $('#password').value }) }); $('#password').value = ''; await loadState(); }
  catch (error) { errorEl.textContent = error.message; }
};
logoutButton.onclick = async () => { await api('/api/admin/logout', { method: 'POST', body: '{}' }).catch(() => {}); state = null; await loadState(); };
$('#refresh').onclick = loadState;
$('#profile-search').oninput = () => { if (state) renderProfiles(); };
loadState();
