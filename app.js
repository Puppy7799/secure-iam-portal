const state = { csrf: null, user: null, register: false };

const byId = (id) => document.getElementById(id);
const authView = byId('auth-view');
const dashboardView = byId('dashboard-view');
const authForm = byId('auth-form');

function showMessage(element, text, success = false) {
  element.textContent = text;
  element.classList.toggle('success', success);
  element.hidden = false;
}

function clearMessage(element) {
  element.textContent = '';
  element.classList.remove('success');
  element.hidden = true;
}

async function request(path, method = 'GET', body = undefined) {
  const headers = {};
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (method !== 'GET') headers['X-CSRF-Token'] = state.csrf || '';
  const response = await fetch(path, {
    method,
    headers,
    credentials: 'same-origin',
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let data;
  try {
    data = await response.json();
  } catch {
    throw new Error('The server returned an unexpected response.');
  }
  if (!response.ok) throw new Error(data.error || 'Something went wrong. Please try again.');
  return data;
}

function setAuthMode(register) {
  state.register = register;
  byId('login-tab').classList.toggle('active', !register);
  byId('register-tab').classList.toggle('active', register);
  byId('login-tab').setAttribute('aria-selected', String(!register));
  byId('register-tab').setAttribute('aria-selected', String(register));
  byId('name-field').hidden = !register;
  byId('confirm-field').hidden = !register;
  byId('display-name').required = register;
  byId('confirm-password').required = register;
  byId('password').autocomplete = register ? 'new-password' : 'current-password';
  byId('password-hint').hidden = register;
  byId('password-strength').hidden = !register || !byId('password').value;
  updatePasswordStrength();
  byId('auth-eyebrow').textContent = register ? 'A GOOD PLACE TO START' : 'WELCOME BACK';
  byId('auth-heading').textContent = register ? 'Create your account' : 'Sign in to your account';
  byId('auth-description').textContent = register ? 'Join your workspace in just a moment.' : 'Your workspace is ready when you are.';
  byId('submit-label').textContent = register ? 'Create secure account' : 'Sign in securely';
  clearMessage(byId('auth-message'));
}

function updatePasswordStrength() {
  const password = byId('password').value;
  const track = document.querySelector('.strength-track');
  let score = 0;
  if (password.length >= 12) score += 1;
  if (password.length >= 16) score += 1;
  if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score += 1;
  if (/\d/.test(password) || /[^A-Za-z0-9]/.test(password)) score += 1;
  const labels = ['Use at least 12 characters', 'Needs work', 'Fair', 'Good', 'Strong'];
  track.dataset.strength = String(score);
  track.setAttribute('aria-valuenow', String(score));
  byId('strength-label').textContent = labels[score];
  byId('password-strength').hidden = !state.register || !password;
}

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function statCard(label, value, icon) {
  const card = element('div', 'stat-card');
  card.append(element('span', 'stat-label', label));
  const valueRow = element('div', 'stat-value');
  valueRow.append(element('span', 'stat-icon', icon), element('span', '', value));
  card.append(valueRow);
  return card;
}

function profileLine(label, value) {
  const line = element('div', 'profile-line');
  line.append(element('span', '', label), element('strong', '', value));
  return line;
}

function renderProfile(user, dashboard) {
  const stats = byId('account-stats');
  stats.replaceChildren(
    statCard('CURRENT ROLE', user.role, '◈'),
    statCard('PERMISSIONS', String(dashboard.permissions.length), '✳'),
    statCard('ACTIVE SESSIONS', String(dashboard.active_sessions), '◉'),
    statCard('TOTAL MEMBERS', Number(dashboard.total_users).toLocaleString(), '◎'),
  );
  byId('welcome-heading').textContent = `Welcome back, ${user.display_name}`;
  const profile = byId('profile-details');
  profile.replaceChildren(
    profileLine('Name', user.display_name),
    profileLine('Email', user.email),
    profileLine('Role', user.role),
    profileLine('Member since', new Date(user.created_at).toLocaleDateString()),
  );
  const list = byId('permission-list');
  list.replaceChildren(...dashboard.permissions.map((permission) => element('li', '', permission)));
  byId('admin-panel').hidden = !user.permissions.includes('users:read');
  byId('topbar-status').textContent = 'Signed in to your secure workspace';
}

async function loadMemberCount() {
  const label = byId('member-count-value');
  try {
    const stats = await request('/api/public/stats');
    const count = Number(stats.total_users);
    label.textContent = count.toLocaleString();
  } catch {
    label.textContent = 'Unavailable';
  }
}

async function renderAdmin() {
  const [usersData, rolesData] = await Promise.all([
    request('/api/admin/users'),
    request('/api/admin/roles'),
  ]);
  const roles = rolesData.roles;
  const roleSummary = byId('role-summary');
  roleSummary.replaceChildren(...roles.map((role) => {
    const chip = element('span', 'role-chip', `${role.name} · ${role.permissions.length} permissions`);
    chip.title = role.permissions.join(', ');
    return chip;
  }));
  const rows = byId('user-rows');
  rows.replaceChildren();
  for (const user of usersData.users) {
    const row = document.createElement('tr');
    const person = document.createElement('td');
    const personInfo = element('div', 'person-cell');
    personInfo.append(element('strong', '', user.display_name), element('span', '', user.email));
    person.append(personInfo);
    const roleCell = document.createElement('td');
    if (user.id === state.user.id || !state.user.permissions.includes('users:manage')) {
      roleCell.append(element('span', 'access-pill', user.role));
    } else {
      const select = element('select', 'role-select');
      select.setAttribute('aria-label', `Role for ${user.email}`);
      for (const role of roles) {
        const option = document.createElement('option');
        option.value = role.name;
        option.textContent = role.name;
        option.selected = role.name === user.role;
        select.append(option);
      }
      select.addEventListener('change', async () => {
        clearMessage(byId('admin-message'));
        select.disabled = true;
        try {
          await request(`/api/admin/users/${user.id}/role`, 'PATCH', { role: select.value });
          showMessage(byId('admin-message'), `Updated ${user.display_name}'s role.`, true);
          await refreshDashboard();
        } catch (error) {
          showMessage(byId('admin-message'), error.message);
          select.value = user.role;
          select.disabled = false;
        }
      });
      roleCell.append(select);
    }
    const joined = document.createElement('td');
    joined.textContent = new Date(user.created_at).toLocaleDateString();
    const access = document.createElement('td');
    access.append(element('span', 'access-pill', `${roles.find((role) => role.name === user.role)?.permissions.length || 0} permissions`));
    row.append(person, roleCell, joined, access);
    rows.append(row);
  }
}

async function refreshDashboard() {
  const session = await request('/api/session');
  if (!session.authenticated) {
    state.user = null;
    state.csrf = session.csrf_token;
    await initialize();
    return;
  }
  state.user = session.user;
  state.csrf = session.csrf_token;
  const dashboard = await request('/api/dashboard');
  renderProfile(state.user, dashboard);
  if (state.user.permissions.includes('users:read')) await renderAdmin();
  byId('logout-button').hidden = false;
}

function showDashboard(user, csrf) {
  state.user = user;
  state.csrf = csrf || state.csrf;
  authView.hidden = true;
  dashboardView.hidden = false;
  byId('logout-button').hidden = false;
  byId('password-panel').hidden = true;
  byId('topbar-status').textContent = 'Signed in to your secure workspace';
  loadMemberCount();
  refreshDashboard().catch((error) => {
    showMessage(byId('dashboard-message'), error.message);
  });
}

async function initialize() {
  loadMemberCount();
  try {
    const data = await request('/api/session');
    if (data.authenticated) showDashboard(data.user, data.csrf_token);
    else {
      state.csrf = data.csrf_token;
      state.user = null;
      authView.hidden = false;
      dashboardView.hidden = true;
      byId('logout-button').hidden = true;
      byId('topbar-status').textContent = 'Your secure workspace';
    }
  } catch (error) {
    showMessage(byId('auth-message'), error.message);
  }
}

byId('login-tab').addEventListener('click', () => setAuthMode(false));
byId('register-tab').addEventListener('click', () => setAuthMode(true));
byId('password').addEventListener('input', updatePasswordStrength);
document.querySelectorAll('[data-toggle-password]').forEach((button) => {
  button.addEventListener('click', () => {
    const input = byId(button.getAttribute('aria-controls'));
    const visible = input.type === 'password';
    input.type = visible ? 'text' : 'password';
    button.textContent = visible ? 'Hide' : 'Show';
    button.setAttribute('aria-label', `${visible ? 'Hide' : 'Show'} password`);
    button.setAttribute('aria-pressed', String(visible));
  });
});

authForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  clearMessage(byId('auth-message'));
  const submit = byId('submit-auth');
  submit.disabled = true;
  const form = new FormData(authForm);
  const data = {
    email: String(form.get('email')).trim(),
    password: String(form.get('password')),
  };
  if (state.register) {
    data.display_name = String(form.get('display_name')).trim();
    if (data.password !== form.get('confirm_password')) {
      showMessage(byId('auth-message'), 'Your passwords do not match.');
      submit.disabled = false;
      return;
    }
  }
  try {
    const result = await request(state.register ? '/api/auth/register' : '/api/auth/login', 'POST', data);
    authForm.reset();
    showDashboard(result.user, result.csrf_token);
  } catch (error) {
    showMessage(byId('auth-message'), error.message);
  } finally {
    submit.disabled = false;
  }
});

byId('change-password-button').addEventListener('click', () => {
  byId('password-panel').hidden = false;
  byId('current-password').focus();
});
byId('close-password-button').addEventListener('click', () => {
  byId('password-panel').hidden = true;
  byId('password-form').reset();
  clearMessage(byId('password-message'));
});

byId('password-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  clearMessage(byId('password-message'));
  const form = new FormData(event.currentTarget);
  const current = String(form.get('current_password'));
  const next = String(form.get('new_password'));
  if (next !== form.get('confirm_new_password')) {
    showMessage(byId('password-message'), 'Your new passwords do not match.');
    return;
  }
  try {
    const result = await request('/api/auth/change-password', 'POST', {
      current_password: current,
      new_password: next,
    });
    state.csrf = result.csrf_token;
    byId('password-form').reset();
    byId('password-panel').hidden = true;
    showMessage(byId('dashboard-message'), result.message, true);
    await refreshDashboard();
  } catch (error) {
    showMessage(byId('password-message'), error.message);
  }
});

byId('logout-button').addEventListener('click', async () => {
  if (!state.user || !window.confirm('Sign out of this account?')) return;
  try {
    await request('/api/auth/logout', 'POST', {});
    state.user = null;
    state.csrf = null;
    byId('password-panel').hidden = true;
    await initialize();
    authForm.reset();
    setAuthMode(false);
  } catch (error) {
    showMessage(byId('dashboard-message'), error.message);
  }
});

initialize();
