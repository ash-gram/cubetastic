/* Same-origin session and snapshot client for the existing timer UI. */
window.account = {currentUser: null, csrf: '', callbacks: [],
  onAuthStateChanged(callback) { this.ready.then(() => callback(this.currentUser)); },
  async request(path, data) {
    await this.ready;
    const response = await fetch(path, {method: data === undefined ? 'GET' : 'POST',
      credentials: 'same-origin', cache: 'no-store',
      headers: {'Content-Type': 'application/json', 'X-CSRF-Token': this.csrf},
      body: data === undefined ? undefined : JSON.stringify(data)});
    const value = await response.json();
    if (!response.ok) throw new Error(value.error || 'Request failed. Please retry.');
    return value;
  }
};
account.ready = Promise.all([
  fetch('/api/session', {cache: 'no-store'}).then(r => {
    if (!r.ok) throw new Error('Session unavailable');
    return r.json();
  }).catch(() => ({user: null, csrf: ''})),
  new Promise(resolve => document.readyState === 'loading' ? document.addEventListener('DOMContentLoaded', resolve, {once: true}) : resolve())
]).then(([data]) => {
  account.csrf = data.csrf;
  // Session names and display preferences are device-local, separated by account.
  const owner = data.user ? data.user.uid : 'guest';
  const previous = localStorage.getItem('cubetastic.preferencesOwner');
  if (previous && previous !== owner) {
    for (const key of ['sessionNames', 'noOfSessions', 'settings', 'selectedSession', 'selectedCategory']) {
      const oldValue = localStorage.getItem(key);
      if (oldValue !== null) localStorage.setItem('cubetastic.' + previous + '.' + key, oldValue);
      const nextValue = localStorage.getItem('cubetastic.' + owner + '.' + key);
      if (nextValue === null) localStorage.removeItem(key); else localStorage.setItem(key, nextValue);
    }
    localStorage.setItem('cubetastic.preferencesOwner', owner);
    location.reload();
    return new Promise(() => {});
  }
  localStorage.setItem('cubetastic.preferencesOwner', owner);
  account.currentUser = data.user;
});

const stateListeners = new Map();
let cachedState = {}, statePromise = null, stateETag = null, stateDirty = false;
function snapshot(value, key) {
  return {key, val: () => value === undefined ? null : value,
    child: name => snapshot(value && value[name], name),
    hasChildren: () => !!value && Object.keys(value).length > 0,
    numChildren: () => value ? Object.keys(value).length : 0,
    forEach: callback => Object.entries(value || {}).some(([k, v]) => callback(snapshot(v, k)) === true)};
}
function readState(path, limit, end) {
  let value = path.split('/').filter(Boolean).reduce((v, key) => v && v[key], cachedState);
  if (value && (limit || end)) {
    let entries = Object.entries(value).sort(([a], [b]) => a.localeCompare(b));
    if (end) entries = entries.filter(([key]) => key <= end);
    if (limit) entries = entries.slice(-limit);
    value = Object.fromEntries(entries);
  }
  return snapshot(value, path.split('/').pop());
}
async function refreshState(force = false) {
  if (!account.currentUser) return;
  if (statePromise) { if (force) stateDirty = true; return statePromise; }
  statePromise = fetch('/api/state', {cache: 'no-store', credentials: 'same-origin',
    headers: stateETag ? {'If-None-Match': stateETag} : {}}).then(async response => {
    if (response.status === 304) return;
    if (!response.ok) throw new Error('Could not sync your solves. Please retry.');
    const state = await response.json();
    stateETag = response.headers.get('ETag');
    cachedState = state;
    for (const listener of [...stateListeners.values()]) listener();
  }).catch(error => {
    if (typeof snackbar !== 'undefined') snackbar.show({message: error.message});
  }).finally(() => {
    statePromise = null;
    if (stateDirty) { stateDirty = false; refreshState(); }
  });
  return statePromise;
}
window.solveStore = {ref(path) {
  const query = {path, limit: null, end: null,
    orderByKey() { return this; }, limitToLast(n) { this.limit = n; return this; },
    endAt(key) { this.end = key; return this; },
    async once(event, callback) {
      await account.ready;
      if (!Object.keys(cachedState).length) await refreshState();
      const value = readState(this.path, this.limit, this.end);
      if (event === 'child_added') {
        const entries = Object.entries(value.val() || {});
        if (entries.length) callback(snapshot(entries[entries.length - 1][1], entries[entries.length - 1][0]));
      } else callback(value);
      return value;
    },
    on(event, callback) {
      const key = this.path + ':' + this.limit + ':' + this.end;
      // A new session view replaces old session subscriptions.
      if (this.path.includes('/times/') && !this.end) {
        for (const oldKey of stateListeners.keys()) if (oldKey.includes('/times/')) stateListeners.delete(oldKey);
      }
      let previous;
      const listener = () => {
        const value = readState(this.path, this.limit, this.end);
        const encoded = JSON.stringify(value.val());
        if (encoded !== previous) { previous = encoded; callback(value); }
      };
      stateListeners.set(key, listener);
      account.ready.then(() => Object.keys(cachedState).length ? listener() : refreshState());
      return callback;
    }
  };
  return query;
}};
function syncVisibleTimer() {
  if (!document.hidden && stateListeners.size && !window.timerRunning) refreshState();
}
setInterval(syncVisibleTimer, 30000);
window.addEventListener('focus', syncVisibleTimer);
document.addEventListener('visibilitychange', syncVisibleTimer);
$.ajaxPrefilter(function(options, original, xhr) {
  if (!options.crossDomain && !/^(GET|HEAD|OPTIONS)$/i.test(options.type)) xhr.setRequestHeader('X-CSRF-Token', account.csrf);
});
$(document).ajaxSuccess((event, xhr, settings) => {
  if (settings.type === 'POST' && stateListeners.size) refreshState(true);
});
$(document).ajaxError((event, xhr) => {
  const message = xhr.responseJSON?.error || 'Could not save. Check your connection and retry.';
  if (typeof snackbar !== 'undefined') snackbar.show({message});
});
async function signOutUser() {
  try { await account.request('/api/logout', {}); location.href = '/signin'; }
  catch (error) { alert(error.message); }
}
