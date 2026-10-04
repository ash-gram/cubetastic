async function submitAccount(event, endpoint) {
  event.preventDefault();
  const form = event.target;
  const button = form.querySelector('button[type="submit"]');
  const status = form.querySelector('[role="status"]');
  button.disabled = true;
  status.textContent = 'Please wait...';
  try {
    const data = Object.fromEntries(new FormData(form));
    if (data.confirmPassword !== undefined && data.password !== data.confirmPassword) throw new Error('Passwords do not match.');
    const result = await account.request(endpoint, data);
    if (result.recovery_code) {
      form.hidden = true;
      const recovery = document.querySelector('#recovery');
      recovery.hidden = false;
      recovery.querySelector('code').textContent = result.recovery_code;
    } else if (endpoint === '/api/profile') {
      status.textContent = 'Profile saved.';
      document.querySelector('#accountName').textContent = data.display_name || data.username;
    } else if (endpoint === '/api/google/unlink') location.href = '/profile';
    else location.href = '/timer';
  } catch (error) { status.textContent = error.message; }
  finally { button.disabled = false; }
}
account.onAuthStateChanged(user => {
  if (location.pathname !== '/profile') return;
  if (!user) { location.replace('/signin'); return; }
  document.querySelector('#accountName').textContent = user.displayName || user.username;
  document.querySelector('#accountEmail').textContent = user.email;
  document.querySelector('#signInBadge').textContent = user.google_linked ? 'Verified with Google' : 'Email and password';
  document.querySelector('#googleConnected').hidden = !user.google_linked;
  document.querySelector('#googleNotConnected').hidden = user.google_linked;
  document.querySelector('#googleEmail').textContent = user.google_email || '';
  document.querySelector('#googleOnlyHint').hidden = user.has_password;
  document.querySelector('#disconnectGoogle').hidden = !user.google_linked || !user.has_password;
  document.querySelector('#passwordSection').hidden = !user.has_password;
  const avatar = document.querySelector('#profileAvatar');
  avatar.textContent = (user.displayName || user.username).slice(0, 1).toUpperCase();
  if (user.picture) {
    const img = document.createElement('img'); img.src = user.picture; img.alt = ''; img.referrerPolicy = 'no-referrer';
    avatar.replaceChildren(img);
  }
  for (const name of ['display_name', 'username', 'phone', 'location', 'bio']) document.querySelector('[name="' + name + '"]').value = user[name] || '';
});

document.addEventListener('click', async event => {
  const link = event.target.closest('a.google-button');
  if (!link) return;
  event.preventDefault();
  await account.ready;
  location.href = link.href;
});
