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
    } else if (endpoint === '/api/profile') status.textContent = 'Profile saved.';
    else location.href = '/timer';
  } catch (error) { status.textContent = error.message; }
  finally { button.disabled = false; }
}
account.onAuthStateChanged(user => {
  if (location.pathname !== '/profile') return;
  if (!user) { location.replace('/signin'); return; }
  document.querySelector('#accountName').textContent = user.username;
  document.querySelector('#accountEmail').textContent = user.email;
  for (const name of ['phone', 'location', 'bio']) document.querySelector('[name="' + name + '"]').value = user[name] || '';
});
