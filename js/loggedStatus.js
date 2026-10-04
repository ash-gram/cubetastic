account.onAuthStateChanged(function(user) {
  const header = document.querySelector('#profileLinkInHeader');
  const menu = document.querySelector('#sideMenu .mdc-list:last-child');
  if (header) header.innerHTML = user
    ? '<a href="/profile" class="material-icons mdc-top-app-bar__action-item" aria-label="Profile">account_circle</a>'
    : '<a href="/signin" class="material-icons mdc-top-app-bar__action-item" aria-label="Sign in">account_circle</a>';
  if (menu) menu.innerHTML = user
    ? '<a href="/profile" class="mdc-list-item">Profile</a><a href="#" class="mdc-list-item" onclick="signOutUser();return false">Sign out</a>'
    : '<a href="/signin" class="mdc-list-item">Sign in</a><a href="/signup" class="mdc-list-item">Sign up</a>';
});
