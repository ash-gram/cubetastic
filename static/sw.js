// Only public application assets are cached. Never cache sessions or solve APIs.
const CACHE = 'cubetastic-standalone-v1';
const SHELL = ['/timer','/js/main.js','/js/timer.js','/js/loggedStatus.js','/js/tnoodle.js','/js/mdc-web.min.js','/js/nouislider.min.js','/js/vendor/jquery-3.7.1.min.js','/css/main.css','/css/timer.css'];
self.addEventListener('install', event => event.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL)).then(() => self.skipWaiting())));
self.addEventListener('activate', event => event.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim())));
self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);
  if (event.request.method !== 'GET' || url.origin !== location.origin) return;
  const isPublic = url.pathname === '/timer' || /^\/(js|css|images|fonts|audio)\//.test(url.pathname);
  if (!isPublic) return;
  event.respondWith(fetch(event.request).then(response => {
    if (response.ok) { const copy = response.clone(); caches.open(CACHE).then(c => c.put(event.request, copy)); }
    return response;
  }).catch(() => caches.match(event.request)));
});
