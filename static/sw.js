// Cache immutable public assets only; never store sessions or account APIs.
const CACHE = 'cubetastic-public-__VERSION__';
self.addEventListener('install', event => event.waitUntil(self.skipWaiting()));
self.addEventListener('activate', event => event.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k.startsWith('cubetastic-') && k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim())));
self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);
  if (event.request.method !== 'GET' || url.origin !== location.origin) return;
  const immutable = /^\/assets\/[a-f0-9]{40}\/(js|css|images|fonts|audio)\//.test(url.pathname);
  const timer = url.pathname === '/timer';
  if (!immutable && !timer) return;
  event.respondWith(caches.open(CACHE).then(async cache => {
    const network = async () => {
      const response = await fetch(event.request);
      if (response.ok) await cache.put(event.request, response.clone());
      return response;
    };
    if (immutable) return (await cache.match(event.request)) || network();
    try { return await network(); }
    catch (error) { return (await cache.match(event.request)) || Response.error(); }
  }));
});
