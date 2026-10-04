self.addEventListener('activate', e => e.waitUntil(self.registration.unregister()));
