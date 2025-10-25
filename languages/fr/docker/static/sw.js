const CACHE_NAME = 'your-app-cache-v3';  // Incremented version
const urlsToCache = [
  '/static/icons/avatar1.png',
  '/static/icons/avatar2.png',
  '/static/icons/avatar3.png',
  '/static/icons/avatar4.png',
  '/static/icons/avatar5.png',
  '/static/icons/avatar6.png',
  '/static/images/bg.jpg',
  '/static/icons/192.png',
  '/static/icons/512.png',
  '/manifest.json'
];

// Pre-cache static assets on install
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(urlsToCache))
  );
});

// Serve cached static assets and allow dynamic or redirected requests
self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);

  // Only handle requests for static assets
  if (urlsToCache.some(asset => url.pathname === asset)) {
    event.respondWith(
      caches.match(event.request)
        .then(cached => cached || fetch(event.request))
    );
  } else {
    // All other requests (including dynamic or redirected ones) are handled by the browser
    event.respondWith(fetch(event.request));
  }
});