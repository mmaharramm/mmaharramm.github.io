---
layout: null
permalink: /sw.js
sitemap: false
---
/* Retired. An earlier version of the site installed a service worker here; this one removes itself
   and its cache from any device that still has it. Safe to delete this file after a few months. */
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k.startsWith('static-')).map((k) => caches.delete(k))))
      .then(() => self.registration.unregister())
  );
});
