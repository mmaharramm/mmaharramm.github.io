---
layout: null
permalink: /sw.js
sitemap: false
---
/* Keeps the site's static files (side art, CSS, JS, fonts) on the device, so a refresh or a repeat
   visit shows the art at once instead of re-checking every image with GitHub Pages, which only
   allows browsers to keep files for 10 minutes. Pages themselves always come from the network.
   One cache per deploy: a new deploy changes this file, the new worker takes over and drops the
   old cache. To switch it off, replace this file with one that calls self.registration.unregister(). */
const V = '{{ site.time | date: "%s" }}';
const CACHE = 'static-' + V;
const ART = [{% for g in site.data.vibe_preload %}{% for f in g.files %}
  '{{ "/images/vibe/" | append: f | relative_url }}?v=' + V,{% endfor %}{% endfor %}
];

self.addEventListener('install', () => self.skipWaiting());

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k.startsWith('static-') && k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET' || req.mode === 'navigate') { return; }
  const url = new URL(req.url);
  if (url.origin !== self.location.origin || !/^\/(assets|images)\//.test(url.pathname)) { return; }
  e.respondWith(
    caches.open(CACHE).then((c) => c.match(req).then((hit) => hit || fetch(req).then((res) => {
      if (res.ok && res.type === 'basic') { c.put(req, res.clone()); }
      return res;
    })))
  );
});

// The page (wide screens only) asks for the whole art set to be stored, then gets the version back
// once every image is in the cache. It remembers that and stops hiding the art on later loads.
self.addEventListener('message', (e) => {
  if (e.data !== 'vibe-precache' || !e.ports[0]) { return; }
  const port = e.ports[0];
  e.waitUntil(
    caches.open(CACHE)
      .then((c) => Promise.all(ART.map((u) => c.match(u).then((hit) => hit || c.add(u)))))
      .then(() => port.postMessage(V), () => port.postMessage(''))
  );
});
