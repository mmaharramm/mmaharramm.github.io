/* Runs in <head>, before the stylesheet paints anything.
   1. Apply the saved theme right away so a reload never flashes the light theme
      before switching to dark. (Same rule as setTheme() in _main.js: saved choice, otherwise light.)
   2. Side art (wide screens only): keep it hidden until its ~50 images have arrived,
      then fade it in, instead of the gutters popping in piece by piece. */
(function () {
  var root = document.documentElement;
  try {
    if (localStorage.getItem('theme') === 'dark') root.setAttribute('data-theme', 'dark');
  } catch (e) { /* storage blocked: stay on the light default */ }

  // Steady desktop scale: the site renders at 90% on mouse/trackpad screens, and browser zoom
  // (Cmd/Ctrl +/-) is mostly cancelled out, so it only nudges the size (200% zoom ~ 11% bigger).
  // Zoom level = outerWidth / innerWidth, snapped to the browser's zoom steps and accepted only
  // when devicePixelRatio agrees (so a docked DevTools panel is not mistaken for zoom).
  // Browsers where this cannot be read (e.g. Firefox) simply keep normal zoom.
  var fine = window.matchMedia && window.matchMedia('(hover: hover) and (pointer: fine)').matches;
  if (fine && (window.screen && screen.width >= 1024)) {
    var steps = [0.25, 0.33, 0.5, 0.67, 0.75, 0.8, 0.9, 1, 1.1, 1.25, 1.5, 1.75, 2, 2.5, 3, 4, 5];
    var bases = [1, 1.25, 1.5, 1.75, 2, 2.25, 2.5, 3];
    var near = function (v, list, tol) {
      for (var i = 0; i < list.length; i++) { if (Math.abs(v / list[i] - 1) <= tol) { return list[i]; } }
      return 0;
    };
    var steady = function () {
      var z = 1, r = window.outerWidth / window.innerWidth;
      if (isFinite(r) && r > 0) {
        var s = near(r, steps, 0.03);
        if (s && s !== 1 && near((window.devicePixelRatio || 1) / s, bases, 0.04)) { z = s; }
      }
      root.style.zoom = z === 1 ? '' : (0.9 * Math.pow(z, -0.85)).toFixed(4);
    };
    steady();
    window.addEventListener('resize', steady);
  }

  // Only pages wide enough to have gutters show the art (the CSS decides exactly, by laid-out
  // width); this rough gate just avoids holding back a layer that will not appear anyway.
  // 1296 = 1440 x 0.9, the narrowest window that can lay out 1440px at the desktop 90% zoom.
  var wide = (window.innerWidth || 0) >= 1296;
  if (wide) {
    root.classList.add('vibe-wait');
    var shown = false;
    var reveal = function () {
      if (shown) { return; }
      shown = true;
      root.classList.remove('vibe-wait');
    };
    // Wait only for the images the visible pieces use (not the whole page's load event, which also
    // waits for certificate scans and the like). They are already downloading: head.html preloads them.
    var waitArt = function () {
      var layer = document.querySelector('.vibe-layer');
      if (!layer) { reveal(); return; }
      var urls = {}, els = layer.querySelectorAll('*');
      for (var i = 0; i < els.length; i++) {
        if (!els[i].getClientRects().length) { continue; }       // hidden at this width
        var cs = getComputedStyle(els[i]);
        String(cs.webkitMaskImage || cs.maskImage || '').replace(/url\("?([^")]+)"?\)/g, function (m, u) { urls[u] = 1; });
      }
      var list = Object.keys(urls), left = list.length;
      if (!left) { reveal(); return; }
      var done = function () { if (--left === 0) { reveal(); } };
      list.forEach(function (u) {
        var im = new Image();
        im.crossOrigin = 'anonymous';                               // same request mode as the CSS masks
        im.onload = im.onerror = done;
        im.src = u;
      });
    };
    var start = function () {
      // the stylesheet must be applied before the pieces can be measured
      var css = document.querySelector('link[rel="stylesheet"][href*="main.css"]');
      if (css && !css.sheet) { css.addEventListener('load', waitArt, { once: true }); css.addEventListener('error', reveal, { once: true }); }
      else { waitArt(); }
    };
    if (document.readyState === 'loading') { document.addEventListener('DOMContentLoaded', start, { once: true }); } else { start(); }
    window.addEventListener('load', reveal, { once: true });
    setTimeout(reveal, 3500);   // never hold the art back longer than this
  }
})();
