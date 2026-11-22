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
    window.addEventListener('load', reveal, { once: true });
    setTimeout(reveal, 3500);   // never hold the art back longer than this
  }
})();
