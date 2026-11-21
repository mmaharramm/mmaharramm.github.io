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

  // Desktop mouse/trackpad browsers render at 90% (html { zoom: 0.9 }), so the art shows from 1296px there.
  var mm = window.matchMedia && window.matchMedia.bind(window);
  var wide = mm && (mm('(hover: hover) and (pointer: fine)').matches ? mm('(min-width: 1296px)') : mm('(min-width: 1440px)')).matches;
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
