/* ==========================================================================
   Masthead menu
   Which links sit in the bar and which move into the ☰ menu is decided in CSS
   (container query on the masthead, _sass/_custom.scss), so it never depends on
   measuring widths in JS and behaves the same under any page or browser zoom.
   This only opens/closes the ☰ menu and keeps the page clear of the fixed bar.
   ========================================================================== */
(function () {
  var nav = document.getElementById('site-nav');
  if (!nav) { return; }
  var btn = nav.querySelector('.greedy-nav__toggle');
  var menu = nav.querySelector('.hidden-links');

  var setOpen = function (open) {
    if (!btn || !menu) { return; }
    menu.classList.toggle('hidden', !open);
    btn.classList.toggle('close', open);
    btn.setAttribute('aria-expanded', open ? 'true' : 'false');
  };

  if (btn && menu) {
    btn.addEventListener('click', function (e) {
      e.stopPropagation();
      setOpen(menu.classList.contains('hidden'));
    });
    menu.addEventListener('click', function (e) { if (e.target.closest('a')) { setOpen(false); } });
    document.addEventListener('click', function (e) { if (!nav.contains(e.target)) { setOpen(false); } });
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && !menu.classList.contains('hidden')) { setOpen(false); btn.focus(); }
    });
  }

  // Keep the content clear of the fixed masthead, whatever height it ends up at.
  var masthead = document.querySelector('.masthead');
  var pad = function () {
    if (!masthead) { return; }
    var h = masthead.offsetHeight;
    document.body.style.paddingTop = h + 'px';
    var sidebar = document.querySelector('.sidebar');
    var follow = document.querySelector('.author__urls-wrapper button');
    if (sidebar) { sidebar.style.paddingTop = (follow && follow.offsetParent !== null) ? '' : h + 'px'; }
  };
  pad();
  if ('ResizeObserver' in window && masthead) { new ResizeObserver(pad).observe(masthead); }
  window.addEventListener('resize', pad);
})();
