/* Runs in <head>, before the stylesheet paints anything: apply the saved theme
   right away so a reload never flashes the light theme before switching to dark.
   (Same rule as setTheme() in _main.js: saved choice, otherwise light.) */
(function () {
  try {
    if (localStorage.getItem('theme') === 'dark') document.documentElement.setAttribute('data-theme', 'dark');
  } catch (e) { /* storage blocked: stay on the light default */ }
})();
