// Light/dark theme toggle for the landing page and the guide. The inline
// <head> script has already set data-theme before first paint; this only
// handles the button and OS changes. Mirrors ui/src/theme.tsx: same
// 'cilium-theme' key and values, and the OS preference keeps applying
// until the reader picks a theme explicitly.
(function () {
  var KEY = 'cilium-theme';
  var root = document.documentElement;

  function saved() {
    try {
      var t = localStorage.getItem(KEY);
      return t === 'light' || t === 'dark' ? t : null;
    } catch (e) {
      return null;
    }
  }

  function apply(theme) {
    root.setAttribute('data-theme', theme);
  }

  document.querySelectorAll('.theme-toggle').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var next = root.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
      apply(next);
      try { localStorage.setItem(KEY, next); } catch (e) {}
    });
  });

  var mq = window.matchMedia('(prefers-color-scheme: light)');
  var onChange = function (e) {
    if (!saved()) apply(e.matches ? 'light' : 'dark');
  };
  if (mq.addEventListener) mq.addEventListener('change', onChange);
  else if (mq.addListener) mq.addListener(onChange);
})();
