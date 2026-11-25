// Direct-link support for embedded showcase videos:
// - Adds a one-click "Copy link" button to every .demo-player-bar that has a
//   target anchor (data-anchor or its enclosing [id] section), so readers can
//   share a URL that lands straight on that video player.
// - On direct hash navigation (e.g. #demo, #zero-trust, #video), immediately
//   reveals any .reveal blocks in the target section so the player is visible
//   without waiting for a scroll event.
(function () {
  function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text);
    }
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    return Promise.resolve();
  }

  document.querySelectorAll('.demo-player').forEach(function (player) {
    var bar = player.querySelector('.demo-player-bar');
    if (!bar) return;

    var anchor = player.getAttribute('data-anchor') || player.id;
    if (!anchor) {
      var host = player.closest('[id]');
      if (host) anchor = host.id;
    }
    if (!anchor) return;

    var btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'demo-player-copy';
    btn.textContent = 'Copy link';
    btn.title = 'Copy a direct link to this video';
    btn.addEventListener('click', function () {
      var url = window.location.origin + window.location.pathname + '#' + anchor;
      if (history.replaceState) {
        try { history.replaceState(null, '', '#' + anchor); } catch (e) {}
      }
      copyText(url).then(function () {
        btn.textContent = 'Link copied';
        btn.classList.add('copied');
        setTimeout(function () {
          btn.textContent = 'Copy link';
          btn.classList.remove('copied');
        }, 1600);
      });
    });
    bar.appendChild(btn);
  });

  function focusHashTarget() {
    var hash = window.location.hash;
    if (!hash || hash.length < 2) return;
    var target = document.getElementById(hash.slice(1));
    if (!target) return;
    target.querySelectorAll('.reveal').forEach(function (el) {
      el.classList.add('is-visible');
    });
    if (target.classList.contains('reveal')) {
      target.classList.add('is-visible');
    }
    target.scrollIntoView({ behavior: 'auto', block: 'start' });
  }

  if (window.location.hash) {
    window.addEventListener('load', focusHashTarget);
    focusHashTarget();
  }
})();
