// Click-to-zoom for screenshots (landing page demo images + docs guide images).
// Shared by docs/index.html and docs/_layouts/doc.html.
(function () {
  var overlay = document.createElement('div');
  overlay.className = 'lightbox-overlay';
  var img = document.createElement('img');
  overlay.appendChild(img);
  document.body.appendChild(overlay);

  function open(src, alt) {
    img.src = src;
    img.alt = alt || '';
    overlay.classList.add('active');
  }
  function close() {
    overlay.classList.remove('active');
    img.src = '';
  }

  document.querySelectorAll('.demo-item img, .docs-page img').forEach(function (el) {
    el.classList.add('zoomable');
    el.addEventListener('click', function () { open(el.src, el.alt); });
  });

  overlay.addEventListener('click', close);
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') close();
  });
})();
