// Guide-page chrome: the "On this page" outline and the phone menu.
(function () {
  var page = document.querySelector('.docs-page');
  var toc = document.querySelector('.doc-toc');

  // Outline built from the page's own h2/h3 (kramdown gives every heading
  // an id). Skipped on short pages, where it would only repeat the title.
  if (page && toc) {
    var heads = Array.prototype.filter.call(
      page.querySelectorAll('h2[id], h3[id]'),
      function (h) { return !h.closest('details, .expect, .pager'); }
    );
    if (heads.length >= 3) {
      var title = document.createElement('p');
      title.className = 'doc-toc-title';
      title.textContent = 'On this page';
      var list = document.createElement('ul');
      var links = {};
      heads.forEach(function (h) {
        var li = document.createElement('li');
        if (h.tagName === 'H3') li.className = 'toc-sub';
        var a = document.createElement('a');
        a.href = '#' + h.id;
        a.textContent = h.textContent;
        li.appendChild(a);
        list.appendChild(li);
        links[h.id] = a;
      });
      toc.appendChild(title);
      toc.appendChild(list);
      toc.classList.add('has-items');

      // Highlight the last heading that has scrolled past the top bar.
      var active = null;
      var update = function () {
        var current = heads[0];
        for (var i = 0; i < heads.length; i++) {
          if (heads[i].getBoundingClientRect().top <= 120) current = heads[i];
          else break;
        }
        if (current === active) return;
        if (active) links[active.id].classList.remove('active');
        links[current.id].classList.add('active');
        active = current;
      };
      var ticking = false;
      window.addEventListener('scroll', function () {
        if (ticking) return;
        ticking = true;
        requestAnimationFrame(function () { ticking = false; update(); });
      }, { passive: true });
      update();
    }
  }

  // Each table scrolls sideways inside its own box when it is wider than
  // the text column, instead of overflowing the page.
  if (page) {
    page.querySelectorAll('table').forEach(function (table) {
      if (table.parentElement.classList.contains('table-wrap')) return;
      var wrap = document.createElement('div');
      wrap.className = 'table-wrap';
      table.parentNode.insertBefore(wrap, table);
      wrap.appendChild(table);
    });
  }

  // Phone/tablet: the sidebar folds behind the header's menu button.
  var btn = document.querySelector('.menu-toggle');
  var sidebar = document.getElementById('doc-sidebar');
  if (btn && sidebar) {
    var setOpen = function (open) {
      document.body.classList.toggle('menu-open', open);
      btn.setAttribute('aria-expanded', open ? 'true' : 'false');
      btn.setAttribute('aria-label', open ? 'Hide page list' : 'Show page list');
    };
    btn.addEventListener('click', function () {
      setOpen(!document.body.classList.contains('menu-open'));
    });
    sidebar.addEventListener('click', function (e) {
      if (e.target.closest('a')) setOpen(false);
    });
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape') setOpen(false);
    });
  }
})();
