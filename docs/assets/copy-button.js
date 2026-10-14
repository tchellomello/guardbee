// Click-to-copy for guide-page code blocks (the lab walkthrough's
// copy-paste-and-verify steps, and every other guide page's command
// blocks for free). Shared by docs/_layouts/doc.html.
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

  document.querySelectorAll('.docs-page pre').forEach(function (pre) {
    if (pre.closest('.expect')) return; // illustrative output, not a command to run

    // Captured now, before the button exists — and the button is never a
    // child of `pre` (it lives in the wrapper below), so there's no way
    // for its own "Copy"/"Copied" label to end up concatenated onto the
    // copied text, however it's read later.
    var text = pre.textContent;

    var wrapper = document.createElement('div');
    wrapper.className = 'code-block';
    pre.parentNode.insertBefore(wrapper, pre);
    wrapper.appendChild(pre);

    var btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'copy-btn';
    btn.textContent = 'Copy';
    btn.addEventListener('click', function () {
      copyText(text).then(function () {
        btn.textContent = 'Copied';
        btn.classList.add('copied');
        setTimeout(function () {
          btn.textContent = 'Copy';
          btn.classList.remove('copied');
        }, 1500);
      });
    });
    wrapper.appendChild(btn);
  });
})();
