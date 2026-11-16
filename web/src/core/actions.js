// Delegated click handling for elements rendered with act() (lib/format.js).
// Walks from the click target up to the root and runs every [data-act] on the way,
// the same order and reach inline onclick handlers had when the event bubbled.
document.addEventListener('click', e => {
  for (let el = e.target instanceof Element ? e.target.closest('[data-act]') : null; el; el = el.parentElement && el.parentElement.closest('[data-act]')) {
    const fn = window[el.dataset.act];
    if (typeof fn !== 'function') continue;
    let args = [];
    try { args = JSON.parse(el.dataset.args || '[]'); } catch { /* malformed args: call with none */ }
    fn(...args);
    if (e.cancelBubble) return;
  }
});
