// Side-effect module: modal/drawer focus handling and keyboard access.
// Both blocks are idempotent via window.__overlayA11y / __keyboardClickable.

// ── Shared modal / drawer behaviour ──────────────────────────
// Every `.modal-overlay` and `.finding-drawer` added to the page gets
// role=dialog, aria-modal, Escape to close, a Tab focus trap, and focus
// returned to the element that opened it.
const _overlayStack = [];
let _lastOutsideFocus = null;
const _FOCUSABLE = 'a[href],button:not([disabled]),input:not([disabled]):not([type=hidden]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])';

function _overlayFocusables(dialog) {
  return [...dialog.querySelectorAll(_FOCUSABLE)].filter(el => el.offsetParent !== null);
}

function _registerOverlay(overlay, dialog) {
  if (!dialog || _overlayStack.some(o => o.overlay === overlay)) return;
  dialog.setAttribute('role', 'dialog');
  dialog.setAttribute('aria-modal', 'true');
  if (!dialog.hasAttribute('aria-labelledby') && !dialog.hasAttribute('aria-label')) {
    const heading = dialog.querySelector('h1,h2,h3');
    if (heading) dialog.setAttribute('aria-label', heading.textContent.trim());
  }
  dialog.setAttribute('tabindex', '-1');
  _overlayStack.push({ overlay, dialog, trigger: _lastOutsideFocus });
  (_overlayFocusables(dialog)[0] || dialog).focus({ preventScroll: true });
}

function _closeTopOverlay() {
  const top = _overlayStack[_overlayStack.length - 1];
  if (!top) return;
  // Click runs the overlay's own close handler (drawers clean up state there).
  top.overlay.click();
  if (top.overlay.isConnected) { top.overlay.remove(); top.dialog.remove(); }
}

function _scanOverlays(root) {
  if (root.nodeType !== 1) return;
  if (root.matches('.modal-overlay')) _registerOverlay(root, root.firstElementChild);
  else if (root.matches('.finding-drawer')) _registerOverlay(root.previousElementSibling?.classList.contains('finding-drawer-overlay') ? root.previousElementSibling : root, root);
  else root.querySelectorAll?.('.modal-overlay,.finding-drawer').forEach(_scanOverlays);
}

function _releaseOverlays() {
  while (_overlayStack.length) {
    const top = _overlayStack[_overlayStack.length - 1];
    if (top.dialog.isConnected && top.overlay.isConnected) return;
    _overlayStack.pop();
    if (top.trigger && top.trigger.isConnected && !document.querySelector('.modal-overlay,.finding-drawer')) {
      top.trigger.focus({ preventScroll: true });
    }
  }
}

if (typeof document !== 'undefined' && !window.__overlayA11y) {
  window.__overlayA11y = true;
  document.addEventListener('focusin', e => {
    if (!e.target.closest?.('.modal-overlay,.finding-drawer')) _lastOutsideFocus = e.target;
  });
  new MutationObserver(muts => {
    muts.forEach(m => m.addedNodes.forEach(_scanOverlays));
    _releaseOverlays();
  }).observe(document.body, { childList: true });

  document.addEventListener('keydown', e => {
    const top = _overlayStack[_overlayStack.length - 1];
    if (!top) return;
    if (e.key === 'Escape') { e.preventDefault(); _closeTopOverlay(); return; }
    if (e.key !== 'Tab') return;
    const items = _overlayFocusables(top.dialog);
    if (!items.length) { e.preventDefault(); top.dialog.focus(); return; }
    const first = items[0], last = items[items.length - 1];
    if (!top.dialog.contains(document.activeElement)) { e.preventDefault(); first.focus(); }
    else if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
  });
}

// ── Keyboard access for click-only elements ──────────────────
// Elements wired with onclick on non-interactive tags (rows, cards, spans)
// become focusable and respond to Enter / Space like a button.
const _NATIVE_INTERACTIVE = 'button,input,select,textarea,summary,a[href]';

function _makeKeyboardClickable(root) {
  if (root.nodeType !== 1) return;
  const els = root.matches('[onclick]') ? [root] : [];
  root.querySelectorAll?.('[onclick]').forEach(el => els.push(el));
  els.forEach(el => {
    if (el.matches(_NATIVE_INTERACTIVE) || el.hasAttribute('tabindex')) return;
    el.setAttribute('tabindex', '0');
    if (!el.hasAttribute('role') && !['TR', 'TD', 'TH'].includes(el.tagName)) el.setAttribute('role', 'button');
  });
}

if (typeof document !== 'undefined' && !window.__keyboardClickable) {
  window.__keyboardClickable = true;
  _makeKeyboardClickable(document.body);
  new MutationObserver(muts => muts.forEach(m => m.addedNodes.forEach(_makeKeyboardClickable)))
    .observe(document.body, { childList: true, subtree: true });

  document.addEventListener('keydown', e => {
    if (e.key !== 'Enter' && e.key !== ' ') return;
    const el = e.target;
    if (!el || el !== document.activeElement || !el.matches?.('[onclick][tabindex]') || el.matches(_NATIVE_INTERACTIVE)) return;
    e.preventDefault();
    el.click();
  });
}
