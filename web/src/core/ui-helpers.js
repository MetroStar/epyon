// Small DOM helpers used by delegated handlers (see core/actions.js) in place of inline code.
import { navigate } from './router.js';

export function upperAlnumInput(el) {
  el.value = el.value.toUpperCase().replace(/[^A-Z0-9]/g, '');
}

export function upperInput(el) {
  el.value = el.value.toUpperCase();
}

export function closeModalOverlay(el) {
  el.closest('.modal-overlay')?.remove();
}

export function reloadPage() {
  window.location.reload();
}

// Plain left-click on a hash link navigates in-app; modified clicks keep the browser default.
export function spaLinkClick(e, el) {
  if (e.button === 0 && !e.ctrlKey && !e.metaKey && !e.shiftKey) {
    e.preventDefault();
    navigate(el.dataset.href);
  }
}
