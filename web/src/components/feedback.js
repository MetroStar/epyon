// ── Shared toast and confirm components ──────────────────────
// Replace browser alert()/confirm(): themed, non-blocking, and announced to
// screen readers. Errors include a next step.
export function toast(message, kind = 'info') {
  let host = document.getElementById('toast-host');
  if (!host) {
    host = document.createElement('div');
    host.id = 'toast-host';
    host.className = 'toast-host';
    host.setAttribute('role', 'status');
    host.setAttribute('aria-live', 'polite');
    document.body.appendChild(host);
  }
  const el = document.createElement('div');
  el.className = `toast toast-${kind}`;
  if (kind === 'error') el.setAttribute('role', 'alert');
  const text = document.createElement('div');
  text.className = 'toast-text';
  text.textContent = message;
  if (kind === 'error') {
    const hint = document.createElement('div');
    hint.className = 'toast-hint';
    hint.textContent = 'Try again. If it keeps failing, check the Epyon server log.';
    text.appendChild(hint);
  }
  const close = document.createElement('button');
  close.className = 'toast-close';
  close.setAttribute('aria-label', 'Dismiss');
  close.textContent = '\u2715';
  const dismiss = () => el.remove();
  close.addEventListener('click', dismiss);
  el.append(text, close);
  host.appendChild(el);
  setTimeout(dismiss, kind === 'error' ? 10000 : 6000);
}

export function confirmDialog({ title, body, confirmLabel = 'Confirm', cancelLabel = 'Cancel', danger = true }) {
  return new Promise(resolve => {
    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay';
    overlay.innerHTML = `
      <div class="modal-box" aria-labelledby="confirm-title">
        <h2 style="${danger ? '' : 'color:var(--text)'}"><span id="confirm-title"></span></h2>
        <p class="confirm-body"></p>
        <div class="modal-actions">
          <button class="btn" data-act="cancel"></button>
          <button class="btn ${danger ? 'btn-danger' : 'btn-primary'}" data-act="ok"></button>
        </div>
      </div>`;
    overlay.querySelector('#confirm-title').textContent = title;
    overlay.querySelector('.confirm-body').textContent = body;
    overlay.querySelector('[data-act=cancel]').textContent = cancelLabel;
    overlay.querySelector('[data-act=ok]').textContent = confirmLabel;
    let done = false;
    const finish = value => { if (done) return; done = true; overlay.remove(); resolve(value); };
    overlay.addEventListener('click', e => {
      if (e.target === overlay || e.target.dataset?.act === 'cancel') finish(false);
      else if (e.target.dataset?.act === 'ok') finish(true);
    });
    document.body.appendChild(overlay);
  });
}
