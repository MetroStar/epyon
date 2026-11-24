// Themed dropdown that replaces the browser's native <select> popup.
//
// Every <select> is upgraded in place: the native element stays in the DOM
// (hidden) as the source of truth, so `.value`, `change` events, option updates
// and delegated handlers keep working unchanged. Add `data-native` to opt out.
const ENHANCED = new WeakMap();
const valueDesc = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value');
let open = null;

function optionsOf(sel) {
  const out = [];
  for (const node of sel.children) {
    if (node.tagName === 'OPTGROUP') {
      out.push({ group: node.label });
      for (const o of node.children) out.push({ o, indent: true });
    } else if (node.tagName === 'OPTION') out.push({ o: node });
  }
  return out;
}

function selectedLabel(sel) {
  const o = sel.options[sel.selectedIndex];
  return o ? o.textContent.trim() : '';
}

function closeMenu() {
  if (!open) return;
  open.menu.remove();
  open.btn.setAttribute('aria-expanded', 'false');
  open = null;
}

function sync(sel) {
  const st = ENHANCED.get(sel);
  if (!st) return;
  const label = selectedLabel(sel);
  st.text.textContent = label || '\u00a0';
  st.btn.classList.toggle('cs-placeholder', !sel.value);
  st.btn.disabled = sel.disabled;
  st.wrap.hidden = sel.style.display === 'none' || sel.hidden;
  if (open && open.sel === sel) renderItems(open);
}

function renderItems(ctx) {
  const { sel, menu } = ctx;
  menu.innerHTML = '';
  ctx.items = [];
  for (const entry of optionsOf(sel)) {
    if (entry.group !== undefined) {
      const g = document.createElement('div');
      g.className = 'cs-group';
      g.textContent = entry.group;
      menu.appendChild(g);
      continue;
    }
    const item = document.createElement('div');
    item.className = 'cs-item' + (entry.indent ? ' cs-indent' : '');
    item.setAttribute('role', 'option');
    item.textContent = entry.o.textContent.trim() || '\u00a0';
    if (entry.o.selected) { item.classList.add('cs-selected'); item.setAttribute('aria-selected', 'true'); }
    if (entry.o.disabled) item.classList.add('cs-disabled');
    item._opt = entry.o;
    menu.appendChild(item);
    ctx.items.push(item);
  }
  setActive(ctx, ctx.items.findIndex(i => i._opt.selected));
}

function setActive(ctx, idx) {
  ctx.items.forEach(i => i.classList.remove('cs-active'));
  if (idx < 0) idx = 0;
  ctx.active = idx;
  const item = ctx.items[idx];
  if (item) { item.classList.add('cs-active'); item.scrollIntoView({ block: 'nearest' }); }
}

function choose(sel, opt) {
  if (!opt || opt.disabled) return;
  const changed = sel.options[sel.selectedIndex] !== opt;
  valueDesc.set.call(sel, opt.value);
  sync(sel);
  closeMenu();
  if (changed) sel.dispatchEvent(new Event('change', { bubbles: true }));
}

function position(ctx) {
  const r = ctx.btn.getBoundingClientRect();
  const { menu } = ctx;
  menu.style.minWidth = `${r.width}px`;
  menu.style.left = `${r.left}px`;
  const below = window.innerHeight - r.bottom - 8;
  const above = r.top - 8;
  const flip = below < 160 && above > below;
  menu.style.maxHeight = `${Math.max(120, Math.min(280, flip ? above : below))}px`;
  if (flip) { menu.style.top = ''; menu.style.bottom = `${window.innerHeight - r.top + 4}px`; }
  else { menu.style.bottom = ''; menu.style.top = `${r.bottom + 4}px`; }
}

function openMenu(sel) {
  const st = ENHANCED.get(sel);
  if (!st || sel.disabled) return;
  if (open && open.sel === sel) return;
  closeMenu();
  const menu = document.createElement('div');
  menu.className = 'cs-menu';
  menu.setAttribute('role', 'listbox');
  open = { sel, btn: st.btn, menu, items: [], active: 0, typed: '', typedAt: 0 };
  renderItems(open);
  document.body.appendChild(menu);
  position(open);
  st.btn.setAttribute('aria-expanded', 'true');
  menu.addEventListener('mousedown', e => e.preventDefault());
  menu.addEventListener('click', e => {
    const item = e.target.closest('.cs-item');
    if (item) choose(sel, item._opt);
  });
  menu.addEventListener('mousemove', e => {
    const item = e.target.closest('.cs-item');
    if (item) setActive(open, open.items.indexOf(item));
  });
}

function onKey(sel, e) {
  const st = ENHANCED.get(sel);
  if (!open || open.sel !== sel) {
    if (['ArrowDown', 'ArrowUp', 'Enter', ' '].includes(e.key)) { e.preventDefault(); openMenu(sel); }
    return;
  }
  const step = d => {
    let i = open.active;
    do { i += d; } while (open.items[i] && open.items[i]._opt.disabled);
    if (open.items[i]) setActive(open, i);
  };
  switch (e.key) {
    case 'ArrowDown': e.preventDefault(); step(1); break;
    case 'ArrowUp': e.preventDefault(); step(-1); break;
    case 'Home': e.preventDefault(); setActive(open, 0); break;
    case 'End': e.preventDefault(); setActive(open, open.items.length - 1); break;
    case 'Enter': case ' ':
      e.preventDefault(); choose(sel, open.items[open.active]?._opt); break;
    case 'Escape': e.preventDefault(); e.stopPropagation(); closeMenu(); st.btn.focus(); break;
    case 'Tab': closeMenu(); break;
    default:
      if (e.key.length === 1 && !e.ctrlKey && !e.metaKey) {
        const now = Date.now();
        open.typed = (now - open.typedAt < 700 ? open.typed : '') + e.key.toLowerCase();
        open.typedAt = now;
        const i = open.items.findIndex(it => !it._opt.disabled && it.textContent.toLowerCase().startsWith(open.typed));
        if (i >= 0) setActive(open, i);
      }
  }
}

export function enhanceSelect(sel) {
  if (ENHANCED.has(sel) || sel.multiple || sel.size > 1 || 'native' in sel.dataset) return;
  const wrap = document.createElement('div');
  wrap.className = 'cs';
  wrap.style.cssText = sel.style.cssText;
  wrap.style.display = '';
  const btn = document.createElement('button');
  btn.type = 'button';
  btn.className = `cs-btn ${sel.className}`.trim();
  btn.setAttribute('aria-haspopup', 'listbox');
  btn.setAttribute('aria-expanded', 'false');
  const label = sel.getAttribute('aria-label');
  if (label) btn.setAttribute('aria-label', label);
  else if (sel.id) {
    const l = document.querySelector(`label[for="${CSS.escape(sel.id)}"]`) || sel.closest('label');
    if (l) btn.setAttribute('aria-label', l.textContent.trim());
  }
  const text = document.createElement('span');
  text.className = 'cs-text';
  const caret = document.createElement('span');
  caret.className = 'cs-caret';
  caret.setAttribute('aria-hidden', 'true');
  btn.append(text, caret);
  wrap.appendChild(btn);
  sel.classList.add('cs-native');
  sel.tabIndex = -1;
  sel.after(wrap);

  const observer = new MutationObserver(() => sync(sel));
  observer.observe(sel, { childList: true, subtree: true, characterData: true, attributes: true,
    attributeFilter: ['disabled', 'style', 'hidden', 'selected', 'label'] });
  ENHANCED.set(sel, { wrap, btn, text, observer });

  Object.defineProperty(sel, 'value', {
    configurable: true,
    get() { return valueDesc.get.call(sel); },
    set(v) { valueDesc.set.call(sel, v); sync(sel); },
  });
  sel.addEventListener('change', () => sync(sel));
  btn.addEventListener('click', () => (open && open.sel === sel ? closeMenu() : openMenu(sel)));
  btn.addEventListener('keydown', e => onKey(sel, e));
  btn.addEventListener('blur', () => { if (open && open.sel === sel) closeMenu(); });
  sync(sel);
}

function enhanceWithin(root) {
  if (root.nodeType !== 1) return;
  if (root.matches('select')) enhanceSelect(root);
  root.querySelectorAll?.('select').forEach(enhanceSelect);
}

function cleanupWithin(root) {
  if (root.nodeType !== 1) return;
  const sels = root.matches('select') ? [root] : [...root.querySelectorAll('select')];
  for (const sel of sels) {
    if (sel.isConnected) continue;
    const st = ENHANCED.get(sel);
    if (!st) continue;
    st.observer.disconnect();
    if (open && open.sel === sel) closeMenu();
  }
}

if (typeof document !== 'undefined' && !window.__customSelect) {
  window.__customSelect = true;
  enhanceWithin(document.body);
  new MutationObserver(muts => {
    for (const m of muts) {
      m.removedNodes.forEach(cleanupWithin);
      m.addedNodes.forEach(enhanceWithin);
    }
  }).observe(document.body, { childList: true, subtree: true });
  document.addEventListener('mousedown', e => {
    if (open && !open.menu.contains(e.target) && !open.btn.contains(e.target)) closeMenu();
  });
  window.addEventListener('resize', closeMenu);
  window.addEventListener('scroll', e => { if (open && !open.menu.contains(e.target)) closeMenu(); }, true);
}
