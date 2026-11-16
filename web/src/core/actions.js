// Delegated event handling for elements rendered with act()/actOn() (lib/format.js).
// Walks from the event target up to the root and runs every matching data-act* on the
// way, the order and reach inline handlers had when the event bubbled. An element with
// data-stop ends the walk, like event.stopPropagation() did.
function resolveArg(a, el, e) {
  if (!a || typeof a !== 'object' || !a.$) return a;
  switch (a.$) {
    case 'value': return el.value;
    case 'checked': return el.checked;
    case 'el': return el;
    case 'event': return e;
    case 'shift': return e.shiftKey;
    case 'data': return el.dataset[a.k];
    default: return undefined;
  }
}

function dispatch(type, e) {
  const key = type === 'click' ? 'act' : `act${type[0].toUpperCase()}${type.slice(1)}`;
  const argsKey = type === 'click' ? 'args' : `args${type[0].toUpperCase()}${type.slice(1)}`;
  for (let el = e.target instanceof Element ? e.target : null; el; el = el.parentElement) {
    const name = el.dataset[key];
    const fn = name && window[name];
    if (typeof fn === 'function') {
      let args = [];
      try { args = JSON.parse(el.dataset[argsKey] || '[]'); } catch { /* malformed args: call with none */ }
      fn(...args.map(a => resolveArg(a, el, e)));
    }
    if (type === 'click' && el.hasAttribute('data-stop')) return;
  }
}

for (const type of ['click', 'change', 'input', 'submit', 'keydown']) {
  document.addEventListener(type, e => dispatch(type, e));
}
