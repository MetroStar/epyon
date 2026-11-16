// ── Security helpers ──────────────────────────────────────────
export function esc(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// Attributes for a delegated click: `<button ${act('fn', a, b)}>` calls window.fn(a, b)
// (see core/actions.js). Args are JSON, so values are data and never parsed as code.
export function act(fn, ...args) {
  return `data-act="${esc(fn)}" data-args="${esc(JSON.stringify(args))}"`;
}

// ── Formatting helpers ────────────────────────────────────────
export function fmtDate(ts) {
  if (!ts) return '—';
  try {
    return new Date(ts).toLocaleString('en-US', {
      year: 'numeric', month: 'short', day: 'numeric',
      hour: '2-digit', minute: '2-digit',
    });
  } catch (_) { return esc(ts); }
}

export function ucFirst(s) { return s ? s[0].toUpperCase() + s.slice(1) : ''; }

export function dedupeTools(arr) {
  return [...new Set(arr || [])];
}

// Minimal markdown → HTML renderer (no external library)
export function renderMarkdown(text) {
  if (!text) return '';
  const safe = t => t.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

  const lines = text.split('\n');
  let html = '';
  let inUl = false;
  let inOl = false;
  let inCode = false;
  let codeLines = [];

  function closeList() {
    if (inUl) { html += '</ul>'; inUl = false; }
    if (inOl) { html += '</ol>'; inOl = false; }
  }

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Fenced code blocks
    if (/^```/.test(line)) {
      if (!inCode) {
        closeList();
        inCode = true;
        codeLines = [];
      } else {
        html += `<pre><code>${safe(codeLines.join('\n'))}</code></pre>`;
        inCode = false;
        codeLines = [];
      }
      continue;
    }
    if (inCode) { codeLines.push(line); continue; }

    // Horizontal rule
    if (/^---+$/.test(line.trim())) {
      closeList();
      html += '<hr>';
      continue;
    }

    // Headings (### before ## before #)
    if (/^### /.test(line)) {
      closeList();
      html += `<h3>${inlineMarkdown(safe(line.replace(/^### /, '')))}</h3>`;
      continue;
    }
    if (/^## /.test(line)) {
      closeList();
      html += `<h2>${inlineMarkdown(safe(line.replace(/^## /, '')))}</h2>`;
      continue;
    }
    if (/^# /.test(line)) {
      closeList();
      html += `<h2>${inlineMarkdown(safe(line.replace(/^# /, '')))}</h2>`;
      continue;
    }

    // Blockquote
    if (/^> /.test(line)) {
      closeList();
      html += `<blockquote>${inlineMarkdown(safe(line.replace(/^> /, '')))}</blockquote>`;
      continue;
    }

    // Ordered list
    if (/^\d+\. /.test(line)) {
      if (inUl) { html += '</ul>'; inUl = false; }
      if (!inOl) { html += '<ol>'; inOl = true; }
      html += `<li>${inlineMarkdown(safe(line.replace(/^\d+\. /, '')))}</li>`;
      continue;
    }

    // Unordered list
    if (/^[-*] /.test(line)) {
      if (inOl) { html += '</ol>'; inOl = false; }
      if (!inUl) { html += '<ul>'; inUl = true; }
      html += `<li>${inlineMarkdown(safe(line.replace(/^[-*] /, '')))}</li>`;
      continue;
    }

    // Blank line — close any open list
    if (line.trim() === '') {
      closeList();
      continue;
    }

    // Normal paragraph — close list first
    closeList();
    html += `<p>${inlineMarkdown(safe(line))}</p>`;
  }

  closeList();
  if (inCode) html += `<pre><code>${safe(codeLines.join('\n'))}</code></pre>`;
  return html;
}

export function inlineMarkdown(s) {
  s = s.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
  s = s.replace(/__(.+?)__/g, '<strong>$1</strong>');
  s = s.replace(/\*(.+?)\*/g, '<em>$1</em>');
  s = s.replace(/`([^`]+)`/g, '<code>$1</code>');
  return s;
}
