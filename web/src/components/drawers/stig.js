import { closeFindingDetail } from './finding.js';
import { esc, ucFirst } from '../../lib/format.js';
import { renderStigViewer } from '../../pages/stig.js';
import { _stigRegistry } from '../../state/registries.js';


// ── STIG Viewer control detail drawer ────────────────────────
// Opened when the user clicks a row in the STIG Viewer (renderStigViewer).
// Uses the shared finding-drawer overlay so Escape / click-outside close it.
export function openStigViewerDetail(regKey) {
  const entry = _stigRegistry.get(regKey);
  if (!entry) return;
  closeFindingDetail();

  const { c, scanId } = entry;

  const STATUS_CLASS_MAP = {
    'Open':          'stig-status-open',
    'Not a Finding': 'stig-status-pass',
    'Not Applicable':'stig-status-na',
    'Not Reviewed':  'stig-status-nr',
  };

  const conf    = c.confidence ?? 0;
  const confCls = conf >= 90 ? 'conf-high' : conf >= 70 ? 'conf-med' : conf >= 40 ? 'conf-low' : 'conf-none';
  const confLbl = conf >= 90 ? 'High' : conf >= 70 ? 'Medium' : conf >= 40 ? 'Low' : 'Insufficient';
  const sev     = (c.severity || 'unknown').toLowerCase();
  const statusCls = STATUS_CLASS_MAP[c.status] || 'stig-status-nr';

  const justPrefilled = c.locked_by_human && c.evidence
    ? esc(c.evidence.replace(/^\[Human override\] /, '').split('\n')[0])
    : '';
  const autoJustStatuses = ['Not a Finding', 'Not Applicable'];
  const autoJust = c.title || '';
  const justInitial = justPrefilled || (autoJustStatuses.includes(c.status) ? esc(autoJust) : '');

  const overrideOptions = ['Not a Finding', 'Not Applicable', 'Open', 'Not Reviewed']
    .map(s => `<option value="${esc(s)}"${c.status === s ? ' selected' : ''}>${esc(s)}</option>`).join('');

  const overlay = document.createElement('div');
  overlay.className = 'finding-drawer-overlay';
  overlay.id        = 'finding-drawer-overlay';
  overlay.addEventListener('click', closeFindingDetail);

  const drawer = document.createElement('div');
  drawer.className = 'finding-drawer';
  drawer.id        = 'finding-drawer';
  drawer.setAttribute('role', 'dialog');
  drawer.setAttribute('aria-modal', 'true');
  drawer.setAttribute('aria-label', 'STIG control details');
  drawer.addEventListener('click', e => e.stopPropagation());

  drawer.innerHTML = `
    <div class="finding-drawer-header">
      <div class="finding-drawer-title">
        <h2>${esc(c.title || c.vuln_id)}</h2>
        <div class="finding-drawer-badges">
          <span class="stig-sev stig-sev-${esc(sev)}">${ucFirst(sev)}</span>
          <span class="${esc(statusCls)}">${esc(c.status)}</span>
          ${c.locked_by_human ? '<span class="stig-lock-badge" title="Manually locked by reviewer">🔒</span>' : ''}
          <code style="font-size:12px">${esc(c.group_id || c.vuln_id)}</code>
        </div>
      </div>
      <button class="finding-drawer-close" onclick="closeFindingDetail()" aria-label="Close">✕</button>
    </div>
    <div class="finding-drawer-body">

      <div class="finding-detail-grid">
        <div class="finding-detail-section">
          <div class="finding-detail-label">Vuln ID</div>
          <div class="finding-detail-value"><code>${esc(c.vuln_id)}</code></div>
        </div>
        <div class="finding-detail-section">
          <div class="finding-detail-label">Rule ID</div>
          <div class="finding-detail-value"><code>${esc(c.rule_id || '—')}</code></div>
        </div>
        <div class="finding-detail-section">
          <div class="finding-detail-label">Group ID</div>
          <div class="finding-detail-value"><code>${esc(c.group_id || '—')}</code></div>
        </div>
        <div class="finding-detail-section">
          <div class="finding-detail-label">Confidence</div>
          <div class="finding-detail-value">
            <span class="stig-confidence ${confCls}">${conf}/100</span>
            <span style="margin-left:6px;font-size:12px;color:var(--text-muted)">${confLbl}</span>
          </div>
        </div>
        <div class="finding-detail-section">
          <div class="finding-detail-label">STIG</div>
          <div class="finding-detail-value" style="font-size:12px;color:var(--text-muted)">${esc(c._stig_name || '—')}</div>
        </div>
      </div>

      <div class="finding-detail-section" style="margin-top:12px">
        <div class="finding-detail-label">Evidence</div>
        <div class="stig-evidence" style="margin-top:6px">${esc(c.evidence || '—').replace(/\n/g, '<br>')}</div>
      </div>

      ${stigRecordHtml(c)}

      <div class="finding-detail-section" style="margin-top:12px">
        <div class="finding-detail-label">Check Content</div>
        <div class="stig-check" style="margin-top:6px">${esc(c.check_content || '—').replace(/\n/g, '<br>')}</div>
      </div>

      <div class="finding-detail-section" style="margin-top:12px">
        <div class="finding-detail-label">Remediation</div>
        <div style="margin-top:6px;font-size:13px;line-height:1.6;color:var(--text)">${esc(c.fix_text || '—').replace(/\n/g, '<br>')}</div>
      </div>

      <div style="margin-top:20px;border-top:1px solid var(--border);padding-top:16px">
        <button class="btn btn-primary" onclick="openStigJiraModal('${esc(scanId)}', ['${esc(regKey)}'])">Add to Jira</button>
        <span id="stig-jira-drawer-status" style="margin-left:10px;font-size:12px"></span>
      </div>

      <div class="stig-override-section" style="margin-top:20px;border-top:1px solid var(--border);padding-top:16px">
        <div class="finding-detail-label" style="margin-bottom:10px">
          Manual Override
          ${c.locked_by_human ? '<span class="stig-lock-badge" style="margin-left:8px">🔒 Locked by reviewer</span>' : ''}
        </div>
        <div class="stig-override-form">
          <div class="stig-override-row">
            <label class="stig-override-label">Status</label>
            <select class="stig-override-select" id="sd-status-${esc(c.vuln_id)}-${esc(c._slug)}"
              data-auto-just="${esc(autoJust)}"
              onchange="stigOverrideStatusChanged(this, 'sd-just-${esc(c.vuln_id)}-${esc(c._slug)}')">
              ${overrideOptions}
            </select>
          </div>
          <div class="stig-override-row">
            <label class="stig-override-label">Justification</label>
            <textarea class="stig-override-textarea" id="sd-just-${esc(c.vuln_id)}-${esc(c._slug)}"
              placeholder="Explain why this control is met (required)" rows="3">${justInitial}</textarea>
          </div>
          <div class="stig-override-row stig-override-actions">
            <button class="btn btn-sm btn-success"
              onclick="saveStigOverrideFromDrawer('${esc(scanId)}','${esc(c._slug)}','${esc(c.vuln_id)}')"
            >🔒 Lock Override</button>
            ${c.locked_by_human
              ? `<button class="btn btn-sm"
                  onclick="clearStigOverrideFromDrawer('${esc(scanId)}','${esc(c._slug)}','${esc(c.vuln_id)}')"
                >Clear Lock</button>`
              : ''}
            <span class="stig-override-msg" id="sd-msg-${esc(c.vuln_id)}-${esc(c._slug)}"></span>
          </div>
        </div>
      </div>

    </div>`;

  document.body.appendChild(overlay);
  document.body.appendChild(drawer);

}

// "Not Reviewed" is stored as-is (kept separate from N/A) but shown as
// "Evidence needed": the control is open until evidence is supplied.
export function stigStatusLabel(status) {
  return status === 'Not Reviewed' ? 'Evidence needed' : (status || '');
}

export function stigRecordHtml(c) {
  const rows = Array.isArray(c.changes_that_may_affect) ? c.changes_that_may_affect : [];
  const auto = c.automation_recommendation;
  const notes = [];
  if (c.evidence_needed) notes.push(['Evidence needed', c.evidence_needed]);
  if (c.verification_note) notes.push(['Verification', c.verification_note]);
  if (c.reopened_reason) notes.push(['Re-opened', c.reopened_reason]);
  if (c.downgraded_from) notes.push(['Downgraded from', c.downgraded_from]);
  if (c.needs_owner_confirmation) notes.push(['Owner', 'Needs owner confirmation']);
  (c.citation_failures || []).forEach(f => notes.push(['Citation failed', f]));
  if (!rows.length && !auto && !notes.length) return '';
  const noteHtml = notes.map(([k, v]) =>
    `<div style="font-size:13px;margin-top:4px"><strong>${esc(k)}:</strong> ${esc(v)}</div>`).join('');
  const tableHtml = rows.length ? `
    <table class="stig-table" style="margin-top:6px">
      <thead><tr><th scope="col">Change</th><th scope="col">Where</th><th scope="col">Re-check</th></tr></thead>
      <tbody>${rows.map(r => `<tr><td>${esc(r.change)}</td><td>${esc(r.where)}</td><td>${esc(r.recheck)}</td></tr>`).join('')}</tbody>
    </table>` : '';
  const autoHtml = auto ? `
    <div style="margin-top:8px;font-size:13px">
      <strong>Automation:</strong> ${esc(auto.check || '—')}
      ${auto.data_source ? `<div>Data source: ${esc(auto.data_source)}</div>` : ''}
      ${auto.pass_fail_rule ? `<div>Pass/fail: ${esc(auto.pass_fail_rule)}</div>` : ''}
      ${auto.where_it_runs ? `<div>Runs in: ${esc(auto.where_it_runs)}</div>` : ''}
    </div>` : '';
  return `
      <div class="finding-detail-section" style="margin-top:12px">
        <div class="finding-detail-label">Review Record</div>
        ${noteHtml}${rows.length ? '<div class="finding-detail-label" style="margin-top:10px">Changes that may affect this control</div>' : ''}${tableHtml}${autoHtml}
      </div>`;
}

export function closeStigDetail() {
  closeFindingDetail();
}

// Auto-fill the justification with the control's requirement for Not a Finding /
// Not Applicable, without clobbering text the reviewer typed.
window.stigOverrideStatusChanged = (sel, justId) => {
  const just = document.getElementById(justId);
  if (!just) return;
  const auto = sel.dataset.autoJust || '';
  const val = just.value.trim();
  if (val && val !== auto) return;
  just.value = ['Not a Finding', 'Not Applicable'].includes(sel.value) ? auto : '';
};

window.saveStigOverrideFromDrawer = async (sid, slug, vulnId) => {
  const statusEl = document.getElementById(`sd-status-${vulnId}-${slug}`);
  const justEl   = document.getElementById(`sd-just-${vulnId}-${slug}`);
  const msgEl    = document.getElementById(`sd-msg-${vulnId}-${slug}`);
  if (!statusEl || !justEl || !msgEl) return;
  const justification = justEl.value.trim();
  if (!justification) {
    msgEl.textContent = 'Justification is required.';
    msgEl.className = 'stig-override-msg stig-override-err';
    return;
  }
  msgEl.textContent = 'Saving…';
  msgEl.className = 'stig-override-msg';
  try {
    const res = await fetch(`/api/scans/${encodeURIComponent(sid)}/stig-override`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ slug, vuln_id: vulnId, status: statusEl.value, justification }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(err.detail || res.statusText);
    }
    msgEl.textContent = '✓ Locked';
    msgEl.className = 'stig-override-msg stig-override-ok';
    const newStatus = statusEl.value;
    setTimeout(() => {
      closeFindingDetail();
      const patch = { status: newStatus, confidence: 95, locked_by_human: true, evidence: `[Human override] ${justification}\n` };
      if (!window.updateStigControlInPlace?.(slug, vulnId, patch)) renderStigViewer(sid);
    }, 800);
  } catch (e) {
    msgEl.textContent = `Error: ${e.message}`;
    msgEl.className = 'stig-override-msg stig-override-err';
  }
};

window.clearStigOverrideFromDrawer = async (sid, slug, vulnId) => {
  const msgEl = document.getElementById(`sd-msg-${vulnId}-${slug}`);
  if (msgEl) { msgEl.textContent = 'Clearing…'; msgEl.className = 'stig-override-msg'; }
  try {
    const res = await fetch(`/api/scans/${encodeURIComponent(sid)}/stig-override`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ slug, vuln_id: vulnId, status: 'Open', justification: '', clear_lock: true }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(err.detail || res.statusText);
    }
    if (msgEl) { msgEl.textContent = '✓ Lock cleared'; msgEl.className = 'stig-override-msg stig-override-ok'; }
    setTimeout(() => {
      closeFindingDetail();
      const patch = { status: 'Open', confidence: 0, locked_by_human: false, evidence: '' };
      if (!window.updateStigControlInPlace?.(slug, vulnId, patch)) renderStigViewer(sid);
    }, 800);
  } catch (e) {
    if (msgEl) { msgEl.textContent = `Error: ${e.message}`; msgEl.className = 'stig-override-msg stig-override-err'; }
  }
};

// ── STIG control detail drawer (History view) ────────────────
let _stigDetailNextId = 0;

export const _stigDetailRegistry = new Map();

export function _registerStigDetail(c) {
  const id = _stigDetailNextId++;
  _stigDetailRegistry.set(id, c);
  return id;
}

export function openStigDetail(id) {
  const c = _stigDetailRegistry.get(id);
  if (!c) return;
  closeFindingDetail();

  const _SC = { 'Open': 'open', 'Not a Finding': 'not-a-finding', 'Not Applicable': 'na', 'Not Reviewed': 'not-reviewed' };
  const _SA = { 'Open': 'Open', 'Not a Finding': 'Pass', 'Not Applicable': 'N/A', 'Not Reviewed': 'Evid.' };

  const sev     = c.severity || 'unknown';
  const sevCls  = sev.toLowerCase();
  const latCls  = _SC[c.latest_status] || 'not-reviewed';
  const latLbl  = _SA[c.latest_status] || c.latest_status || '—';

  const tl = [...(c.timeline || [])].sort((a, b) => b.date.localeCompare(a.date));
  const timelineRows = tl.map((t, idx) => {
    const cls = _SC[t.status] || 'not-reviewed';
    const lbl = _SA[t.status] || t.status;
    const evidence = t.evidence || 'No evidence provided.';
    const confidence = t.confidence != null ? `${t.confidence}%` : '—';
    
    // Check if evidence changed from previous scan (next in array = older in time)
    const prevEvidence = idx < tl.length - 1 ? (tl[idx + 1].evidence || '') : '';
    const evidenceChanged = prevEvidence && evidence && prevEvidence !== evidence && t.status !== 'Not Reviewed';
    const changeClass = evidenceChanged ? ' style="background:var(--bg-hover)"' : '';
    const changeIcon = evidenceChanged ? ' <span style="color:var(--accent);font-size:12px" title="Evidence changed from previous scan">🔄 Changed</span>' : '';
    
    return `<tr${changeClass}>
      <td style="padding:8px 12px;font-size:12px;color:var(--text-muted);white-space:nowrap;vertical-align:top">${esc(t.date.slice(0, 10))}</td>
      <td style="padding:8px 12px;vertical-align:top"><span class="stig-status-chip ${cls}">${esc(lbl)}</span>${changeIcon}</td>
      <td style="padding:8px 12px;font-size:12px;color:var(--text-muted);text-align:center;vertical-align:top">${confidence}</td>
      <td style="padding:8px 12px;font-size:12px;color:var(--text);line-height:1.5;vertical-align:top">${esc(evidence).replace(/\n/g, '<br>')}</td>
    </tr>`;
  }).join('');

  const overlay = document.createElement('div');
  overlay.className = 'finding-drawer-overlay';
  overlay.id        = 'finding-drawer-overlay';
  overlay.addEventListener('click', closeFindingDetail);

  const drawer = document.createElement('div');
  drawer.className = 'finding-drawer';
  drawer.id        = 'finding-drawer';
  drawer.setAttribute('role', 'dialog');
  drawer.setAttribute('aria-modal', 'true');
  drawer.setAttribute('aria-label', 'STIG control details');
  drawer.addEventListener('click', e => e.stopPropagation());

  drawer.innerHTML = `
    <div class="finding-drawer-header">
      <div class="finding-drawer-title">
        <h2>${esc(c.title || c.vuln_id || '—')}</h2>
        <div class="finding-drawer-badges">
          <span class="sev-badge ${esc(sevCls)}">${ucFirst(sev)}</span>
          <span class="tool-tag">STIG</span>
          <code>${esc(c.vuln_id)}</code>
        </div>
      </div>
      <button class="finding-drawer-close" onclick="closeFindingDetail()" aria-label="Close">✕</button>
    </div>
    <div class="finding-drawer-body">
      <div class="finding-detail-grid">
        <div class="finding-detail-section">
          <div class="finding-detail-label">Current Status</div>
          <div class="finding-detail-value"><span class="stig-status-chip ${latCls}">${esc(latLbl)}</span></div>
        </div>
        <div class="finding-detail-section">
          <div class="finding-detail-label">Benchmark</div>
          <div class="finding-detail-value">${c.stig_name ? `<code style="font-size:12px">${esc(c.stig_name)}</code>` : '<span style="color:var(--text-dim)">—</span>'}</div>
        </div>
        <div class="finding-detail-section">
          <div class="finding-detail-label">First Open</div>
          <div class="finding-detail-value">${c.first_open ? esc(c.first_open.slice(0, 10)) : '<span style="color:var(--text-dim)">—</span>'}</div>
        </div>
        <div class="finding-detail-section">
          <div class="finding-detail-label">First Closed</div>
          <div class="finding-detail-value">${c.first_closed ? esc(c.first_closed.slice(0, 10)) : '<span style="color:var(--text-dim)">—</span>'}</div>
        </div>
        <div class="finding-detail-section">
          <div class="finding-detail-label">MTTR</div>
          <div class="finding-detail-value">${c.mttr_days != null ? `<strong>${c.mttr_days} days</strong>` : '<span style="color:var(--text-dim)">—</span>'}</div>
        </div>
      </div>
      ${tl.length ? `
      <div class="finding-detail-section">
        <div class="finding-detail-label">Scan History</div>
        <div class="finding-detail-desc" style="padding:0;background:none;border:1px solid var(--border-muted);border-radius:var(--radius);overflow:hidden">
          <table style="width:100%;border-collapse:collapse">
            <thead>
              <tr style="background:var(--bg-hover);border-bottom:1px solid var(--border)">
                <th scope="col" style="padding:8px 12px;font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;color:var(--text-muted);text-align:left;width:100px">Date</th>
                <th scope="col" style="padding:8px 12px;font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;color:var(--text-muted);text-align:left;width:140px">Status</th>
                <th scope="col" style="padding:8px 12px;font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;color:var(--text-muted);text-align:center;width:80px">Confidence</th>
                <th scope="col" style="padding:8px 12px;font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;color:var(--text-muted);text-align:left">Evidence / Reasoning</th>
              </tr>
            </thead>
            <tbody>${timelineRows}</tbody>
          </table>
        </div>
      </div>` : ''}
    </div>`;

  document.body.appendChild(overlay);
  document.body.appendChild(drawer);

}
