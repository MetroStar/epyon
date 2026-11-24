import { gateBadge, sevBadgeRow, statusBadge } from './badges.js';
import { esc, fmtDate, act } from '../lib/format.js';

export const appCard = app => `
          <div class="app-card status-${esc(app.status)}"
               ${act('navigate', `#/applications/${encodeURIComponent(app.name)}`)}>
            <div class="app-card-header">
              <span class="app-name">${esc(app.name)}</span>
              ${statusBadge(app.status)}
            </div>
            <div class="app-card-meta">
              ${app.last_scanned
                ? `Last scanned: ${fmtDate(app.last_scanned)} · ${esc(app.scan_type || 'full')}`
                : 'Never scanned'}
            </div>
            <div class="severity-row">${gateBadge(app)} ${sevBadgeRow(app)}</div>
            <div class="app-card-footer">
              ${app.scan_count} scan${app.scan_count !== 1 ? 's' : ''} total
            </div>
          </div>`;
