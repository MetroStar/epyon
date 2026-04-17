import React, { useEffect, useRef } from 'react';
import { useMetrics } from '@src/api/hooks';
import { StatCard } from '@src/components/stat-card/StatCard';
import type { MetricsCveEntry, MetricsScanFrequency, MetricsToolEntry, MetricsTrendPoint } from '@src/api/types';

// ── Colour palette (mirrors epyon CSS vars) ───────────────────
const C = {
  critical: '#ff7b72',
  high:     '#ffa657',
  medium:   '#e3b341',
  low:      '#79c0ff',
  clean:    '#3fb950',
  border:   '#30363d',
  card:     '#161b22',
  text:     '#8b949e',
  dim:      '#6e7681',
};

// ── Donut chart ───────────────────────────────────────────────
interface DonutProps { withFix: number; withoutFix: number; }
const DonutChart: React.FC<DonutProps> = ({ withFix, withoutFix }) => {
  const ref = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d')!;
    const dpr = window.devicePixelRatio || 1;
    const W = 200, H = 200;
    canvas.width = W * dpr; canvas.height = H * dpr;
    canvas.style.width = W + 'px'; canvas.style.height = H + 'px';
    ctx.scale(dpr, dpr);
    const cx = W / 2, cy = H / 2, R = 78, ir = 50;
    const total = withFix + withoutFix;
    if (!total) {
      ctx.fillStyle = C.border;
      ctx.beginPath(); ctx.arc(cx, cy, R, 0, Math.PI * 2); ctx.fill();
      ctx.fillStyle = C.card;
      ctx.beginPath(); ctx.arc(cx, cy, ir, 0, Math.PI * 2); ctx.fill();
      ctx.fillStyle = C.dim; ctx.font = '12px sans-serif';
      ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
      ctx.fillText('No data', cx, cy);
      return;
    }
    const segs = [
      { value: withFix,    color: C.clean },
      { value: withoutFix, color: C.border },
    ];
    let angle = -Math.PI / 2;
    for (const seg of segs) {
      if (!seg.value) continue;
      const slice = (seg.value / total) * Math.PI * 2;
      ctx.beginPath(); ctx.moveTo(cx, cy);
      ctx.arc(cx, cy, R, angle, angle + slice); ctx.closePath();
      ctx.fillStyle = seg.color; ctx.fill();
      angle += slice;
    }
    ctx.beginPath(); ctx.arc(cx, cy, ir, 0, Math.PI * 2);
    ctx.fillStyle = C.card; ctx.fill();
    const pct = Math.round((withFix / total) * 100);
    ctx.fillStyle = '#e6edf3'; ctx.font = 'bold 22px sans-serif';
    ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
    ctx.fillText(pct + '%', cx, cy - 9);
    ctx.fillStyle = C.text; ctx.font = '11px sans-serif';
    ctx.fillText('fixable', cx, cy + 10);
  }, [withFix, withoutFix]);
  return <canvas ref={ref} />;
};

// ── Horizontal stacked bar chart ──────────────────────────────
interface HBarProps { items: MetricsToolEntry[]; }
const HBarChart: React.FC<HBarProps> = ({ items }) => {
  const ref = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    const canvas = ref.current;
    if (!canvas || !items.length) return;
    const ctx = canvas.getContext('2d')!;
    const dpr = window.devicePixelRatio || 1;
    const w = canvas.parentElement?.clientWidth ?? 400;
    const rowH = 36, h = items.length * rowH + 8;
    canvas.width = w * dpr; canvas.height = h * dpr;
    canvas.style.width = w + 'px'; canvas.style.height = h + 'px';
    ctx.scale(dpr, dpr);
    const labelW = 110, countW = 44, barArea = w - labelW - countW;
    const maxTotal = Math.max(...items.map((x) => x.total), 1);
    items.forEach((item, i) => {
      const barH = 20, barY = i * rowH + (rowH - barH) / 2;
      ctx.fillStyle = '#21262d';
      ctx.fillRect(labelW, barY, barArea, barH);
      let xOff = labelW;
      for (const sev of ['critical', 'high', 'medium', 'low'] as const) {
        const val = item[sev] || 0;
        if (!val) continue;
        const bw = Math.max(1, Math.round((val / maxTotal) * barArea));
        ctx.fillStyle = C[sev];
        ctx.fillRect(xOff, barY, bw, barH);
        xOff += bw;
      }
      ctx.fillStyle = C.text;
      ctx.font = '12px -apple-system,sans-serif';
      ctx.textAlign = 'right'; ctx.textBaseline = 'middle';
      const lbl = item.tool.length > 14 ? item.tool.slice(0, 13) + '…' : item.tool;
      ctx.fillText(lbl, labelW - 8, barY + barH / 2);
      ctx.textAlign = 'left';
      ctx.fillText(String(item.total), labelW + barArea + 8, barY + barH / 2);
    });
  }, [items]);
  const h = Math.max(items.length * 36 + 8, 60);
  return <canvas ref={ref} style={{ display: 'block', width: '100%', height: h }} />;
};

// ── Line chart ────────────────────────────────────────────────
interface LineProps { trend: MetricsTrendPoint[]; }
const LineChart: React.FC<LineProps> = ({ trend }) => {
  const ref = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    const canvas = ref.current;
    if (!canvas || !trend.length) return;
    const ctx = canvas.getContext('2d')!;
    const dpr = window.devicePixelRatio || 1;
    const w = canvas.parentElement?.clientWidth ?? 600, h = 200;
    canvas.width = w * dpr; canvas.height = h * dpr;
    canvas.style.width = w + 'px'; canvas.style.height = h + 'px';
    ctx.scale(dpr, dpr);
    const n = trend.length;
    const pad = { top: 16, right: 16, bottom: 36, left: 44 };
    const cw = w - pad.left - pad.right, ch = h - pad.top - pad.bottom;
    const series = [
      { color: C.critical, data: trend.map((t) => t.critical) },
      { color: C.high,     data: trend.map((t) => t.high) },
      { color: C.medium,   data: trend.map((t) => t.medium) },
      { color: C.low,      data: trend.map((t) => t.low) },
    ];
    const maxV = Math.max(...series.flatMap((s) => s.data), 1);
    ctx.strokeStyle = '#21262d'; ctx.lineWidth = 1;
    for (let i = 0; i <= 4; i++) {
      const y = pad.top + ch * (1 - i / 4);
      ctx.beginPath(); ctx.moveTo(pad.left, y); ctx.lineTo(pad.left + cw, y); ctx.stroke();
      ctx.fillStyle = C.dim; ctx.font = '10px sans-serif';
      ctx.textAlign = 'right'; ctx.textBaseline = 'middle';
      ctx.fillText(String(Math.round(maxV * i / 4)), pad.left - 5, y);
    }
    const step = Math.max(1, Math.floor(n / 12));
    ctx.fillStyle = C.dim; ctx.font = '10px sans-serif';
    ctx.textAlign = 'center'; ctx.textBaseline = 'top';
    for (let i = 0; i < n; i += step) {
      const x = pad.left + (n === 1 ? cw / 2 : (i / (n - 1)) * cw);
      ctx.fillText(trend[i].timestamp.slice(5, 10), x, pad.top + ch + 6);
    }
    for (const s of series) {
      if (!s.data.some((v) => v > 0)) continue;
      ctx.strokeStyle = s.color; ctx.lineWidth = 2; ctx.lineJoin = 'round';
      ctx.beginPath();
      s.data.forEach((v, i) => {
        const x = pad.left + (n === 1 ? cw / 2 : (i / (n - 1)) * cw);
        const y = pad.top + ch * (1 - v / maxV);
        i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
      });
      ctx.stroke();
    }
  }, [trend]);
  return <canvas ref={ref} style={{ display: 'block', width: '100%', height: 200 }} />;
};

// ── Legend ────────────────────────────────────────────────────
const SevLegend: React.FC = () => (
  <div className="epyon-metrics-legend">
    {(['critical', 'high', 'medium', 'low'] as const).map((s) => (
      <span key={s} className="epyon-metrics-legend__item">
        <span className="epyon-metrics-legend__dot" style={{ background: C[s] }} />
        {s.charAt(0).toUpperCase() + s.slice(1)}
      </span>
    ))}
  </div>
);

// ── Top CVEs table ────────────────────────────────────────────
const TopCvesTable: React.FC<{ cves: MetricsCveEntry[] }> = ({ cves }) => (
  <div className="epyon-table-wrap">
    <table className="usa-table usa-table--borderless" style={{ width: '100%' }}>
      <thead>
        <tr>
          <th>CVE ID</th>
          <th>Severity</th>
          <th>Count</th>
          <th>Title</th>
          <th>Applications</th>
        </tr>
      </thead>
      <tbody>
        {cves.length === 0 ? (
          <tr><td colSpan={5} style={{ textAlign: 'center', padding: '2rem', color: C.text }}>
            No CVE data — run a scan to populate
          </td></tr>
        ) : cves.map((c) => (
          <tr key={c.cve_id}>
            <td>
              <a href={`https://nvd.nist.gov/vuln/detail/${c.cve_id}`}
                 target="_blank" rel="noopener noreferrer"
                 style={{ color: 'var(--epyon-accent)', fontFamily: 'monospace', fontSize: 12 }}>
                {c.cve_id}
              </a>
            </td>
            <td><span className={`epyon-badge epyon-badge--${c.severity}`}>
              {c.severity.charAt(0).toUpperCase() + c.severity.slice(1)}
            </span></td>
            <td>{c.count}</td>
            <td style={{ maxWidth: 360, fontSize: 12 }}>{c.title || '—'}</td>
            <td style={{ fontSize: 11, color: C.text }}>{c.apps.join(', ')}</td>
          </tr>
        ))}
      </tbody>
    </table>
  </div>
);

// ── Scan frequency table ──────────────────────────────────────
const FrequencyTable: React.FC<{ freq: Record<string, MetricsScanFrequency> }> = ({ freq }) => {
  const rows = Object.entries(freq).sort((a, b) => b[1].total - a[1].total);
  return (
    <div className="epyon-table-wrap">
      <table className="usa-table usa-table--borderless" style={{ width: '100%' }}>
        <thead>
          <tr>
            <th>Application</th>
            <th>Total Scans</th>
            <th>First Scan</th>
            <th>Latest Scan</th>
            <th>Activity</th>
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 ? (
            <tr><td colSpan={5} style={{ textAlign: 'center', padding: '2rem', color: C.text }}>
              No scan data
            </td></tr>
          ) : rows.map(([name, f]) => (
            <tr key={name}>
              <td><strong>{name}</strong></td>
              <td>{f.total}</td>
              <td style={{ fontSize: 12 }}>{f.dates[0] ?? '—'}</td>
              <td style={{ fontSize: 12 }}>{f.dates[f.dates.length - 1] ?? '—'}</td>
              <td>
                <div className="epyon-freq-dots">
                  {f.dates.map((d, i) => (
                    <span key={i} className="epyon-freq-dot" title={d} />
                  ))}
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

// ── Main page ─────────────────────────────────────────────────
export const Metrics = (): React.ReactElement => {
  const { data: m, isLoading, isError, error, refetch } = useMetrics();

  if (isLoading) {
    return (
      <div className="grid-container">
        <div className="epyon-loading"><div className="epyon-spinner" /> Loading metrics…</div>
      </div>
    );
  }

  if (isError || !m) {
    return (
      <div className="grid-container">
        <div className="epyon-page-header"><h1>Metrics</h1></div>
        <div className="usa-alert usa-alert--error">
          <div className="usa-alert__body">
            <p className="usa-alert__text">
              {(error as Error)?.message ?? 'Failed to load metrics'}
            </p>
          </div>
        </div>
      </div>
    );
  }

  const totalFindings = m.fix_rate.with_fix + m.fix_rate.without_fix;
  const fixPct        = totalFindings > 0 ? Math.round((m.fix_rate.with_fix / totalFindings) * 100) : 0;
  const topTool       = m.by_tool[0]?.tool ?? '—';
  const activeApps    = Object.keys(m.scan_frequency).length;

  return (
    <div className="grid-container">
      <div className="epyon-page-header">
        <h1>Metrics</h1>
        <button className="usa-button usa-button--secondary" onClick={() => refetch()}>
          ↻ Refresh
        </button>
      </div>

      {/* Summary stats */}
      <div className="epyon-section">
        <div className="epyon-section-title">Summary</div>
        <div className="epyon-grid-stats">
          <StatCard value={totalFindings} label="Total Findings" variant="default" />
          <StatCard value={`${fixPct}%`}  label="Fixable"        variant="clean" />
          <StatCard value={activeApps}    label="Active Apps"    variant="default" />
          <StatCard value={topTool}       label="Top Finding Tool" variant="default" />
        </div>
      </div>

      {/* Fix rate + by tool */}
      <div className="epyon-section">
        <div className="epyon-metrics-two-col">
          <div className="epyon-chart-panel">
            <div className="epyon-section-title">Fix Rate</div>
            <div style={{ display: 'flex', justifyContent: 'center', padding: '12px 0' }}>
              <DonutChart withFix={m.fix_rate.with_fix} withoutFix={m.fix_rate.without_fix} />
            </div>
            <div className="epyon-metrics-legend">
              <span className="epyon-metrics-legend__item">
                <span className="epyon-metrics-legend__dot" style={{ background: C.clean }} />
                Fixable ({m.fix_rate.with_fix})
              </span>
              <span className="epyon-metrics-legend__item">
                <span className="epyon-metrics-legend__dot"
                  style={{ background: C.border, border: '1px solid #6e7681' }} />
                No fix ({m.fix_rate.without_fix})
              </span>
            </div>
          </div>
          <div className="epyon-chart-panel" style={{ flex: 2, minWidth: 0 }}>
            <div className="epyon-section-title">Findings by Tool</div>
            <HBarChart items={m.by_tool} />
            <SevLegend />
          </div>
        </div>
      </div>

      {/* Trend */}
      <div className="epyon-section">
        <div className="epyon-section-title" style={{ display: 'flex', justifyContent: 'space-between' }}>
          Vulnerability Trend
          <span style={{ fontSize: 12, fontWeight: 'normal', color: C.text }}>
            last {m.trend.length} scans
          </span>
        </div>
        <div className="epyon-chart-panel" style={{ padding: '20px 20px 8px' }}>
          <LineChart trend={m.trend} />
        </div>
        <SevLegend />
      </div>

      {/* Top CVEs */}
      <div className="epyon-section">
        <div className="epyon-section-title" style={{ display: 'flex', justifyContent: 'space-between' }}>
          Top CVEs
          <span style={{ fontSize: 12, fontWeight: 'normal', color: C.text }}>
            from latest scan per application
          </span>
        </div>
        <TopCvesTable cves={m.top_cves} />
      </div>

      {/* Scan frequency */}
      <div className="epyon-section">
        <div className="epyon-section-title">Scan Frequency</div>
        <FrequencyTable freq={m.scan_frequency} />
      </div>
    </div>
  );
};
