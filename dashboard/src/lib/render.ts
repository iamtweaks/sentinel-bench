import { sb } from './sb';

export type Status = 'act' | 'plan' | 'mon' | 'risk';
export type BorderKey = 'crit' | 'high' | 'med' | 'low';

export function statusFor(score: number | null | undefined, isKev: boolean | null | undefined): Status {
  if (isKev) return 'act';
  const s = score ?? 0;
  if (s >= 70) return 'act';
  if (s >= 50) return 'plan';
  if (s >= 25) return 'mon';
  return 'risk';
}

export function borderKeyFor(score: number | null | undefined, isKev: boolean | null | undefined): BorderKey {
  if (isKev) return 'crit';
  const s = score ?? 0;
  if (s >= 70) return 'crit';
  if (s >= 50) return 'high';
  if (s >= 25) return 'med';
  return 'low';
}

const STATUS_LABEL: Record<Status, string> = {
  act: 'Act Now',
  plan: 'Plan Patch',
  mon: 'Monitor',
  risk: 'Low Risk',
};
export function statusLabel(s: Status) { return STATUS_LABEL[s]; }
export function statusClass(s: Status) { return `s-${s === 'risk' ? 'risk' : s === 'act' ? 'act' : s === 'plan' ? 'plan' : 'mon'}`; }

function scoreClass(score: number) {
  if (score >= 70) return 'score-crit';
  if (score >= 50) return 'score-high';
  if (score >= 25) return 'score-med';
  return 'score-low';
}

function firstVendor(v: any): string {
  const list = v?.vendors;
  if (Array.isArray(list) && list.length) return String(list[0]);
  return '—';
}

function relativeWhen(iso: string | null | undefined): string {
  if (!iso) return 'fecha desconocida';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return 'fecha desconocida';
  const diffSec = Math.floor((Date.now() - d.getTime()) / 1000);
  if (diffSec < 60) return 'just now';
  const rtf = new Intl.RelativeTimeFormat('es', { numeric: 'auto' });
  const units: [Intl.RelativeTimeFormatUnit, number][] = [
    ['year', 60 * 60 * 24 * 365],
    ['month', 60 * 60 * 24 * 30],
    ['week', 60 * 60 * 24 * 7],
    ['day', 60 * 60 * 24],
    ['hour', 60 * 60],
    ['minute', 60],
  ];
  for (const [unit, sec] of units) {
    if (Math.abs(diffSec) >= sec) {
      const v = -Math.round(diffSec / sec);
      // ponytail: "X days ago" style — override to english-ish per spec
      return rtf.format(v, unit);
    }
  }
  return rtf.format(-Math.floor(diffSec / 60), 'minute');
}

function escapeHtml(s: any): string {
  return String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c] || c));
}

function truncate(s: any, n: number): string {
  const str = String(s ?? '');
  return str.length > n ? str.slice(0, n - 1) + '…' : str;
}

function renderItCard(r: any): string {
  const v = r.vuln || {};
  const status = statusFor(r.score, v.is_kev);
  const border = borderKeyFor(r.score, v.is_kev);
  const vendor = firstVendor(v);
  const title = v.cve_id || r.cve_id || 'CVE';
  const desc = v.description || r.rationale || 'Sin descripción disponible.';
  const cve = escapeHtml(r.cve_id);
  const cvss = v.cvss_v3_score != null ? v.cvss_v3_score.toFixed(1) : null;
  const epss = v.epss_score != null ? (v.epss_score * 100).toFixed(1) + '%' : null;
  const when = relativeWhen(v.last_updated_at || r.computed_at);
  const badges: string[] = [];
  if (v.is_kev) badges.push(`<span class="badge b-kev">KEV</span>`);
  if (v.poc_public) badges.push(`<span class="badge b-poc">PoC</span>`);
  if (cvss) badges.push(`<span class="badge b-cvss">CVSS ${escapeHtml(cvss)}</span>`);
  if (epss) badges.push(`<span class="badge b-epss">EPSS ${escapeHtml(epss)}</span>`);

  return `<article class="card b-${border}" data-cve="${cve}" data-kind="it" role="button" tabindex="0">
    <div class="row-top">
      <span class="vendor"><span class="domain-tag it">IT</span><span class="vendor-name">${escapeHtml(vendor)}</span></span>
      <span class="badges">
        ${badges.join('')}
        <span class="score-pill ${scoreClass(r.score)}">${r.score.toFixed(1)}</span>
        <span class="status ${statusClass(status)}">${statusLabel(status)}</span>
      </span>
    </div>
    <h3 class="title">${escapeHtml(title)}</h3>
    <p class="desc">${escapeHtml(truncate(desc, 240))}</p>
    <div class="row-foot">
      <span class="cves"><span class="cve">${cve}</span></span>
      <span class="when">${escapeHtml(when)}</span>
    </div>
  </article>`;
}

function renderOtCard(a: any): string {
  const sev = String(a.severity || '').toUpperCase();
  const sevScoreMap: Record<string, number> = { CRITICAL: 80, HIGH: 60, MEDIUM: 35, LOW: 10 };
  const approxScore = sevScoreMap[sev] ?? 20;
  const isKevLike = sev === 'CRITICAL';
  const status = isKevLike ? 'act' : statusFor(approxScore, false);
  const border = isKevLike ? 'crit' : borderKeyFor(approxScore, false);
  const vendor = firstVendor({ vendors: a.vendors });
  const title = a.title || 'Advisory sin título';
  const desc = a.summary || '';
  const when = relativeWhen(a.published_at);
  const cves = Array.isArray(a.cve_ids) ? a.cve_ids : [];
  const cvesStr = cves.length ? cves.slice(0, 3).map((c: string) => escapeHtml(c)).join(', ') + (cves.length > 3 ? ` +${cves.length - 3}` : '') : '—';
  const advisoryId = a.advisory_id || (a.url ? safeAdvisoryIdFromUrl(a.url) : null);
  const sevBadge = sev ? `<span class="badge b-cvss">${escapeHtml(sev)}</span>` : '';

  const inner = `<article class="card b-${border}" data-kind="ot" ${a.url ? `data-url="${escapeHtml(a.url)}"` : ''}>
    <div class="row-top">
      <span class="vendor"><span class="domain-tag ot">OT</span><span class="vendor-name">${escapeHtml(vendor)}</span></span>
      <span class="badges">${sevBadge}<span class="status ${statusClass(status)}">${statusLabel(status)}</span></span>
    </div>
    <h3 class="title">${escapeHtml(title)}</h3>
    <p class="desc">${escapeHtml(truncate(desc, 240))}</p>
    <div class="row-foot">
      <span class="cves">${cvesStr}${advisoryId ? ` · <span class="advisory-id">${escapeHtml(advisoryId)}</span>` : ''}</span>
      <span class="when">${escapeHtml(when)}</span>
    </div>
  </article>`;
  return a.url ? `<a href="${escapeHtml(a.url)}" target="_blank" rel="noopener noreferrer" style="text-decoration:none;color:inherit">${inner}</a>` : inner;
}

function safeAdvisoryIdFromUrl(url: string): string | null {
  try {
    const u = new URL(url);
    const parts = u.pathname.split('/').filter(Boolean);
    return parts.length ? parts[parts.length - 1].slice(0, 40) : u.hostname;
  } catch { return null; }
}

export function renderRows(container: HTMLElement, rows: any[]) {
  if (rows.length === 0) {
    container.innerHTML = '<div class="empty">Sin resultados para los filtros aplicados.</div>';
    return;
  }
  const html = rows.slice(0, 200).map(renderItCard).join('');
  container.innerHTML = html;
}

export function renderOtCards(container: HTMLElement, advisories: any[]) {
  if (!advisories.length) {
    container.innerHTML = '<div class="empty">Todavía no hay advisories OT.</div>';
    return;
  }
  container.innerHTML = advisories.slice(0, 60).map(renderOtCard).join('');
}

export function bindRowClicks(container: HTMLElement, onClick: (cve: string) => void) {
  container.querySelectorAll<HTMLElement>('[data-cve][data-kind="it"]').forEach(el => {
    const cve = el.dataset.cve!;
    el.addEventListener('click', e => { e.preventDefault(); onClick(cve); });
    el.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onClick(cve); } });
  });
}

export function renderDetail(pane: HTMLElement, row: any) {
  if (!row) return;
  pane.style.display = 'block';
  const v = row.vuln || {};
  const factors = JSON.stringify(row.factors || {}, null, 2);
  pane.innerHTML = `
    <div class="detail">
      <h2>${escapeHtml(row.cve_id)} — score ${row.score.toFixed(1)}</h2>
      <div class="detail-grid">
        <div class="k">CVSS v3</div><div>${v.cvss_v3_score ?? '—'}</div>
        <div class="k">EPSS</div><div>${v.epss_score != null ? (v.epss_score * 100).toFixed(3) + '% (percentil ' + ((v.epss_percentile || 0) * 100).toFixed(2) + '%)' : '—'}</div>
        <div class="k">KEV</div><div>${v.is_kev ? '✅ Sí (CISA KEV)' : '—'}</div>
        <div class="k">Explotación</div><div>${v.exploited_in_wild ? 'Confirmada en producción' : v.poc_public ? 'PoC público disponible' : 'Sin evidencia pública'}</div>
        <div class="k">Vendors</div><div>${(v.vendors || []).map(escapeHtml).join(', ') || '—'}</div>
        <div class="k">Productos</div><div>${(v.products || []).map(escapeHtml).join(', ') || '—'}</div>
        <div class="k">Descripción</div><div>${escapeHtml((v.description || '').slice(0, 600))}</div>
        <div class="k">Rationale</div><div>${escapeHtml(row.rationale || '—')}</div>
        <div class="k">Factores (raw)</div><div class="factors">${escapeHtml(factors)}</div>
      </div>
      <div id="detail-sources" style="margin-top:18px"><strong>Fuentes:</strong> <span style="color:var(--muted)">cargando…</span></div>
    </div>
  `;
  if (sb) {
    sb.from('advisories')
      .select('url,title,source_id,sources!inner(slug)')
      .contains('cve_ids', [row.cve_id])
      .limit(20)
      .then(({ data }) => {
        const el = document.getElementById('detail-sources');
        if (!el || !data) return;
        el.innerHTML = '<strong>Fuentes:</strong> ' + (data.length
          ? data.map(d => `<a href="${d.url}" rel="noopener" target="_blank">[${(d as any).sources?.slug || 'src'}] ${escapeHtml((d.title || '').slice(0, 80))}</a>`).join('<br/>')
          : '<em>Sin enlaces</em>');
      });
  }
  pane.scrollIntoView({ behavior: 'smooth' });
}
