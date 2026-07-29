import { sb } from './sb';

function scoreClass(score: number) {
  if (score >= 70) return 'score-crit';
  if (score >= 50) return 'score-high';
  if (score >= 25) return 'score-med';
  return 'score-low';
}

function exploitBadge(v: any): string {
  if (v?.exploited_in_wild) return '<span class="badge b-kev">KEV</span>';
  if (v?.poc_public) return '<span class="badge b-poc">PoC</span>';
  return '<span class="badge b-cve">CVE</span>';
}

export function renderRows(tbody: HTMLElement, rows: any[]) {
  if (rows.length === 0) {
    tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--muted);padding:30px">Sin resultados</td></tr>';
    return;
  }
  tbody.innerHTML = rows.slice(0, 200).map(r => {
    const v = r.vuln || {};
    const vendor = (v.vendors || [])[0] || '—';
    const cvss = v.cvss_v3_score ?? '—';
    const epss = v.epss_score != null ? (v.epss_score * 100).toFixed(2) + '%' : '—';
    const expl = exploitBadge(v);
    const updated = v.last_updated_at ? new Date(v.last_updated_at).toISOString().slice(0, 10) : '—';
    return `<tr data-cve="${r.cve_id}">
      <td class="cve"><a href="javascript:void(0)">${r.cve_id}</a></td>
      <td><span class="score-pill ${scoreClass(r.score)}">${r.score.toFixed(1)}</span></td>
      <td>${cvss}</td>
      <td>${epss}</td>
      <td>${escapeHtml(vendor)}</td>
      <td>${expl}</td>
      <td>${escapeHtml(r.rationale || '')}</td>
      <td>${updated}</td>
    </tr>`;
  }).join('');
}

export function bindRowClicks(tbody: HTMLElement, onClick: (cve: string) => void) {
  tbody.querySelectorAll('a').forEach(a => {
    a.addEventListener('click', e => {
      e.preventDefault();
      const tr = (a.closest('tr') as HTMLElement);
      const cve = tr?.dataset.cve;
      if (cve) onClick(cve);
    });
  });
}

export function renderDetail(pane: HTMLElement, row: any) {
  if (!row) return;
  pane.style.display = 'block';
  const v = row.vuln || {};
  const factors = JSON.stringify(row.factors || {}, null, 2);
  pane.innerHTML = `
    <div class="detail">
      <h2>${row.cve_id} — score ${row.score.toFixed(1)}</h2>
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
  // Fetch advisories linked to this CVE
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

function escapeHtml(s: string): string {
  return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c] || c));
}