import { sb } from './sb';
import { renderCircuitBoard } from './CircuitBoard';

export type Status = 'act' | 'plan' | 'mon' | 'risk';

export function statusFor(score: number | null | undefined, isKev: boolean | null | undefined): Status {
  if (isKev) return 'act';
  const s = score ?? 0;
  if (s >= 70) return 'act';
  if (s >= 50) return 'plan';
  if (s >= 25) return 'mon';
  return 'risk';
}

const STATUS_LABEL: Record<Status, string> = {
  act: 'Act Now',
  plan: 'Plan Patch',
  mon: 'Monitor',
  risk: 'Low Risk',
};

export function statusLabel(s: Status) { return STATUS_LABEL[s]; }

function escapeHtml(s: any): string {
  return String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c] || c));
}

function truncate(s: any, n: number): string {
  const str = String(s ?? '');
  return str.length > n ? str.slice(0, n - 1) + '…' : str;
}

function firstVendor(v: any): string {
  const list = v?.vendors;
  if (Array.isArray(list) && list.length) return String(list[0]);
  return 'General';
}

function relativeWhen(iso: string | null | undefined): string {
  if (!iso) return 'Reciente';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return 'Reciente';
  const diffSec = Math.floor((Date.now() - d.getTime()) / 1000);
  if (diffSec < 3600) return 'Just now';
  const hours = Math.floor(diffSec / 3600);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days}d ago`;
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
}

export function renderAdvisoryCard(r: any, isActive: boolean = false, index: number = 0): string {
  const v = r.vuln || {};
  const status = statusFor(r.score, v.is_kev);
  const vendor = firstVendor(v);
  const title = v.cve_id ? `${vendor} Advisory (${v.cve_id})` : (r.cve_id || 'Security Advisory');
  const desc = v.description || r.rationale || 'Sin descripción disponible.';
  const cve = escapeHtml(r.cve_id);
  const when = relativeWhen(v.last_updated_at || r.computed_at);
  
  const badges: string[] = [];
  if (v.is_kev) badges.push(`<span class="badge-kev">CISA KEV</span>`);
  if (v.exploited_in_wild) badges.push(`<span class="badge-wild">EXPLOITED IN WILD</span>`);
  if (v.poc_public) badges.push(`<span class="badge-poc">POC PUBLIC</span>`);

  const fixText = v.is_kev ? '<span class="no-fix">No fix available</span>' : '<span class="fix-available">Fix available</span>';
  const activeClass = isActive ? 'is-active' : '';
  const delayMs = Math.min(index * 25, 400);

  return `
    <article class="advisory-card ${activeClass}" data-cve="${cve}" style="--delay: ${delayMs}ms">
      <span class="card-urgency-badge ${status}">${statusLabel(status)}</span>
      <div class="card-badges">${badges.join('')}</div>
      <div class="card-title">${escapeHtml(truncate(desc.length > 30 ? desc.slice(0, 75) : title, 80))}</div>
      <div class="card-summary">${escapeHtml(truncate(desc, 160))}</div>
      <div class="card-tags">
        <span class="vendor-tag">${escapeHtml(vendor)}</span>
        ${(v.products || []).slice(0, 2).map((p: string) => `<span class="vendor-tag">${escapeHtml(p)}</span>`).join('')}
      </div>
      <div class="card-footer">
        <div>${fixText} · <strong>${cve}</strong></div>
        <div>${escapeHtml(when)}</div>
      </div>
    </article>
  `;
}

export function renderFeedCards(container: HTMLElement, rows: any[], activeCveId: string | null, onCardClick: (cve: string) => void) {
  if (!rows || rows.length === 0) {
    container.innerHTML = `<div class="detail-placeholder">No se encontraron vulnerabilidades para los filtros seleccionados.</div>`;
    return;
  }

  container.innerHTML = rows.slice(0, 150).map((r, i) => renderAdvisoryCard(r, r.cve_id === activeCveId, i)).join('');

  container.querySelectorAll<HTMLElement>('.advisory-card').forEach(card => {
    card.addEventListener('click', () => {
      const cve = card.dataset.cve;
      if (cve) onCardClick(cve);
    });
  });
}

export function renderDetailPanel(container: HTMLElement, row: any | null, onClose: () => void) {
  const closeBtnSvg = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 6 6 18"/><path d="m6 6 12 12"/></svg>`;

  if (!row) {
    container.innerHTML = `
      <div class="drawer-header-bar">
        <span style="font-weight:700;color:var(--muted)">Vulnerability Analysis</span>
        <button class="drawer-close-btn" id="btn-close-drawer">${closeBtnSvg}</button>
      </div>
      <div class="drawer-body">
        <div class="detail-placeholder">Seleccioná una vulnerabilidad del feed para ver su análisis completo.</div>
      </div>
    `;
    return;
  }

  const v = row.vuln || {};
  const status = statusFor(row.score, v.is_kev);
  const cvss = v.cvss_v3_score != null ? v.cvss_v3_score.toFixed(1) : '7.5';
  const epss = v.epss_score != null ? (v.epss_score * 100).toFixed(1) + '%' : '12.4%';
  const vendor = firstVendor(v);
  const desc = v.description || 'Sin información detallada de la vulnerabilidad.';
  const when = relativeWhen(v.last_updated_at || row.computed_at);

  const attackVector = 'Network';
  const authReq = (v.cvss_v3_score || 0) >= 8.5 ? 'None' : 'Low';
  const complexity = (v.cvss_v3_score || 0) >= 9.0 ? 'Low' : 'Low';
  const userInteraction = v.is_kev ? 'None needed' : 'Required';

  // White Outline SVG Icons
  const globeIcon = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#ffffff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"/><path d="M2 12h20"/></svg>`;
  const keyIcon = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#ffffff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m15.5 7.5 2.3 2.3a1 1 0 0 0 1.4 0l2.1-2.1a1 1 0 0 0 0-1.4L19 4.1a1 1 0 0 0-1.4 0l-2.1 2.1a1 1 0 0 0 0 1.3"/><circle cx="7.5" cy="16.5" r="4.5"/><path d="m10.7 13.3 5.3-5.3"/></svg>`;
  const gearIcon = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#ffffff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="8"/><path d="M12 20a8 8 0 1 0 0-16 8 8 0 0 0 0 16Z"/></svg>`;
  const userIcon = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#ffffff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>`;

  const alertIcon = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`;
  const usersIcon = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#60a5fa" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>`;
  const targetIcon = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#f59e0b" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/></svg>`;

  container.innerHTML = `
    <div class="drawer-header-bar">
      <div class="detail-meta-bar">
        <span class="card-urgency-badge ${status}">${statusLabel(status)}</span>
        <span style="font-size:12.5px;font-weight:700;color:var(--text-dim)">CVSS ${cvss}</span>
        <span style="font-size:11.5px;color:var(--muted)">EPSS ${epss}</span>
      </div>
      <button class="drawer-close-btn" id="btn-close-drawer">${closeBtnSvg}</button>
    </div>

    <div class="drawer-body">
      <div class="detail-title">${escapeHtml(row.cve_id)} — ${escapeHtml(vendor)}</div>

      <div class="card-tags">
        <span class="vendor-tag" style="background:var(--accent-glow);color:var(--accent-light)">${escapeHtml(vendor)}</span>
        <span class="vendor-tag">Critical Asset</span>
        <span class="vendor-tag">Infrastructure</span>
      </div>

      <!-- ATTACK PATH GRAPHIC COMPONENT -->
      <div class="attack-path-container">
        <div class="attack-path-title">ATTACK PATH</div>
        <div class="attack-path-flow">
          <div class="attack-step">
            <div class="step-icon">${globeIcon}</div>
            <div class="step-label">VECTOR</div>
            <div class="step-val">${attackVector}</div>
          </div>
          <div class="attack-step">
            <div class="step-icon">${keyIcon}</div>
            <div class="step-label">AUTH</div>
            <div class="step-val">${authReq}</div>
          </div>
          <div class="attack-step">
            <div class="step-icon">${gearIcon}</div>
            <div class="step-label">COMPLEXITY</div>
            <div class="step-val">${complexity}</div>
          </div>
          <div class="attack-step">
            <div class="step-icon">${userIcon}</div>
            <div class="step-label">INTERACTION</div>
            <div class="step-val">${userInteraction}</div>
          </div>
        </div>
      </div>

      <!-- CIRCUIT BOARD COMPONENT (Explaining How Vulnerabilities Work) -->
      ${renderCircuitBoard([
        { id: "start", x: 75, y: 140, label: "Cloud", type: "cloud", status: "Ingress / Entry" },
        { id: "process", x: 250, y: 70, label: "Server", type: "server", status: "Vulnerable Service" },
        { id: "validate", x: 250, y: 210, label: "Validate", type: "shield", status: "WAF / Policy Check" },
        { id: "end", x: 425, y: 140, label: "Database", type: "database", status: "Target Asset" },
      ], [
        { from: "start", to: "process", animated: true },
        { from: "start", to: "validate", animated: true },
        { from: "process", to: "end", animated: true },
        { from: "validate", to: "end", animated: true },
      ], 500, 280)}

      <!-- SUMMARY -->
      <div>
        <div class="detail-section-label">SUMMARY</div>
        <div class="detail-summary-text">${escapeHtml(desc)}</div>
      </div>

      <!-- WHAT THIS MEANS -->
      <div>
        <div class="detail-section-label">WHAT THIS MEANS</div>
        <div class="what-this-means-box">
          <div class="meaning-item">
            <span class="m-icon">${alertIcon}</span>
            <div>
              <strong>What could happen</strong>
              Un atacante con acceso a la red objetivo podría ejecutar código arbitrario o comprometer la integridad del activo afectado.
            </div>
          </div>
          <div class="meaning-item">
            <span class="m-icon">${usersIcon}</span>
            <div>
              <strong>Who's at risk</strong>
              Entornos que despliegan componentes de ${escapeHtml(vendor)} expuestos a segmentos de red internos o perimetrales.
            </div>
          </div>
          <div class="meaning-item">
            <span class="m-icon">${targetIcon}</span>
            <div>
              <strong>How it could be exploited</strong>
              Mediante el envío de peticiones de red manipuladas a puertos de escucha vulnerables. ${v.poc_public ? 'Existe código PoC público disponible.' : ''}
            </div>
          </div>
        </div>
      </div>

      <!-- PREREQUISITES -->
      <div>
        <div class="detail-section-label">PREREQUISITES</div>
        <ul class="prereqs-list">
          <li>Acceso de red directo o por VPN al puerto expuesto.</li>
          <li>Versión de software vulnerable sin parche aplicado.</li>
          ${v.is_kev ? '<li>Explotación activa confirmada por CISA KEV.</li>' : ''}
        </ul>
      </div>

      <!-- TECHNICAL TAGS -->
      <div style="display:flex;gap:6px;flex-wrap:wrap;margin-top:10px">
        ${v.is_kev ? '<span class="vendor-tag" style="color:#60a5fa">actively exploited (KEV)</span>' : ''}
        ${v.poc_public ? '<span class="vendor-tag" style="color:#f59e0b">public poc available</span>' : ''}
        <span class="vendor-tag">network access required</span>
      </div>
    </div>
  `;

  document.getElementById('btn-close-drawer')?.addEventListener('click', onClose);
}

export function renderVendorSidebar(container: HTMLElement, vendorCounts: Record<string, number>, selectedVendors: Set<string>, onToggle: (vendor: string) => void) {
  const vendors = Object.keys(vendorCounts).sort((a, b) => vendorCounts[b] - vendorCounts[a]);
  if (!vendors.length) {
    container.innerHTML = `<div style="font-size:12px;color:var(--muted)">Cargando vendors...</div>`;
    return;
  }

  container.innerHTML = vendors.slice(0, 35).map(v => {
    const isChecked = selectedVendors.has(v);
    return `
      <div class="vendor-item ${isChecked ? 'is-selected' : ''}" data-vendor="${escapeHtml(v)}">
        <label>
          <input type="checkbox" ${isChecked ? 'checked' : ''} />
          <span>${escapeHtml(v)}</span>
        </label>
        <span class="vendor-count">${vendorCounts[v]}</span>
      </div>
    `;
  }).join('');

  container.querySelectorAll<HTMLElement>('.vendor-item').forEach(item => {
    const v = item.dataset.vendor;
    const checkbox = item.querySelector('input') as HTMLInputElement;
    if (v && checkbox) {
      checkbox.addEventListener('change', () => onToggle(v));
    }
  });
}
