/**
 * CircuitBoard Component
 * Renders an SVG + HTML circuit board diagram explaining vulnerability data flow.
 */

export interface CircuitNode {
  id: string;
  x: number;
  y: number;
  label: string;
  type?: 'cloud' | 'server' | 'shield' | 'database';
  status?: string;
}

export interface CircuitConnection {
  from: string;
  to: string;
  animated?: boolean;
}

export function renderCircuitBoard(
  nodes: CircuitNode[] = [
    { id: "start", x: 75, y: 140, label: "Cloud", type: "cloud", status: "Ingress / Entry" },
    { id: "process", x: 250, y: 70, label: "Server", type: "server", status: "Vulnerable Service" },
    { id: "validate", x: 250, y: 210, label: "Validate", type: "shield", status: "WAF / Policy Check" },
    { id: "end", x: 425, y: 140, label: "Database", type: "database", status: "Target Asset" },
  ],
  connections: CircuitConnection[] = [
    { from: "start", to: "process", animated: true },
    { from: "start", to: "validate", animated: true },
    { from: "process", to: "end", animated: true },
    { from: "validate", to: "end", animated: true },
  ],
  width: number = 500,
  height: number = 280
): string {
  const nodeMap = new Map<string, CircuitNode>();
  nodes.forEach(n => nodeMap.set(n.id, n));

  // Icons SVG
  const icons: Record<string, string> = {
    cloud: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M175 19a5 5 0 0 0 2-9.6A7 7 0 1 0 5 16.5A5 5 0 0 0 8 19h9.5z"/></svg>`,
    server: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="20" height="8" x="2" y="2" rx="2" ry="2"/><rect width="20" height="8" x="2" y="14" rx="2" ry="2"/><line x1="6" x2="6.01" y1="6" y2="6"/><line x1="6" x2="6.01" y1="18" y2="18"/></svg>`,
    shield: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`,
    database: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>`,
  };

  // Generate SVG path definitions for PCB circuit traces
  const pathsSVG = connections.map((conn, idx) => {
    const fromNode = nodeMap.get(conn.from);
    const toNode = nodeMap.get(conn.to);
    if (!fromNode || !toNode) return '';

    const midX = (fromNode.x + toNode.x) / 2;
    // Orthogonal PCB trace path
    const pathD = `M ${fromNode.x} ${fromNode.y} H ${midX} V ${toNode.y} H ${toNode.x}`;
    const dur = 2.2 + idx * 0.4;

    return `
      <!-- Base PCB trace background line -->
      <path d="${pathD}" fill="none" stroke="var(--border-2)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
      
      <!-- Highlight glowing trace line -->
      <path d="${pathD}" fill="none" stroke="var(--accent-light)" stroke-width="1.5" stroke-opacity="0.4" stroke-dasharray="4 4" stroke-linecap="round"/>
      
      ${conn.animated ? `
        <!-- Animated signal pulse dot along trace -->
        <circle r="3.5" fill="var(--accent-light)" filter="drop-shadow(0 0 6px var(--accent))">
          <animateMotion path="${pathD}" dur="${dur}s" repeatCount="indefinite" />
        </circle>
        <circle r="1.5" fill="#ffffff">
          <animateMotion path="${pathD}" dur="${dur}s" repeatCount="indefinite" />
        </circle>
      ` : ''}
    `;
  }).join('');

  // Generate Node Cards
  const nodesHTML = nodes.map(node => {
    const iconSvg = icons[node.type || 'server'] || icons.server;
    const isThreat = node.id === 'process';
    const isSecure = node.id === 'validate';
    
    let accentStyle = 'border-color: var(--accent-border);';
    if (isThreat) accentStyle = 'border-color: rgba(239, 68, 68, 0.4); background: rgba(239, 68, 68, 0.06);';
    if (isSecure) accentStyle = 'border-color: rgba(16, 185, 129, 0.4); background: rgba(16, 185, 129, 0.06);';

    return `
      <foreignObject x="${node.x - 55}" y="${node.y - 32}" width="110" height="64">
        <div xmlns="http://www.w3.org/1999/xhtml" class="circuit-node-card" style="${accentStyle}">
          <div class="circuit-node-icon ${isThreat ? 'icon-threat' : isSecure ? 'icon-secure' : ''}">
            ${iconSvg}
          </div>
          <div class="circuit-node-info">
            <div class="circuit-node-label">${node.label}</div>
            ${node.status ? `<div class="circuit-node-status">${node.status}</div>` : ''}
          </div>
        </div>
      </foreignObject>
    `;
  }).join('');

  return `
    <div class="circuit-board-wrap">
      <div class="circuit-board-header">
        <div class="circuit-board-title">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="20" height="20" rx="2"/><path d="M6 12h12M12 6v12"/></svg>
          <span>EXPLOITATION FLOW &amp; CIRCUIT ARCHITECTURE</span>
        </div>
        <span class="circuit-live-badge"><span class="live-dot"></span> LIVE SIGNAL</span>
      </div>
      
      <div class="circuit-svg-container">
        <svg viewBox="0 0 ${width} ${height}" class="circuit-svg" preserveAspectRatio="xMidYMid meet">
          <!-- Background PCB Grid pattern -->
          <defs>
            <pattern id="pcb-grid" width="20" height="20" patternUnits="userSpaceOnUse">
              <circle cx="10" cy="10" r="1" fill="var(--border)" opacity="0.4"/>
            </pattern>
          </defs>
          <rect width="100%" height="100%" fill="url(#pcb-grid)"/>

          <!-- Traces and Signals -->
          <g class="circuit-traces">
            ${pathsSVG}
          </g>

          <!-- Node Elements -->
          <g class="circuit-nodes">
            ${nodesHTML}
          </g>
        </svg>
      </div>
    </div>
  `;
}
