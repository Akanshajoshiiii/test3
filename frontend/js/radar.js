/* ==========================================================================
   Threat Radar — the dashboard's signature visual.
   A sweeping SOC-style radar plotting the current highest-risk entities:
     - angle  = stable hash of entity_id (so a given entity always sits at
                the same bearing, like a real radar contact)
     - radius = INVERTED risk (critical-risk entities plot closest to the
                center "contact" zone, low-risk drift to the outer rings) —
                mirrors how an analyst reads urgency on a real radar scope.
   Pure SVG + CSS animation, no chart library needed.
   ========================================================================== */

function hashAngle(str) {
  let h = 0;
  for (let i = 0; i < str.length; i++) { h = (h * 31 + str.charCodeAt(i)) >>> 0; }
  return (h % 360) * (Math.PI / 180);
}

const RISK_COLOR = {
  Low: '#34d399',
  Medium: '#fbbf24',
  High: '#fb7185',
  Critical: '#ff3366',
};

function renderThreatRadar(containerId, alerts) {
  const el = document.getElementById(containerId);
  if (!el) return;
  const cx = 170, cy = 170, maxR = 148;

  const rings = [0.25, 0.5, 0.75, 1.0].map(f =>
    `<circle class="radar-ring" cx="${cx}" cy="${cy}" r="${maxR * f}" />`
  ).join('');

  const crosshair = `
    <line class="radar-crosshair" x1="${cx - maxR}" y1="${cy}" x2="${cx + maxR}" y2="${cy}" />
    <line class="radar-crosshair" x1="${cx}" y1="${cy - maxR}" x2="${cx}" y2="${cy + maxR}" />
  `;

  // top ~26 highest-risk, non-Low alerts as radar contacts
  const contacts = alerts
    .filter(a => a.risk_level !== 'Low')
    .slice(0, 26)
    .map(a => {
      const angle = hashAngle(a.entity_id || a.event_id || 'x');
      const urgency = a.risk_score / 100; // 0..1, higher = more urgent
      const radius = maxR * (0.14 + (1 - urgency) * 0.8); // urgent -> near center
      const x = cx + radius * Math.cos(angle);
      const y = cy + radius * Math.sin(angle);
      const color = RISK_COLOR[a.risk_level] || RISK_COLOR.Medium;
      const r = a.risk_level === 'Critical' ? 5.5 : a.risk_level === 'High' ? 4.5 : 3.5;
      const pulseClass = a.risk_level === 'Critical' ? 'radar-blip-pulse' : '';
      return `<circle class="radar-blip ${pulseClass}" cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="${r}" fill="${color}">
        <title>${a.entity_id} — ${a.risk_level} (${a.risk_score}) — ${(a.predicted_attack_type || '').replace(/_/g, ' ')}</title>
      </circle>`;
    }).join('');

  el.innerHTML = `
    <svg class="radar-svg" viewBox="0 0 340 340" xmlns="http://www.w3.org/2000/svg">
      <defs>
        <radialGradient id="radarBg" cx="50%" cy="50%" r="50%">
          <stop offset="0%" stop-color="rgba(76,141,255,0.10)" />
          <stop offset="100%" stop-color="rgba(76,141,255,0)" />
        </radialGradient>
        <linearGradient id="sweepGradient" x1="0%" y1="0%" x2="100%" y2="0%">
          <stop offset="0%" stop-color="rgba(76,141,255,0)" />
          <stop offset="100%" stop-color="rgba(76,141,255,0.9)" />
        </linearGradient>
        <linearGradient id="sweepFill" x1="0%" y1="100%" x2="100%" y2="0%">
          <stop offset="0%" stop-color="rgba(76,141,255,0.22)" />
          <stop offset="100%" stop-color="rgba(76,141,255,0)" />
        </linearGradient>
      </defs>
      <circle cx="${cx}" cy="${cy}" r="${maxR}" fill="url(#radarBg)" />
      ${rings}
      ${crosshair}
      <g class="radar-sweep-group">
        <path d="M ${cx} ${cy} L ${cx + maxR} ${cy} A ${maxR} ${maxR} 0 0 1 ${(cx + maxR * Math.cos(-0.6)).toFixed(1)} ${(cy + maxR * Math.sin(-0.6)).toFixed(1)} Z" fill="url(#sweepFill)" />
        <line class="radar-sweep-line" x1="${cx}" y1="${cy}" x2="${cx + maxR}" y2="${cy}" />
      </g>
      ${contacts}
      <circle class="radar-center" cx="${cx}" cy="${cy}" r="3.5" />
    </svg>
  `;
}
