/* ==========================================================================
   Page renderers — each Pages.xxx(root) fetches its data and injects HTML
   into #page-root. Kept framework-free (template strings + event delegation)
   for zero build step.
   ========================================================================== */

const Pages = {};

function riskClass(level) { return (level || 'low').toLowerCase(); }
function fmtPct(x) { return `${(x * 100).toFixed(1)}%`; }
function fmtTime(ts) { return new Date(ts).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }); }

function skeleton(h = 120) {
  return `<div class="loading-shimmer" style="height:${h}px; width:100%;"></div>`;
}

/* ---------------------------------------------------------------------- */
/* HOME                                                                     */
/* ---------------------------------------------------------------------- */

Pages.home = async function (root) {
  root.innerHTML = `
    <div class="grid grid-kpis" style="margin-bottom:18px;">
      <div class="card kpi-card kpi-critical">${skeleton(90)}</div>
      <div class="card kpi-card kpi-blue">${skeleton(90)}</div>
      <div class="card kpi-card kpi-purple">${skeleton(90)}</div>
      <div class="card kpi-card kpi-cyan">${skeleton(90)}</div>
    </div>
    <div class="grid grid-2" style="margin-bottom:18px;">
      <div class="card"><div class="card-header"><div><h3>Threat Radar</h3><div class="sub">Live high-risk contacts by entity — closer to center = more urgent</div></div></div>
        <div class="radar-wrap"><div id="radar-target"></div></div>
        <div class="radar-legend">
          <span><i style="background:#ff3366;"></i>Critical</span>
          <span><i style="background:#fb7185;"></i>High</span>
          <span><i style="background:#fbbf24;"></i>Medium</span>
        </div>
      </div>
      <div class="card"><div class="card-header"><div><h3>Risk Distribution</h3><div class="sub">Across all scored events</div></div></div>
        <div style="height:200px;"><canvas id="chart-risk-donut"></canvas></div>
        <div id="donut-legend" style="margin-top:14px; display:flex; flex-direction:column; gap:8px;"></div>
      </div>
    </div>
    <div class="grid grid-2" style="margin-bottom:18px;">
      <div class="card"><div class="card-header"><div><h3>Alert Timeline</h3><div class="sub">Daily volume vs. total traffic</div></div></div>
        <div style="height:230px;"><canvas id="chart-timeline"></canvas></div>
      </div>
      <div class="card"><div class="card-header"><div><h3>Top Attack Types</h3><div class="sub">By predicted classification</div></div></div>
        <div style="height:230px;"><canvas id="chart-attack-bar"></canvas></div>
      </div>
    </div>
    <div class="card">
      <div class="card-header"><div><h3>Access Heatmap</h3><div class="sub">Average risk score by hour &amp; weekday · red cells contain active alerts</div></div></div>
      <div id="heatmap-target" style="overflow-x:auto; padding-top:4px;"></div>
    </div>
  `;

  const [dash, timeline, attackAlerts, heat] = await Promise.all([
    Api.dashboard(), Api.timeline('D'), Api.alerts({ limit: 200 }), Api.heatmap(),
  ]);

  document.getElementById('live-count').textContent = dash.live_threat_count.toLocaleString();
  document.getElementById('nav-alert-badge').textContent = dash.live_threat_count.toLocaleString();
  document.getElementById('sf-baseline').textContent = dash.model_backends.baseline;
  document.getElementById('sf-classifier').textContent = dash.model_backends.classifier;

  const kpiGrid = root.querySelector('.grid-kpis');
  kpiGrid.innerHTML = `
    <div class="card kpi-card kpi-critical">
      <div class="icon-badge"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 9v4M12 17h.01M10.3 3.86L1.8 18a1.8 1.8 0 0 0 1.55 2.7h17.3A1.8 1.8 0 0 0 22.2 18L13.7 3.86a1.8 1.8 0 0 0-3.4 0z"/></svg></div>
      <div class="label">Live Threats</div>
      <div class="value">${dash.live_threat_count.toLocaleString()}</div>
      <div class="delta">High + Critical risk events</div>
    </div>
    <div class="card kpi-card kpi-blue">
      <div class="icon-badge"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="17" rx="2"/><path d="M8 2v4M16 2v4M3 9h18"/></svg></div>
      <div class="label">Today's Alerts</div>
      <div class="value">${dash.today_alert_count.toLocaleString()}</div>
      <div class="delta">Since 00:00 (dataset clock)</div>
    </div>
    <div class="card kpi-card kpi-purple">
      <div class="icon-badge"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 12A10 10 0 1 1 12 2"/><path d="M22 2 12 12"/></svg></div>
      <div class="label">Detection Recall</div>
      <div class="value">${fmtPct(dash.detection_rate)}</div>
      <div class="delta">FPR ${fmtPct(dash.false_positive_rate)}</div>
    </div>
    <div class="card kpi-card kpi-cyan">
      <div class="icon-badge"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 3"/></svg></div>
      <div class="label">Entities Monitored</div>
      <div class="value">${dash.total_entities.toLocaleString()}</div>
      <div class="delta">${dash.total_events.toLocaleString()} total events scored</div>
    </div>
  `;

  renderThreatRadar('radar-target', attackAlerts.alerts);
  makeRiskDonut('chart-risk-donut', dash.risk_distribution);
  const legend = document.getElementById('donut-legend');
  const total = Object.values(dash.risk_distribution).reduce((a, b) => a + b, 0);
  legend.innerHTML = ['Critical', 'High', 'Medium', 'Low'].map(l => {
    const v = dash.risk_distribution[l] || 0;
    return `<div style="display:flex; justify-content:space-between; align-items:center; font-size:12px;">
      <span class="badge-risk ${riskClass(l)}">${l}</span>
      <span class="mono" style="color:var(--text-secondary);">${v.toLocaleString()} <span style="color:var(--text-tertiary);">(${total ? ((v / total) * 100).toFixed(1) : 0}%)</span></span>
    </div>`;
  }).join('');

  makeTimelineChart('chart-timeline', timeline);
  makeAttackBar('chart-attack-bar', dash.top_attack_types);
  makeHeatmap('heatmap-target', heat);
};

/* ---------------------------------------------------------------------- */
/* ALERTS                                                                   */
/* ---------------------------------------------------------------------- */

let alertsState = { risk_level: '', attack_type: '', offset: 0, limit: 50 };

Pages.alerts = async function (root) {
  root.innerHTML = `
    <div class="filters-row">
      <button class="btn-filter active" data-risk="">All</button>
      <button class="btn-filter" data-risk="Critical">Critical</button>
      <button class="btn-filter" data-risk="High">High</button>
      <button class="btn-filter" data-risk="Medium">Medium</button>
      <select id="attack-type-filter">
        <option value="">All attack types</option>
        <option value="brute_force">Brute Force</option>
        <option value="credential_stuffing">Credential Stuffing</option>
        <option value="impossible_travel">Impossible Travel</option>
        <option value="device_spoofing">Device Spoofing</option>
        <option value="lateral_movement">Lateral Movement</option>
        <option value="low_and_slow_exfiltration">Low &amp; Slow Exfiltration</option>
        <option value="insider_drift">Insider Drift</option>
      </select>
      <div style="margin-left:auto; font-size:12px; color:var(--text-tertiary);" id="alerts-count"></div>
    </div>
    <div class="card" style="padding:0;">
      <div style="overflow-x:auto;">
      <table>
        <thead><tr>
          <th>Risk</th><th>Entity</th><th>Attack Type</th><th>Resource</th><th>Location</th><th>Confidence</th><th>Time</th>
        </tr></thead>
        <tbody id="alerts-tbody"><tr><td colspan="7">${skeleton(200)}</td></tr></tbody>
      </table>
      </div>
      <div style="display:flex; justify-content:center; gap:10px; padding:16px;">
        <button class="btn-filter" id="alerts-prev">← Prev</button>
        <button class="btn-filter" id="alerts-next">Next →</button>
      </div>
    </div>
  `;

  root.querySelectorAll('.btn-filter[data-risk]').forEach(btn => {
    btn.addEventListener('click', () => {
      root.querySelectorAll('.btn-filter[data-risk]').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      alertsState.risk_level = btn.dataset.risk;
      alertsState.offset = 0;
      loadAlertsTable();
    });
  });
  document.getElementById('attack-type-filter').addEventListener('change', (e) => {
    alertsState.attack_type = e.target.value;
    alertsState.offset = 0;
    loadAlertsTable();
  });
  document.getElementById('alerts-prev').addEventListener('click', () => {
    alertsState.offset = Math.max(0, alertsState.offset - alertsState.limit);
    loadAlertsTable();
  });
  document.getElementById('alerts-next').addEventListener('click', () => {
    alertsState.offset += alertsState.limit;
    loadAlertsTable();
  });

  await loadAlertsTable();
};

async function loadAlertsTable() {
  const params = { limit: alertsState.limit, offset: alertsState.offset, only_flagged: 'true' };
  if (alertsState.risk_level) params.risk_level = alertsState.risk_level;
  if (alertsState.attack_type) params.attack_type = alertsState.attack_type;
  const data = await Api.alerts(params);
  const tbody = document.getElementById('alerts-tbody');
  if (!tbody) return;
  document.getElementById('alerts-count').textContent = `${data.total.toLocaleString()} matching alerts`;

  if (data.alerts.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7"><div class="empty-state">No alerts match these filters.</div></td></tr>`;
    return;
  }

  tbody.innerHTML = data.alerts.map(a => `
    <tr data-event-id="${a.event_id}">
      <td>
        <div style="display:flex; align-items:center; gap:8px;">
          <span class="badge-risk ${riskClass(a.risk_level)}">${a.risk_level}</span>
          <span class="mono" style="font-size:11.5px; color:var(--text-secondary);">${a.risk_score}</span>
        </div>
      </td>
      <td><div class="cell-entity">${a.entity_id}</div><div class="cell-sub">${a.entity_type}</div></td>
      <td>${(a.predicted_attack_type || '').replace(/_/g, ' ')}</td>
      <td class="cell-mono">${a.resource_accessed}</td>
      <td class="cell-mono">${a.city}, ${a.country}</td>
      <td class="cell-mono">${(a.prediction_confidence * 100).toFixed(0)}%</td>
      <td class="cell-mono">${fmtTime(a.timestamp)}</td>
    </tr>
  `).join('');

  tbody.querySelectorAll('tr[data-event-id]').forEach(tr => {
    tr.addEventListener('click', () => openAlertDrawer(tr.dataset.eventId));
  });
}

async function openAlertDrawer(eventId) {
  const overlay = document.createElement('div');
  overlay.className = 'drawer-overlay';
  overlay.innerHTML = `<div class="drawer"><div class="drawer-close">&times;</div>${skeleton(300)}</div>`;
  document.getElementById('drawer-root').appendChild(overlay);
  overlay.addEventListener('click', (e) => { if (e.target === overlay) overlay.remove(); });
  overlay.querySelector('.drawer-close').addEventListener('click', () => overlay.remove());

  const d = await Api.alertDetail(eventId);
  const drawer = overlay.querySelector('.drawer');
  const factors = (d.top_features || []).map(f => `
    <div class="factor-row">
      <div class="flabel"><span class="fname">${f.feature.replace(/_/g, ' ')}</span><span class="fpct">${f.contribution_pct}%</span></div>
      <div class="factor-bar-track"><div class="factor-bar-fill" style="width:${f.contribution_pct}%;"></div></div>
    </div>
  `).join('') || `<div style="color:var(--text-tertiary); font-size:12.5px;">No detailed attribution computed for this event (outside top-risk explained set).</div>`;

  drawer.innerHTML = `
    <div class="drawer-close">&times;</div>
    <span class="badge-risk ${riskClass(d.risk_level)}" style="margin-bottom:10px;">${d.risk_level} · ${d.risk_score}/100</span>
    <h2>${(d.predicted_attack_type || '').replace(/_/g, ' ')}</h2>
    <div class="drawer-sub">${d.entity_id} (${d.entity_type}) · ${fmtTime(d.timestamp)}</div>

    <div class="explain-box">${d.explanation}</div>

    <div class="mitre-box">
      <div class="mitre-chip"><span class="l">MITRE Tactic</span>${d.mitre_tactic}</div>
      <div class="mitre-chip"><span class="l">Technique</span>${d.mitre_technique}</div>
    </div>

    <div class="card-header"><h3 style="font-size:12.5px;">Contributing Factors</h3></div>
    ${factors}

    <div class="kv-grid">
      <div><div class="kv-label">Source IP</div><div class="kv-value">${d.source_ip}</div></div>
      <div><div class="kv-label">Location</div><div class="kv-value">${d.city}, ${d.country}</div></div>
      <div><div class="kv-label">Resource</div><div class="kv-value">${d.resource_accessed}</div></div>
      <div><div class="kv-label">Auth Method</div><div class="kv-value">${d.authentication_method}</div></div>
      <div><div class="kv-label">Device</div><div class="kv-value">${d.device_id}</div></div>
      <div><div class="kv-label">OS</div><div class="kv-value">${d.operating_system}</div></div>
      <div><div class="kv-label">Anomaly Score</div><div class="kv-value">${d.anomaly_score}</div></div>
      <div><div class="kv-label">Confidence</div><div class="kv-value">${(d.prediction_confidence * 100).toFixed(1)}%</div></div>
    </div>

    <div class="card-header"><h3 style="font-size:12.5px;">Recommended Response</h3></div>
    <div class="response-box">${d.recommended_response}</div>

    <div class="card-header"><h3 style="font-size:12.5px;">Analyst Feedback</h3></div>
    <div class="feedback-row" id="feedback-row-${d.event_id}">
      <button class="fb-btn tp" data-verdict="true_positive">True Positive</button>
      <button class="fb-btn fp" data-verdict="false_positive">False Positive</button>
      <button class="fb-btn" data-verdict="needs_investigation">Investigate</button>
      <button class="fb-btn" data-verdict="ignore">Ignore</button>
    </div>
  `;

  drawer.querySelector('.drawer-close').addEventListener('click', () => overlay.remove());
  drawer.querySelectorAll('.fb-btn').forEach(btn => {
    btn.addEventListener('click', async () => {
      await Api.submitFeedback(d.event_id, btn.dataset.verdict);
      drawer.querySelectorAll('.fb-btn').forEach(b => b.classList.remove('recorded'));
      btn.classList.add('recorded');
      btn.textContent += ' ✓';
    });
  });
}

/* ---------------------------------------------------------------------- */
/* ENTITIES                                                                  */
/* ---------------------------------------------------------------------- */

Pages.entities = async function (root) {
  root.innerHTML = `
    <div class="entity-layout">
      <div class="card" style="max-height:640px; overflow-y:auto;">
        <div class="card-header"><h3>Entities</h3></div>
        <div id="entity-list">${skeleton(400)}</div>
      </div>
      <div class="card" id="entity-detail-panel">
        <div class="empty-state">Select an entity to view its behavioral profile, history, and risk timeline.</div>
      </div>
    </div>
  `;
  const list = await Api.entities('');
  renderEntityList(list);
};

function renderEntityList(entities) {
  const el = document.getElementById('entity-list');
  if (!el) return;
  if (entities.length === 0) { el.innerHTML = `<div class="empty-state">No entities found.</div>`; return; }
  el.innerHTML = entities.map(e => `
    <div class="entity-list-item" data-entity-id="${e.entity_id}">
      <div><div class="ename">${e.entity_id}</div><div class="etype">${e.entity_type}</div></div>
      <span class="badge-risk ${riskClass(e.max_risk >= 85 ? 'Critical' : e.max_risk >= 65 ? 'High' : e.max_risk >= 40 ? 'Medium' : 'Low')}">${e.max_risk}</span>
    </div>
  `).join('');
  el.querySelectorAll('.entity-list-item').forEach(item => {
    item.addEventListener('click', () => {
      el.querySelectorAll('.entity-list-item').forEach(i => i.classList.remove('active'));
      item.classList.add('active');
      loadEntityDetail(item.dataset.entityId);
    });
  });
}

async function loadEntityDetail(entityId) {
  const panel = document.getElementById('entity-detail-panel');
  panel.innerHTML = skeleton(400);
  const d = await Api.entityDetail(entityId);

  panel.innerHTML = `
    <div class="card-header">
      <div>
        <h3 style="font-size:17px;">${d.entity_id}</h3>
        <div class="sub">${d.entity_type} · ${d.total_events} events · ${d.total_alerts} alerts</div>
      </div>
      <span class="badge-risk ${riskClass(d.max_risk_score >= 85 ? 'Critical' : d.max_risk_score >= 65 ? 'High' : d.max_risk_score >= 40 ? 'Medium' : 'Low')}">Peak ${d.max_risk_score}</span>
    </div>

    <div style="margin-bottom:16px;">
      <div class="kv-label" style="margin-bottom:6px;">Home Locations</div>
      ${(d.home_cities || []).map(c => `<span class="tag-chip">${c}</span>`).join('') || '<span class="cell-sub">—</span>'}
    </div>
    <div style="margin-bottom:16px;">
      <div class="kv-label" style="margin-bottom:6px;">Typical Resources</div>
      ${(d.typical_resources || []).map(r => `<span class="tag-chip">${r}</span>`).join('')}
    </div>
    <div style="margin-bottom:20px;">
      <div class="kv-label" style="margin-bottom:6px;">Known Devices</div>
      ${(d.known_device_ids || []).map(dv => `<span class="tag-chip mono">${dv}</span>`).join('')}
    </div>

    <div class="card-header"><h3 style="font-size:13px;">Behavior / Risk Timeline</h3></div>
    <div style="height:180px; margin-bottom:20px;"><canvas id="entity-behavior-chart"></canvas></div>

    <div class="card-header"><h3 style="font-size:13px;">Recent Activity</h3></div>
    <div style="max-height:300px; overflow-y:auto;">
    <table>
      <thead><tr><th>Time</th><th>Resource</th><th>Location</th><th>Device</th><th>Risk</th></tr></thead>
      <tbody>
        ${d.history.slice().reverse().slice(0, 40).map(h => `
          <tr>
            <td class="cell-mono">${fmtTime(h.timestamp)}</td>
            <td class="cell-mono">${h.resource_accessed}</td>
            <td class="cell-mono">${h.city}</td>
            <td class="cell-mono">${h.device_id}</td>
            <td><span class="badge-risk ${riskClass(h.risk_level)}">${h.risk_score}</span></td>
          </tr>
        `).join('')}
      </tbody>
    </table>
    </div>
  `;
  makeBehaviorTimelineChart('entity-behavior-chart', d.behavior_timeline);
}

/* ---------------------------------------------------------------------- */
/* MAP                                                                       */
/* ---------------------------------------------------------------------- */

let leafletMap = null;

Pages.map = async function (root) {
  root.innerHTML = `
    <div class="filters-row">
      <button class="btn-filter active" data-risk="">All flagged</button>
      <button class="btn-filter" data-risk="Critical">Critical</button>
      <button class="btn-filter" data-risk="High">High</button>
      <button class="btn-filter" data-risk="Medium">Medium</button>
    </div>
    <div id="map-container"></div>
  `;

  root.querySelectorAll('.btn-filter').forEach(btn => {
    btn.addEventListener('click', () => {
      root.querySelectorAll('.btn-filter').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      loadMapPoints(btn.dataset.risk);
    });
  });

  if (!leafletMap) {
    leafletMap = L.map('map-container', { worldCopyJump: true }).setView([20, 10], 2);
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
      attribution: '&copy; OpenStreetMap &copy; CARTO', subdomains: 'abcd', maxZoom: 19,
    }).addTo(leafletMap);
  } else {
    setTimeout(() => leafletMap.invalidateSize(), 50);
  }
  await loadMapPoints('');
};

let mapMarkers = [];
async function loadMapPoints(riskLevel) {
  const points = await Api.map(riskLevel);
  mapMarkers.forEach(m => leafletMap.removeLayer(m));
  mapMarkers = [];
  points.forEach(p => {
    const color = RISK_COLOR[p.risk_level] || '#4c8dff';
    const marker = L.circleMarker([p.latitude, p.longitude], {
      radius: p.risk_level === 'Critical' ? 8 : p.risk_level === 'High' ? 6 : 4.5,
      color, weight: 1.5, fillColor: color, fillOpacity: 0.55,
    }).addTo(leafletMap);
    marker.bindPopup(`
      <div class="map-popup">
        <div class="mp-title">${p.entity_id}</div>
        <div class="mp-row">${(p.predicted_attack_type || '').replace(/_/g, ' ')} · risk ${p.risk_score}</div>
        <div class="mp-row">${p.city}, ${p.country}</div>
        <div class="mp-row">${fmtTime(p.timestamp)}</div>
      </div>
    `);
    mapMarkers.push(marker);
  });
}

/* ---------------------------------------------------------------------- */
/* ANALYTICS                                                                 */
/* ---------------------------------------------------------------------- */

Pages.analytics = async function (root) {
  root.innerHTML = `
    <div class="grid grid-kpis" style="margin-bottom:18px;">
      <div class="metric-pill">${skeleton(50)}</div>
      <div class="metric-pill">${skeleton(50)}</div>
      <div class="metric-pill">${skeleton(50)}</div>
      <div class="metric-pill">${skeleton(50)}</div>
    </div>
    <div class="grid grid-2" style="margin-bottom:18px;">
      <div class="card">
        <div class="card-header"><div><h3>Confusion Matrix</h3><div class="sub">Held-out test set, true class (rows) vs predicted (cols)</div></div></div>
        <div id="cm-target" style="overflow-x:auto;"></div>
      </div>
      <div class="card">
        <div class="card-header"><div><h3>Global Feature Importance</h3><div class="sub">Aggregated from per-alert attributions</div></div></div>
        <div style="height:320px;"><canvas id="chart-feat-importance"></canvas></div>
      </div>
    </div>
    <div class="card">
      <div class="card-header"><div><h3>Per-Class Performance</h3><div class="sub">Precision / Recall / F1, held-out test set</div></div></div>
      <div id="perclass-target" style="overflow-x:auto;"></div>
    </div>
  `;

  const [analytics, featImp] = await Promise.all([Api.analytics(), Api.featureImportance()]);

  const kpiGrid = root.querySelector('.grid-kpis');
  const bin = analytics.binary_attack_detection;
  kpiGrid.innerHTML = `
    <div class="metric-pill"><div class="mval">${(analytics.overall_accuracy * 100).toFixed(1)}%</div><div class="mlbl">Overall Accuracy</div></div>
    <div class="metric-pill"><div class="mval">${(analytics.macro_f1 * 100).toFixed(1)}%</div><div class="mlbl">Macro F1 (all classes)</div></div>
    <div class="metric-pill"><div class="mval">${(analytics.roc_auc_macro_ovr * 100).toFixed(1)}%</div><div class="mlbl">ROC-AUC (macro OvR)</div></div>
    <div class="metric-pill"><div class="mval">${(bin.recall * 100).toFixed(1)}%</div><div class="mlbl">Attack Recall (FPR ${(bin.false_positive_rate * 100).toFixed(2)}%)</div></div>
  `;

  renderConfusionMatrix('cm-target', analytics.confusion_matrix, analytics.confusion_matrix_labels);
  renderPerClassTable('perclass-target', analytics.per_class_report);
  makeFeatureImportanceChart('chart-feat-importance', featImp);
};

function renderConfusionMatrix(containerId, matrix, labels) {
  const el = document.getElementById(containerId);
  const max = Math.max(...matrix.flat());
  let html = '<table class="cm-table"><thead><tr><th></th>' + labels.map(l => `<th>${l.slice(0, 10)}</th>`).join('') + '</tr></thead><tbody>';
  matrix.forEach((row, i) => {
    html += `<tr><th style="text-align:right;">${labels[i].slice(0, 14)}</th>`;
    row.forEach((v, j) => {
      const intensity = max ? v / max : 0;
      const bg = i === j ? `rgba(52,211,153,${0.12 + intensity * 0.55})` : `rgba(255,51,102,${v ? 0.1 + intensity * 0.45 : 0.02})`;
      html += `<td><div class="cm-cell" style="background:${bg}; padding:5px 0;">${v}</div></td>`;
    });
    html += '</tr>';
  });
  html += '</tbody></table>';
  el.innerHTML = html;
}

function renderPerClassTable(containerId, report) {
  const el = document.getElementById(containerId);
  const rows = Object.entries(report).filter(([k]) => !['accuracy', 'macro avg', 'weighted avg'].includes(k));
  let html = `<table><thead><tr><th>Class</th><th>Precision</th><th>Recall</th><th>F1</th><th>Support</th></tr></thead><tbody>`;
  rows.forEach(([cls, m]) => {
    html += `<tr>
      <td>${cls.replace(/_/g, ' ')}</td>
      <td class="cell-mono">${(m.precision * 100).toFixed(1)}%</td>
      <td class="cell-mono">${(m.recall * 100).toFixed(1)}%</td>
      <td class="cell-mono">${(m['f1-score'] * 100).toFixed(1)}%</td>
      <td class="cell-mono">${m.support}</td>
    </tr>`;
  });
  html += '</tbody></table>';
  el.innerHTML = html;
}
