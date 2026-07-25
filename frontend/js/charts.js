/* ==========================================================================
   Chart.js theming helpers
   ========================================================================== */

const CHART_COLORS = {
  grid: 'rgba(255,255,255,0.045)',
  text: '#8b93ac',
  low: '#34d399',
  medium: '#fbbf24',
  high: '#fb7185',
  critical: '#ff3366',
  blue: '#4c8dff',
  cyan: '#35d9e8',
  purple: '#9d6bff',
};

Chart.defaults.color = CHART_COLORS.text;
Chart.defaults.font.family = "'Inter', sans-serif";
Chart.defaults.font.size = 11;

const activeCharts = {};

function destroyChart(id) {
  if (activeCharts[id]) { activeCharts[id].destroy(); delete activeCharts[id]; }
}

function makeRiskDonut(canvasId, dist) {
  destroyChart(canvasId);
  const ctx = document.getElementById(canvasId);
  if (!ctx) return;
  const labels = ['Critical', 'High', 'Medium', 'Low'];
  const colors = [CHART_COLORS.critical, CHART_COLORS.high, CHART_COLORS.medium, CHART_COLORS.low];
  const data = labels.map(l => dist[l] || 0);
  activeCharts[canvasId] = new Chart(ctx, {
    type: 'doughnut',
    data: { labels, datasets: [{ data, backgroundColor: colors, borderWidth: 0, hoverOffset: 6 }] },
    options: {
      cutout: '72%',
      plugins: { legend: { display: false } },
      animation: { animateRotate: true, duration: 900 },
    },
  });
}

function makeAttackBar(canvasId, counts) {
  destroyChart(canvasId);
  const ctx = document.getElementById(canvasId);
  if (!ctx) return;
  const entries = Object.entries(counts).sort((a, b) => b[1] - a[1]);
  activeCharts[canvasId] = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: entries.map(e => e[0].replace(/_/g, ' ')),
      datasets: [{
        data: entries.map(e => e[1]),
        backgroundColor: 'rgba(76,141,255,0.55)',
        hoverBackgroundColor: CHART_COLORS.blue,
        borderRadius: 6,
        maxBarThickness: 22,
      }],
    },
    options: {
      indexAxis: 'y',
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { color: CHART_COLORS.grid }, ticks: { font: { size: 10.5 } } },
        y: { grid: { display: false }, ticks: { font: { size: 10.5 } } },
      },
    },
  });
}

function makeTimelineChart(canvasId, rows) {
  destroyChart(canvasId);
  const ctx = document.getElementById(canvasId);
  if (!ctx) return;
  const labels = rows.map(r => new Date(r.timestamp).toLocaleDateString(undefined, { month: 'short', day: 'numeric' }));
  activeCharts[canvasId] = new Chart(ctx, {
    type: 'line',
    data: {
      labels,
      datasets: [
        {
          label: 'Alerts',
          data: rows.map(r => r.alerts),
          borderColor: CHART_COLORS.critical,
          backgroundColor: 'rgba(255,51,102,0.12)',
          fill: true, tension: 0.35, pointRadius: 0, borderWidth: 2, yAxisID: 'y',
        },
        {
          label: 'Total events',
          data: rows.map(r => r.total_events),
          borderColor: 'rgba(140,154,255,0.5)',
          backgroundColor: 'transparent',
          fill: false, tension: 0.35, pointRadius: 0, borderWidth: 1.5, borderDash: [4, 3], yAxisID: 'y1',
        },
      ],
    },
    options: {
      interaction: { mode: 'index', intersect: false },
      plugins: { legend: { position: 'top', align: 'end', labels: { boxWidth: 10, font: { size: 10.5 } } } },
      scales: {
        x: { grid: { display: false }, ticks: { font: { size: 10 }, maxRotation: 0 } },
        y: { position: 'left', grid: { color: CHART_COLORS.grid }, ticks: { font: { size: 10 } } },
        y1: { position: 'right', grid: { display: false }, ticks: { font: { size: 10 } } },
      },
    },
  });
}

function makeHeatmap(containerId, rows) {
  const el = document.getElementById(containerId);
  if (!el) return;
  const days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];
  const byKey = {};
  let max = 0.0001;
  rows.forEach(r => { byKey[`${r.weekday}-${r.hour}`] = r; max = Math.max(max, r.risk_score); });

  let html = '<div style="display:grid; grid-template-columns: 60px repeat(24, 1fr); gap:3px; font-family:var(--font-mono); font-size:9px;">';
  html += `<div></div>`;
  for (let h = 0; h < 24; h++) html += `<div style="text-align:center; color:var(--text-tertiary);">${h % 3 === 0 ? h : ''}</div>`;
  days.forEach(d => {
    html += `<div style="color:var(--text-tertiary); display:flex; align-items:center;">${d.slice(0, 3)}</div>`;
    for (let h = 0; h < 24; h++) {
      const cell = byKey[`${d}-${h}`];
      const score = cell ? cell.risk_score : 0;
      const alertCount = cell ? cell.alert_count : 0;
      const intensity = Math.min(1, score / max);
      const bg = alertCount > 0
        ? `rgba(255,51,102,${0.15 + intensity * 0.7})`
        : `rgba(76,141,255,${0.06 + intensity * 0.22})`;
      html += `<div title="${d} ${h}:00 — avg risk ${score}, ${alertCount} alerts" style="aspect-ratio:1; border-radius:3px; background:${bg}; cursor:default;"></div>`;
    }
  });
  html += '</div>';
  el.innerHTML = html;
}

function makeFeatureImportanceChart(canvasId, rows) {
  destroyChart(canvasId);
  const ctx = document.getElementById(canvasId);
  if (!ctx) return;
  const sorted = [...rows].sort((a, b) => a.avg_contribution_pct - b.avg_contribution_pct);
  activeCharts[canvasId] = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: sorted.map(r => r.feature.replace(/_/g, ' ')),
      datasets: [{
        data: sorted.map(r => r.avg_contribution_pct),
        backgroundColor: sorted.map((_, i) => `rgba(${76 + i * 6},${141 - i * 3},255,0.7)`),
        borderRadius: 5,
        maxBarThickness: 16,
      }],
    },
    options: {
      indexAxis: 'y',
      plugins: { legend: { display: false }, tooltip: { callbacks: { label: (c) => `${c.raw}% avg contribution` } } },
      scales: {
        x: { grid: { color: CHART_COLORS.grid }, ticks: { font: { size: 10 } }, title: { display: true, text: 'avg contribution %', color: CHART_COLORS.text, font: { size: 10 } } },
        y: { grid: { display: false }, ticks: { font: { size: 10.5 } } },
      },
    },
  });
}

function makeBehaviorTimelineChart(canvasId, rows) {
  destroyChart(canvasId);
  const ctx = document.getElementById(canvasId);
  if (!ctx) return;
  activeCharts[canvasId] = new Chart(ctx, {
    type: 'line',
    data: {
      labels: rows.map(r => new Date(r.timestamp).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })),
      datasets: [{
        label: 'Risk score',
        data: rows.map(r => r.risk_score),
        borderColor: CHART_COLORS.purple,
        backgroundColor: 'rgba(157,107,255,0.12)',
        fill: true, tension: 0.3, pointRadius: 2, pointBackgroundColor: CHART_COLORS.purple, borderWidth: 2,
      }],
    },
    options: {
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { display: false }, ticks: { font: { size: 9 }, maxRotation: 0, autoSkip: true, maxTicksLimit: 8 } },
        y: { min: 0, max: 100, grid: { color: CHART_COLORS.grid }, ticks: { font: { size: 10 } } },
      },
    },
  });
}
