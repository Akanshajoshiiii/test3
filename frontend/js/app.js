/* ==========================================================================
   App bootstrap — hash router + global search + live SSE badge updates
   ========================================================================== */

const PAGE_META = {
  home: { title: 'Security Overview', sub: 'Real-time behavioral anomaly detection across users, service accounts & edge devices' },
  alerts: { title: 'Alert Queue', sub: 'Ranked by composite risk score — click a row for full explainability' },
  entities: { title: 'Entity Profiles', sub: 'Per-entity behavioral baseline, history, and risk trend' },
  map: { title: 'Threat Map', sub: 'Geolocated high-risk activity' },
  analytics: { title: 'Model Analytics', sub: 'Detection performance on held-out data' },
};

async function navigate(route) {
  if (!Pages[route]) route = 'home';
  document.querySelectorAll('.nav-item').forEach(n => n.classList.toggle('active', n.dataset.route === route));
  document.getElementById('page-title').textContent = PAGE_META[route].title;
  document.getElementById('page-subtitle').textContent = PAGE_META[route].sub;
  const root = document.getElementById('page-root');
  root.classList.remove('page');
  void root.offsetWidth;
  root.classList.add('page');
  try {
    await Pages[route](root);
  } catch (err) {
    console.error(err);
    root.innerHTML = `<div class="card"><div class="empty-state">
      Could not load data from the backend API.<br/>
      <span class="mono" style="font-size:11px;">${err.message}</span><br/><br/>
      Make sure the Flask backend is running: <span class="mono">python backend/app.py</span>
    </div></div>`;
  }
}

window.addEventListener('hashchange', () => navigate(location.hash.slice(1)));
window.addEventListener('DOMContentLoaded', () => {
  navigate(location.hash.slice(1) || 'home');

  // simple global search -> jumps to entities page filtered by query
  document.getElementById('global-search').addEventListener('keydown', async (e) => {
    if (e.key === 'Enter' && e.target.value.trim()) {
      location.hash = '#entities';
      setTimeout(async () => {
        const list = await Api.entities(e.target.value.trim());
        renderEntityList(list);
      }, 150);
    }
  });

  // periodic live-threat badge refresh (lightweight poll; SSE stream is
  // available at /api/stream for a true push-based feed if desired)
  setInterval(async () => {
    try {
      const d = await Api.dashboard();
      document.getElementById('live-count').textContent = d.live_threat_count.toLocaleString();
      document.getElementById('nav-alert-badge').textContent = d.live_threat_count.toLocaleString();
    } catch (e) { /* backend not reachable yet — ignore */ }
  }, 15000);
});
