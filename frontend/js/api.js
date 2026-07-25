/* ==========================================================================
   API client — thin fetch wrapper around the Flask backend.
   Set API_BASE to '' when the frontend is served BY the backend (default,
   see backend/app.py static routes). Point it at a different host if you
   run the frontend separately (e.g. `python -m http.server` in /frontend).
   ========================================================================== */

const API_BASE = (window.SENTINEL_API_BASE !== undefined) ? window.SENTINEL_API_BASE : '';

async function apiGet(path) {
  const res = await fetch(`${API_BASE}${path}`);
  if (!res.ok) throw new Error(`GET ${path} failed: ${res.status}`);
  return res.json();
}

async function apiPost(path, body) {
  const res = await fetch(`${API_BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body || {}),
  });
  if (!res.ok) throw new Error(`POST ${path} failed: ${res.status}`);
  return res.json();
}

const Api = {
  dashboard: () => apiGet('/api/dashboard'),
  alerts: (params = {}) => {
    const q = new URLSearchParams(params).toString();
    return apiGet(`/api/alerts?${q}`);
  },
  alertDetail: (eventId) => apiGet(`/api/alerts/${encodeURIComponent(eventId)}`),
  entities: (q = '') => apiGet(`/api/entities?q=${encodeURIComponent(q)}`),
  entityDetail: (entityId) => apiGet(`/api/entities/${encodeURIComponent(entityId)}`),
  analytics: () => apiGet('/api/analytics'),
  featureImportance: () => apiGet('/api/feature-importance'),
  heatmap: () => apiGet('/api/heatmap'),
  timeline: (granularity = 'D') => apiGet(`/api/timeline?granularity=${granularity}`),
  map: (riskLevel = '') => apiGet(`/api/map${riskLevel ? `?risk_level=${riskLevel}` : ''}`),
  submitFeedback: (eventId, verdict) => apiPost('/api/feedback', { event_id: eventId, verdict }),
  predict: (payload) => apiPost('/api/predict', payload),
};
