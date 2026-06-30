// Thin client for the BFF. The session cookie is http-only, so we just rely on
// the browser sending it (credentials: 'include'); the access token never reaches
// the SPA — the BFF injects it server-side.
async function call(path, body) {
  const r = await fetch(path, {
    method: body ? 'POST' : 'GET',
    headers: body ? { 'Content-Type': 'application/json' } : {},
    credentials: 'include',
    body: body ? JSON.stringify(body) : undefined,
  });
  let json = null;
  try { json = await r.json(); } catch { /* non-JSON */ }
  return { status: r.status, body: json };
}

export const api = {
  me: () => call('api/me'),
  // Names for autocomplete (read-only engine metadata).
  metaStores: () => call('api/meta/stores'),
  metaRelations: (store) => call('api/meta/relations?store=' + encodeURIComponent(store)),
  metaObjects: (store) => call('api/meta/objects?store=' + encodeURIComponent(store)),
  metaSubjects: (store) => call('api/meta/subjects?store=' + encodeURIComponent(store)),
  metaTypes: (store) => call('api/meta/types?store=' + encodeURIComponent(store)),
  // Explore mode (engine-direct, read-only, arbitrary subjects).
  model: (store) => call('api/model?store=' + encodeURIComponent(store)),
  tuples: (store) => call('api/tuples?store=' + encodeURIComponent(store)),
  conditions: (store) => call('api/conditions?store=' + encodeURIComponent(store)),
  exploreCheck: (body) => call('api/explore/check', body),
  exploreExplain: (body) => call('api/explore/explain', body),
  // "As me" mode: q(rule, input) → OPA's result for data.authz.<rule> with the user's token.
  q: (rule, input) => call('api/q', { rule, input }),
  login: () => { location.href = 'auth/login'; },
  logout: () => { location.href = 'auth/logout'; },
};
