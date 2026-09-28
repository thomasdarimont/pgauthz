// Thin client for the BFF. The session cookie is http-only, so we just rely on
// the browser sending it (credentials: 'include'); the access token never reaches
// the SPA — the BFF injects it server-side.
async function call(path, body, allow = []) {
  const r = await fetch(path, {
    method: body ? 'POST' : 'GET',
    headers: body ? { 'Content-Type': 'application/json' } : {},
    credentials: 'include',
    body: body ? JSON.stringify(body) : undefined,
  });
  let json = null;
  try {
    json = await r.json();
  } catch {
    /* non-JSON */
  }
  // Surface backend failures as thrown errors so callers (via _run) show them
  // instead of silently rendering empty/undefined/stale state. `allow` lists
  // non-2xx statuses that are a valid response (e.g. /api/me → 401 when logged out).
  if (!r.ok && !allow.includes(r.status)) {
    // BFF errors are {error}; pgauthzd errors (proxied verbatim) are {status, message}.
    throw new Error(json?.error ?? json?.message ?? `HTTP ${r.status}`);
  }
  return { status: r.status, body: json };
}

export const api = {
  me: () => call('api/me', undefined, [401]), // 401 = logged out, a normal response
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
  // AuthZEN console: proxied to the authzen-opa service with the user's token.
  // `store` scopes the call to the selected store (tenant path form on the service).
  authzenConfig: (store) =>
    call(
      'api/authzen/config' + (store ? '?store=' + encodeURIComponent(store) : ''),
      undefined,
      [401, 502, 503],
    ),
  authzen: (endpoint, body, store) =>
    call(
      'api/authzen/' + endpoint + (store ? '?store=' + encodeURIComponent(store) : ''),
      body,
      [400, 401, 403, 502, 503],
    ),
  // Action-log demo: record / reserve via pgauthzd-full (user's token), reset via the BFF.
  eventsRecord: (body) => call('api/events/record', body),
  eventsReserve: (body) => call('api/events/reserve', body),
  eventsReset: (store) => call('api/events/reset', { store }),
  login: () => {
    location.href = 'auth/login';
  },
  logout: () => {
    location.href = 'auth/logout';
  },
};
