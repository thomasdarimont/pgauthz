// Thin client for the console BFF. The session cookie is http-only; the browser
// sends it (credentials: 'include'), the access token never reaches the SPA.
// Every call resolves to the JSON body or throws an ApiError carrying the
// status and, for 403s, which console capability was missing.
export class ApiError extends Error {
  constructor(status, body) {
    super(body?.error ?? body?.message ?? `HTTP ${status}`);
    this.status = status;
    this.required = body?.required;
    this.object = body?.object;
    this.code = body?.code;
  }
}

async function call(path, body, { method, allow = [] } = {}) {
  const r = await fetch(path, {
    method: method ?? (body ? 'POST' : 'GET'),
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
  if (!r.ok && !allow.includes(r.status)) throw new ApiError(r.status, json);
  return json;
}

const enc = encodeURIComponent;

export const api = {
  me: () => call('api/me', undefined, { allow: [401] }),
  version: () => call('api/version'),
  login: (next) => {
    location.href = 'auth/login?next=' + enc(next ?? location.pathname);
  },
  logout: () => {
    location.href = 'auth/logout';
  },
  // The local admin sign-in (no IdP): offered when api/me says login.local.
  localLogin: (username, password) => call('auth/local', { username, password }),

  stores: () => call('api/stores'),
  createStore: (name, description) => call('api/stores', { name, description }),
  adoptStore: (store) => call(`api/stores/${enc(store)}/adopt`, {}),
  deleteStore: (store, confirm, purgeAudit) =>
    call(`api/stores/${enc(store)}/delete`, { confirm, purge_audit: purgeAudit }),
  retireStore: (store, confirm) => call(`api/stores/${enc(store)}/retire`, { confirm }),
  store: (store) => call(`api/stores/${enc(store)}`),

  model: (store) => call(`api/stores/${enc(store)}/model`),
  modelEdit: (store, op, edit) => call(`api/stores/${enc(store)}/model/${enc(op)}`, edit),
  modelBatch: (store, ops) => call(`api/stores/${enc(store)}/model/batch`, { ops }),
  modelDSL: (store, dsl) => call(`api/stores/${enc(store)}/model/dsl`, { dsl }),
  storeSettings: (store, settings) => call(`api/stores/${enc(store)}/settings`, settings),

  tupleStats: (store) => call(`api/stores/${enc(store)}/tuples/stats`),
  tuples: (store, q, limit, offset = 0, sort = '', dir = 'asc') =>
    call(
      `api/stores/${enc(store)}/tuples?q=${enc(q ?? '')}&limit=${enc(limit ?? 500)}&offset=${enc(offset)}&sort=${enc(sort)}&dir=${enc(dir)}`,
    ),
  writeTuple: (store, t) => call(`api/stores/${enc(store)}/tuples`, t),
  tuplesExportURL: (store, format) => `api/stores/${enc(store)}/tuples/export?format=${enc(format)}`,
  tuplesImport: (store, text, apply) => call(`api/stores/${enc(store)}/tuples/import`, { text, apply }),
  offboard: (store, userType, userId, apply) =>
    call(`api/stores/${enc(store)}/tuples/offboard`, { user_type: userType, user_id: userId, apply }),
  deleteTuples: (store, tuples) => call(`api/stores/${enc(store)}/tuples/delete`, { tuples }),

  meta: (store) => call(`api/stores/${enc(store)}/meta`),
  check: (store, q) => call(`api/stores/${enc(store)}/check`, q),
  explain: (store, q) => call(`api/stores/${enc(store)}/explain`, q),
  checkBatch: (store, q) => call(`api/stores/${enc(store)}/check/batch`, q),
  search: (store, q) => call(`api/stores/${enc(store)}/search`, q),
  evaluateCondition: (store, name, q) => call(`api/stores/${enc(store)}/conditions/${enc(name)}/evaluate`, q),
  decide: (store, q) => call(`api/stores/${enc(store)}/decide`, q),

  rollout: (store) => call(`api/stores/${enc(store)}/rollout`),
  publish: (store, name, description) => call(`api/stores/${enc(store)}/publish`, { name, description }),
  plan: (store, name, version) => call(`api/stores/${enc(store)}/plan`, { name, version }),
  apply: (store, name, version) => call(`api/stores/${enc(store)}/apply`, { name, version }),

  activity: (store) => call(`api/stores/${enc(store)}/activity`),

  ops: (store) => call(`api/stores/${enc(store)}/ops`),
  opsRecorderGrant: (store, dbRole, actions) =>
    call(`api/stores/${enc(store)}/ops/recorders`, { db_role: dbRole, actions }),
  opsRecorderRevoke: (store, dbRole, actions) =>
    call(`api/stores/${enc(store)}/ops/recorders/revoke`, { db_role: dbRole, actions }),
  opsPurgeEvents: (store, before, force) =>
    call(`api/stores/${enc(store)}/ops/purge-events`, { before, force }),
  opsCleanupExpired: (store, grace) => call(`api/stores/${enc(store)}/ops/cleanup-expired`, { grace }),
  opsRedundant: (store, objectType, relation, apply) =>
    call(`api/stores/${enc(store)}/ops/redundant`, { object_type: objectType, relation, apply }),
  platformOps: () => call('api/platform/ops'),
  platformEnsurePartitions: (monthsAhead) =>
    call('api/platform/partitions/ensure', { months_ahead: monthsAhead }),
  platformDropEventPartitions: (before, force) =>
    call('api/platform/partitions/drop-events', { before, force }),

  access: (store) => call(`api/stores/${enc(store)}/access`),
  accessAdd: (store, a) => call(`api/stores/${enc(store)}/access`, a),
  accessRemove: (store, items) => call(`api/stores/${enc(store)}/access/remove`, { items }),

  registry: () => call('api/registry'),
  platform: () => call('api/platform'),
  platformAccess: () => call('api/platform/access'),
  platformAccessAdd: (a) => call('api/platform/access', a),
  platformAccessRemove: (items) => call('api/platform/access/remove', { items }),
  policies: (store) => call(`api/stores/${enc(store)}/policies`),
  namespaces: (store) => call(`api/stores/${enc(store)}/namespaces`),
  namespaceAccessAdd: (store, ns, a) => call(`api/stores/${enc(store)}/namespaces/${enc(ns)}/access`, a),
  namespaceAccessRemove: (store, ns, items) =>
    call(`api/stores/${enc(store)}/namespaces/${enc(ns)}/access/remove`, { items }),
  namespaceRename: (store, ns, to) => call(`api/stores/${enc(store)}/namespaces/${enc(ns)}/rename`, { to }),
};
