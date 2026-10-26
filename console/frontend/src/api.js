// Thin client for the console BFF. The session cookie is http-only; the browser
// sends it (credentials: 'include'), the access token never reaches the SPA.
// Every call resolves to the JSON body or throws an ApiError carrying the
// status and, for 403s, which console capability was missing.
export class ApiError extends Error {
  constructor(status, body) {
    // the reference (request_id) names the request in the BFF's and pgauthzd's logs:
    // kept in the message so every error box, copied or screenshotted, carries it
    super((body?.error ?? body?.message ?? `HTTP ${status}`) + (body?.request_id ? ` (ref ${body.request_id})` : ''));
    this.status = status;
    this.requestId = body?.request_id;
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
  /** @returns {Promise<import('./types.js').Me>} */
  me: () => call('api/me', undefined, { allow: [401] }),
  version: () => call('api/version'),
  login: (next, issuer) => {
    location.href = 'auth/login?next=' + enc(next ?? location.pathname) + (issuer ? '&issuer=' + enc(issuer) : '');
  },
  logout: () => {
    location.href = 'auth/logout';
  },
  // The local admin sign-in (no IdP): offered when api/me says login.local.
  localLogin: (username, password) => call('auth/local', { username, password }),

  /** @returns {Promise<import('./types.js').StoreList>} */
  stores: () => call('api/stores'),
  createStore: (name, description, group) => call('api/stores', group === undefined ? { name, description } : { name, description, group }),
  adoptStore: (store) => call(`api/stores/${enc(store)}/adopt`, {}),
  deleteStore: (store, confirm, purgeAudit, purgeDecisions) =>
    call(`api/stores/${enc(store)}/delete`, {
      confirm,
      purge_audit: purgeAudit,
      purge_decisions: purgeDecisions,
    }),
  retireStore: (store, confirm) => call(`api/stores/${enc(store)}/retire`, { confirm }),
  /** @returns {Promise<import('./types.js').StoreRow>} */
  store: (store) => call(`api/stores/${enc(store)}`),

  /** @returns {Promise<import('./types.js').ModelResponse>} */
  model: (store) => call(`api/stores/${enc(store)}/model`),
  modelEdit: (store, op, edit) => call(`api/stores/${enc(store)}/model/${enc(op)}`, edit),
  modelBatch: (store, ops) => call(`api/stores/${enc(store)}/model/batch`, { ops }),
  /** @returns {Promise<import('./types.js').DSLReport>} */
  modelDSL: (store, dsl) => call(`api/stores/${enc(store)}/model/dsl`, { dsl }),
  storeSettings: (store, settings) => call(`api/stores/${enc(store)}/settings`, settings),

  /** @returns {Promise<import('./types.js').TupleStats>} */
  tupleStats: (store) => call(`api/stores/${enc(store)}/tuples/stats`),
  /** @returns {Promise<import('./types.js').TupleList>} */
  tuples: (store, q, limit, offset = 0, sort = '', dir = 'asc') =>
    call(
      `api/stores/${enc(store)}/tuples?q=${enc(q ?? '')}&limit=${enc(limit ?? 500)}&offset=${enc(offset)}&sort=${enc(sort)}&dir=${enc(dir)}`,
    ),
  writeTuple: (store, t) => call(`api/stores/${enc(store)}/tuples`, t),
  tuplesExportURL: (store, format) => `api/stores/${enc(store)}/tuples/export?format=${enc(format)}`,
  /** @returns {Promise<import('./types.js').ImportPreview|import('./types.js').ImportResult>} */
  tuplesImport: (store, text, apply) => call(`api/stores/${enc(store)}/tuples/import`, { text, apply }),
  /** @returns {Promise<import('./types.js').ShareOptions>} */
  shareOptions: (store, o) =>
    call(
      `api/stores/${enc(store)}/share?object_type=${enc(o.object_type)}&object_id=${enc(o.object_id)}&actor_type=${enc(o.actor_type)}&actor_id=${enc(o.actor_id)}`,
    ),
  /** @returns {Promise<{ok: boolean, result: {granted: number, revoked: number}}>} */
  shareApply: (store, o, grants, revokes) =>
    call(`api/stores/${enc(store)}/share`, { ...o, grants, revokes }),
  /** @returns {Promise<import('./types.js').OffboardResult>} */
  offboard: (store, userType, userId, apply) =>
    call(`api/stores/${enc(store)}/tuples/offboard`, { user_type: userType, user_id: userId, apply }),
  deleteTuples: (store, tuples) => call(`api/stores/${enc(store)}/tuples/delete`, { tuples }),

  /** @returns {Promise<import('./types.js').Meta>} */
  meta: (store) => call(`api/stores/${enc(store)}/meta`),
  check: (store, q) => call(`api/stores/${enc(store)}/check`, q),
  explain: (store, q) => call(`api/stores/${enc(store)}/explain`, q),
  checkBatch: (store, q) => call(`api/stores/${enc(store)}/check/batch`, q),
  search: (store, q) => call(`api/stores/${enc(store)}/search`, q),
  evaluateCondition: (store, name, q) => call(`api/stores/${enc(store)}/conditions/${enc(name)}/evaluate`, q),
  decide: (store, q) => call(`api/stores/${enc(store)}/decide`, q),
  /** @returns {Promise<{actions: string[]}>} what the subject holds and may do on the object (list_actions) */
  actions: (store, q) => call(`api/stores/${enc(store)}/actions`, q),
  /** @returns {Promise<import('./types.js').Scenarios>} */
  scenarios: (store) => call(`api/stores/${enc(store)}/scenarios`),
  scenariosSave: (store, yaml) => call(`api/stores/${enc(store)}/scenarios`, { yaml }, { method: 'PUT' }),
  /** @returns {Promise<import('./types.js').ScenariosRun>} */
  scenariosRun: (store, yaml, only) =>
    call(`api/stores/${enc(store)}/scenarios/run`, only?.length ? { yaml, only } : { yaml }),
  /** @returns {Promise<{ok: boolean, cases?: number, tests?: number, error?: string, line?: number}>} */
  scenariosValidate: (store, yaml) => call(`api/stores/${enc(store)}/scenarios/validate`, { yaml }),
  /** @returns {Promise<{tree: object, redacted: boolean}>} */
  scenariosExplain: (store, yaml, q) => call(`api/stores/${enc(store)}/scenarios/explain`, { yaml, ...q }), // q: test, user, relation, object, successful_only, redact
  /** @returns {Promise<import('./types.js').ScenariosExport>} */
  scenariosExport: (store) => call(`api/stores/${enc(store)}/scenarios/export`),
  // the store's tuples in the native export shape — can_export, recorded as an export
  tuplesExportJSON: (store) => call(`api/stores/${enc(store)}/tuples/export?format=json`),

  /** @returns {Promise<import('./types.js').RolloutResponse>} */
  rollout: (store) => call(`api/stores/${enc(store)}/rollout`),
  publish: (store, name, description) => call(`api/stores/${enc(store)}/publish`, { name, description }),
  /** @returns {Promise<import('./types.js').PlanResponse>} */
  plan: (store, name, version) => call(`api/stores/${enc(store)}/plan`, { name, version }),
  apply: (store, name, version) => call(`api/stores/${enc(store)}/apply`, { name, version }),

  /** @returns {Promise<import('./types.js').ActivityResponse>} */
  activity: (store) => call(`api/stores/${enc(store)}/activity`),
  // The decision log (postgres sink): p = {subject, resource, action, outcome, from, to, before, limit}
  decisions: (store, p = {}) => call(`api/stores/${enc(store)}/decisions?${new URLSearchParams(p)}`),
  decisionsSummary: (store, p = {}) =>
    call(`api/stores/${enc(store)}/decisions/summary?${new URLSearchParams(p)}`),

  /** @returns {Promise<import('./types.js').OpsOverview>} */
  ops: (store) => call(`api/stores/${enc(store)}/ops`),
  opsRecorderGrant: (store, dbRole, actions) =>
    call(`api/stores/${enc(store)}/ops/recorders`, { db_role: dbRole, actions }),
  opsRecorderRevoke: (store, dbRole, actions) =>
    call(`api/stores/${enc(store)}/ops/recorders/revoke`, { db_role: dbRole, actions }),
  opsPurgeEvents: (store, before, force) =>
    call(`api/stores/${enc(store)}/ops/purge-events`, { before, force }),
  opsCleanupExpired: (store, grace) => call(`api/stores/${enc(store)}/ops/cleanup-expired`, { grace }),
  // Data subject requests (Store → Data subject): the export document, its download link, the erasure.
  /** @returns {Promise<import('./types.js').SubjectExport>} */
  subject: (store, subject, relations = '') =>
    call(`api/stores/${enc(store)}/subject?subject=${enc(subject)}&relations=${enc(relations)}`),
  // format: json (the whole document) | csv (the objects the subject relates to, for the application teams)
  subjectExportURL: (store, subject, format = 'json', relations = '') =>
    `api/stores/${enc(store)}/subject?subject=${enc(subject)}&relations=${enc(relations)}&format=${enc(format)}&download=1`,
  /** @returns {Promise<import('./types.js').SubjectErased>} */
  subjectErase: (store, body) => call(`api/stores/${enc(store)}/subject/erase`, body),
  /** @returns {Promise<import('./types.js').RedundantResult>} */
  opsRedundant: (store, objectType, relation, apply) =>
    call(`api/stores/${enc(store)}/ops/redundant`, { object_type: objectType, relation, apply }),
  /** @returns {Promise<import('./types.js').PlatformOps>} */
  platformOps: () => call('api/platform/ops'),
  platformEnsurePartitions: (monthsAhead) =>
    call('api/platform/partitions/ensure', { months_ahead: monthsAhead }),
  platformDropEventPartitions: (before, force) =>
    call('api/platform/partitions/drop-events', { before, force }),

  /** @returns {Promise<import('./types.js').AccessResponse>} */
  access: (store) => call(`api/stores/${enc(store)}/access`),
  accessAdd: (store, a) => call(`api/stores/${enc(store)}/access`, a),
  accessRemove: (store, items) => call(`api/stores/${enc(store)}/access/remove`, { items }),

  /** @returns {Promise<import('./types.js').RegistryResponse>} */
  registry: () => call('api/registry'),
  /** @returns {Promise<import('./types.js').PlatformInfo>} */
  platform: () => call('api/platform'),
  /** @returns {Promise<import('./types.js').AccessResponse>} */
  platformAccess: () => call('api/platform/access'),
  platformAccessAdd: (a) => call('api/platform/access', a),
  platformAccessRemove: (items) => call('api/platform/access/remove', { items }),
  // Platform → Issuers: the database-managed issuer bindings.
  /** @returns {Promise<import('./types.js').IssuersResponse>} */
  // store groups (ADR 0017)
  platformGroups: () => call('api/platform/groups'),
  groupCreate: (name, description) => call('api/platform/groups', { name, description }),
  groupUpdate: (group, description) => call(`api/platform/groups/${enc(group)}`, { description }, { method: 'PUT' }),
  groupDelete: (group) => call(`api/platform/groups/${enc(group)}/delete`, {}),
  groupAccess: (group) => call(`api/platform/groups/${enc(group)}/access`),
  groupAccessAdd: (group, a) => call(`api/platform/groups/${enc(group)}/access`, a),
  groupAccessRemove: (group, items) => call(`api/platform/groups/${enc(group)}/access/remove`, { items }),
  storeGroupSet: (store, group) => call(`api/stores/${enc(store)}/group`, { group }, { method: 'PUT' }),
  groupConsumers: (group) => call(`api/platform/groups/${enc(group)}/consumers`),
  groupConsumerGrant: (group, consumer) => call(`api/platform/groups/${enc(group)}/consumers`, { consumer }),
  groupConsumerRevoke: (group, consumer) => call(`api/platform/groups/${enc(group)}/consumers/revoke`, { consumer }),
  platformIssuers: () => call('api/platform/issuers'),
  /** @returns {Promise<import('./types.js').IssuerAuditPage>} */
  platformIssuersAudit: (p = {}) => call(`api/platform/issuers/audit?${new URLSearchParams(p)}`),
  /** @param {import('./types.js').IssuerBinding} b */
  platformIssuerSave: (b) => call('api/platform/issuers', b, { method: 'PUT' }),
  platformIssuerDelete: (issuer, store_group = '') => call('api/platform/issuers/delete', store_group ? { issuer, store_group } : { issuer }),
  platformIssuerDiscover: (issuer, url) => call(`api/platform/issuers/discover?issuer=${enc(issuer)}${url ? '&url=' + enc(url) : ''}`),
  platformIssuerSignin: (b) => call('api/platform/issuers/signin', b, { method: 'PUT' }),
  platformIssuerSigninDelete: (issuer, store_group) => call('api/platform/issuers/signin/delete', { issuer, store_group }),
  /** @returns {Promise<import('./types.js').PoliciesResponse>} */
  policies: (store) => call(`api/stores/${enc(store)}/policies`),
  /** @returns {Promise<import('./types.js').NamespacesResponse>} */
  namespaces: (store) => call(`api/stores/${enc(store)}/namespaces`),
  namespaceAccessAdd: (store, ns, a) => call(`api/stores/${enc(store)}/namespaces/${enc(ns)}/access`, a),
  namespaceAccessRemove: (store, ns, items) =>
    call(`api/stores/${enc(store)}/namespaces/${enc(ns)}/access/remove`, { items }),
  namespaceRename: (store, ns, to) => call(`api/stores/${enc(store)}/namespaces/${enc(ns)}/rename`, { to }),
};
