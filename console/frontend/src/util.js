import { html } from 'lit';
import { t } from './i18n.js';

// Shared bits for the page components.

const CAP_LABELS = {
  can_view: 'view',
  can_run_tests: 'test',
  can_edit_model: 'edit model',
  can_publish: 'publish',
  can_rollout: 'roll out',
  can_grant: 'share',
  can_view_audit: 'audit',
  can_export: 'export',
  can_view_decisions: 'decisions',
  can_manage_access: 'manage access',
};

export function capLabel(cap) {
  return t(CAP_LABELS[cap] ?? cap);
}

const ROLE_HELP = {
  owner: 'everything on this store, including who else has access',
  author: 'edit the model and run tests',
  publisher: 'publish registry versions and roll them out; test; see decisions',
  sharer: 'grant and revoke relationships (write tuples)',
  tester: 'test their own access: checks and redacted trees (the test policy)',
  supporter: "look up and explain anyone's access with full trees; never edits",
  auditor: 'read the audit trail, action log and decisions',
  exporter: "export the store's tuples (JSON, CSV, OpenFGA); every export is recorded",
  viewer: 'read-only: model, data, rollout state',
  admin: 'platform admin: sees every store, adopts unclaimed stores, reassigns owners',
  issuer_admin: "manages the trusted identity providers' bindings (Platform → Issuers), nothing else",
};

export function roleHelp(role) {
  return ROLE_HELP[role] ? t(ROLE_HELP[role]) : '';
}

export function fmtTime(s) {
  if (!s) return '';
  const d = new Date(s);
  if (Number.isNaN(d.getTime())) return s;
  return d.toLocaleString(document.documentElement.lang || undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  });
}

// A store's managed-model badge: "saas_core@3", "@3 drifted" or "unmanaged".
/** @param {import('./types.js').Status} [st] */
export function statusBadge(st) {
  if (!st || !st.model_name) return html`<span class="badge muted">${t('unmanaged')}</span>`;
  const label = `${st.model_name}@${st.model_version}`;
  return st.in_sync
    ? html`<span class="badge ok" title=${t('live model matches the registry version')}>${label}</span>`
    : html`<span class="badge warn" title=${t('live model differs from the applied registry version')}
        >${label} · ${t('drifted')}</span
      >`;
}

// Render a tuple's subject: user:alice or team:x#member.
export function subjectOf(tu) {
  return `${tu.user_type}:${tu.user_id}${tu.user_relation ? '#' + tu.user_relation : ''}`;
}

export async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

// Wraps an async action: sets busy/error on the element while it runs; the
// element shows `error` instead of throwing.
export async function run(el, fn) {
  el.busy = true;
  el.error = '';
  try {
    return await fn();
  } catch (e) {
    if (!(e instanceof FieldInvalid)) el.error = e.message || String(e);
    return undefined;
  } finally {
    el.busy = false;
  }
}

// Thrown by a handler after it reported a mistake next to the field it is
// in (PgcJson.report): run() then shows no page-level box for it.
export class FieldInvalid extends Error {}

// A 403 from the BFF says which console capability was missing.
export function forbiddenText(e) {
  if (e?.status === 403 && e.required)
    return t('This needs "{capability}" on {object}.', {
      capability: capLabel(e.required),
      object: e.object,
    });
  return e?.message ?? String(e);
}

// Parse one-per-line (or comma-separated) identifiers from a textarea.
export function parseList(text) {
  return [
    ...new Set(
      String(text ?? '')
        .split(/[\n,]/)
        .map((x) => x.trim())
        .filter(Boolean),
    ),
  ];
}

// Sort relations by their metadata.ui_order (lowest first; unset after the
// ordered ones), then by name — the model's own idea of display order.
// Display only: ui_order never influences evaluation.
export function byOrder(items, metaOf = (r) => r.metadata) {
  const key = (r) => {
    const o = metaOf(r)?.ui_order;
    return typeof o === 'number' ? o : Number.POSITIVE_INFINITY;
  };
  return [...items].sort((a, b) => key(a) - key(b) || String(a.name).localeCompare(String(b.name)));
}

// Relative, locale-aware time: "in 2 hours", "3 days ago" (Intl.RelativeTimeFormat
// in the console's language). Picks the largest unit that is at least 1.
export function fmtRelative(s, now = Date.now()) {
  if (!s) return '';
  const d = new Date(s);
  if (Number.isNaN(d.getTime())) return s;
  const lang = document.documentElement.lang || undefined;
  const diff = (d.getTime() - now) / 1000;
  const units = [
    ['year', 31536000],
    ['month', 2592000],
    ['week', 604800],
    ['day', 86400],
    ['hour', 3600],
    ['minute', 60],
    ['second', 1],
  ];
  const rtf = new Intl.RelativeTimeFormat(lang, { numeric: 'auto' });
  for (const [unit, secs] of units) {
    if (Math.abs(diff) >= secs || unit === 'second')
      return rtf.format(Math.round(diff / secs), /** @type {Intl.RelativeTimeFormatUnit} */ (unit));
  }
  return '';
}
