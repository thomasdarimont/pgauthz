import { html, nothing } from 'lit';
import { PgcElement, help, errorBox } from '../base.js';
import { api } from '../api.js';
import { t } from '../i18n.js';
import { run, fmtTime, subjectOf } from '../util.js';

// Activity tab: what happened to this store — console actions (who edited,
// published, shared through the console), the tuple audit trail (every
// relationship change, by whom), the model change history (rules,
// conditions, gates and grant rules added or removed — the versioned parts
// of the model), and the store's own action log (what principals did, as
// recorded by its enforcement points).
export class PgcActivity extends PgcElement {
  static properties = {
    store: { type: String },
    caps: { attribute: false },
    d: { state: true },
    view: { state: true },
    busy: { state: true },
    error: { state: true },
  };

  constructor() {
    super();
    /** @type {import('../types.js').ActivityResponse|null} */
    this.d = null;
    this.view = 'console';
    this.busy = false;
    this.error = '';
  }

  willUpdate(changed) {
    if (changed.has('store') && this.store) void this._load();
  }

  async _load() {
    const d = await run(this, () => api.activity(this.store));
    if (d) this.d = d;
  }

  // Every log is the same five columns — when, what changed (a badge),
  // what kind of thing, the details, and who — so the eye lands in the
  // same place on each; the model changes view set the shape.
  static HEAD = (detailsHelp) =>
    html`<thead>
      <tr>
        <th>${t('When')}</th>
        <th>${t('Change')}</th>
        <th>${t('What')}</th>
        <th>${t('Details')} ${detailsHelp ? help(detailsHelp) : nothing}</th>
        <th>${t('By')}</th>
      </tr>
    </thead>`;

  _row(testid, when, change, what, details, by) {
    return html`<tr data-testid=${testid}>
      <td class="muted nowrap" title=${when}>${fmtTime(when)}</td>
      <td>${change}</td>
      <td>${what}</td>
      <td class="details">${details}</td>
      <td class="mono">${by}</td>
    </tr>`;
  }

  _badge(cls, text) {
    return html`<span class="badge ${cls}">${text}</span>`;
  }

  _changeBadge(action) {
    return this._badge(
      action === 'INSERT' ? 'ok' : action === 'DELETE' ? 'deny' : 'warn',
      t(action === 'INSERT' ? 'added' : action === 'DELETE' ? 'removed' : action.toLowerCase()),
    );
  }

  // The console's own action log for this store: the capability used as the
  // change, the operation as what, and the payload summarised.
  _console(events) {
    if (!events.length) return html`<div class="empty">${t('No console actions on this store yet.')}</div>`;
    // A recorded test: what was asked (check, explain, search) or how much (matrix).
    const test = (p) =>
      p?.checks !== undefined
        ? html`<span class="mono muted">${p.checks} ${t('checks')}</span>`
        : p?.subject !== undefined || p?.resource !== undefined
          ? html`<span class="mono muted"
              >${[p.subject, p.action, p.resource].filter(Boolean).join(' ')}${p.at ? ' @ ' + p.at : ''}</span
            >`
          : nothing;
    // An export: the format and how many rows left the system.
    const exp = (p) =>
      p?.op === 'export'
        ? html`<span class="mono muted">${p.format} · ${p.count} ${t('tuples')}</span>`
        : nothing;
    // A recorder allowlist change: the role and the actions.
    const rec = (p) =>
      p?.db_role
        ? html`<span class="mono muted">${p.db_role}: ${(p.actions ?? []).join(', ') || t('all')}</span>`
        : nothing;
    // A share: as whom, on what, how many grants and revokes.
    const share = (p) =>
      p?.op === 'share'
        ? html`<span class="mono muted"
            >${p.actor} → ${p.object}: ${p.grants} ${t('grant(s)')}, ${p.revokes} ${t('revoke(s)')}</span
          >`
        : nothing;
    const summary = (p) =>
      html`${exp(p)}${rec(p)}${share(p)}${test(p)}${p?.model ? html`<span class="mono">${p.model}${p.version ? '@' + p.version : ''}</span> ` : nothing}${
        p?.edit ? html`<span class="mono muted">${JSON.stringify(p.edit).slice(0, 120)}</span>` : nothing
      }${p?.ops ? html`<span class="mono muted">${p.ops.length} ${t('operations')}</span>` : nothing}${
        p?.tuple
          ? html`<span class="mono muted"
              >${subjectOf(p.tuple)} ${p.tuple.relation} ${p.tuple.object_type}:${p.tuple.object_id}</span
            >`
          : nothing
      }${p?.tuples ? html`<span class="mono muted">${p.tuples.length} ${t('tuples')}</span>` : nothing}${
        p?.access
          ? html`<span class="mono muted"
              >${p.access.subject_type}:${p.access.subject_id} ${t('as')} ${p.access.role}</span
            >`
          : nothing
      }${p?.items ? html`<span class="mono muted">${p.items.map((a) => `${a.subject_type}:${a.subject_id} ${t('as')} ${a.role}`).join(', ')}</span>` : nothing}${
        p?.docs_url !== undefined
          ? html`<span class="mono muted">${p.description} ${p.docs_url}</span>`
          : nothing
      }`;
    return html`<div class="table-wrap">
      <table data-testid="activity-console-table">
        ${PgcActivity.HEAD('What the action carried: the edit, the version, the tuple or the role it was about.')}
        <tbody>
          ${events.map((e) =>
            this._row(
              `activity-console-${e.seq}`,
              e.occurred_at,
              this._badge('accent', t(e.action.replace('can_', '').replaceAll('_', ' '))),
              html`<span class="mono">${e.payload?.op ?? e.kind}</span>`,
              summary(e.payload),
              `${e.subject_type}:${e.subject_id}`,
            ),
          )}
        </tbody>
      </table>
    </div>`;
  }

  // The tuple audit trail: a relationship added or removed.
  _audit(rows) {
    if (!rows.length) return html`<div class="empty">${t('No relationship changes recorded.')}</div>`;
    return html`<div class="table-wrap">
      <table data-testid="activity-audit-table">
        ${PgcActivity.HEAD('The relationship: subject, relation, object. By: the person when the write came through the console, else the connection role.')}
        <tbody>
          ${rows.map((a, i) =>
            this._row(
              `activity-audit-${i}`,
              a.performed_at,
              this._changeBadge(a.action),
              t('relationship'),
              html`<span class="mono">${subjectOf(a)}</span> <span class="muted">${t('is')}</span>
                <span class="mono">${a.relation}</span> <span class="muted">${t('of')}</span>
                <span class="mono">${a.object_type}:${a.object_id}</span>`,
              a.performed_by,
            ),
          )}
        </tbody>
      </table>
    </div>`;
  }

  // One model change as words: what it was, where, and the definition.
  _modelWhat(c) {
    const d = c.detail ?? {};
    switch (c.kind) {
      case 'rule': {
        const def =
          d.rule_type === 'direct'
            ? t('direct')
            : d.rule_type === 'computed'
              ? d.computed_relation
              : `${d.tupleset_computed} ${t('from')} ${d.tupleset_relation}`;
        return html`<span class="mono">${c.object_type}.${c.relation}</span> ←
          ${d.negated ? html`<span class="badge deny">${t('not')}</span> ` : nothing}<span class="mono"
            >${def}</span
          >
          ${d.group_id ? html`<span class="muted">(${t('group')} ${d.group_id}${d.group_op !== 'or' ? ', ' + d.group_op : ''})</span>` : nothing}`;
      }
      case 'condition':
        return html`<span class="mono">${c.name}</span> <span class="muted">${d.lang}:</span>
          <span class="mono">${String(d.expression ?? '').slice(0, 120)}</span>`;
      case 'gate':
        return html`<span class="mono">${c.object_type}.${c.relation}</span> —
          <span class="mono">${c.name}</span>
          <span class="muted"
            >${d.spec?.mode ?? 'enforce'}, ${(d.spec?.all_of ?? []).length} ${t('clauses')}</span
          >`;
      case 'grant_rule':
        return html`<span class="mono">${c.object_type}.${c.relation}</span>
          <span class="muted">${t('needs')}</span>
          <span class="mono">${d.requires}</span>
          ${d.requires_revoke ? html`<span class="muted">${t('to revoke')}</span> <span class="mono">${d.requires_revoke}</span>` : nothing}`;
      default:
        return html`<span class="mono">${c.object_type}.${c.relation} ${c.name}</span>`;
    }
  }

  _model(rows) {
    if (!rows.length) return html`<div class="empty">${t('No model changes recorded.')}</div>`;
    const kinds = { rule: 'rule', condition: 'condition', gate: 'gate', grant_rule: 'grant rule' };
    return html`<div class="table-wrap">
      <table data-testid="activity-model-table">
        ${PgcActivity.HEAD('The rule, condition, gate or grant rule as it was. Editing a condition, gate or grant rule shows as a removal plus an addition; types and relations themselves are not versioned (they are the dictionary).')}
        <tbody>
          ${rows.map((c) =>
            this._row(
              `activity-model-${c.kind}-${c.seq}`,
              c.performed_at,
              this._changeBadge(c.action),
              t(kinds[c.kind] ?? c.kind),
              this._modelWhat(c),
              c.performed_by,
            ),
          )}
        </tbody>
      </table>
    </div>`;
  }

  // The store's action log: the event kind as the change, the action as
  // what, subject and object as the details, the recording PEP as by.
  _events(rows) {
    if (!rows.length)
      return html`<div class="empty">
        ${t('The action log is empty — PEPs record what principals did via record_event.')}
      </div>`;
    return html`<div class="table-wrap">
      <table data-testid="activity-events-table">
        ${PgcActivity.HEAD('Who did it to what. Change is the event kind: request means something was asked or done; other kinds are what the recording PEP chose.')}
        <tbody>
          ${rows.map((e) =>
            this._row(
              `activity-event-${e.seq}`,
              e.occurred_at,
              this._badge(e.kind === 'denied' ? 'deny' : e.kind === 'response' ? 'ok' : 'muted', e.kind),
              html`<span class="mono">${e.action}</span>`,
              html`<span class="mono">${e.subject_type}:${e.subject_id}</span>${
                  e.object_type
                    ? html` <span class="muted">${t('on')}</span>
                        <span class="mono">${e.object_type}:${e.object_id}</span>`
                    : nothing
                }`,
              e.recorded_by,
            ),
          )}
        </tbody>
      </table>
    </div>`;
  }

  render() {
    const d = this.d;
    if (!d) return html`${this.error ? errorBox(this.error) : html`<p class="muted">${t('Loading…')}</p>`}`;
    const views = [
      [
        'console',
        t('Console actions') + ` (${d.console.length})`,
        "What people did to this store through the console, from the console store's action log.",
      ],
      [
        'audit',
        t('Relationship audit') + ` (${d.audit.length})`,
        'Every tuple written or removed in this store, with who did it (the audit trail).',
      ],
      [
        'model',
        t('Model changes') + ` (${(d.model ?? []).length})`,
        'Rules, conditions, temporal gates and grant rules added or removed, with who did it (the model audit tables).',
      ],
      [
        'events',
        t('Action log') + ` (${d.events.length})`,
        'What principals actually did, as recorded by enforcement points (record_event); temporal gates decide on it.',
      ],
    ];
    return html`
      <div class="toolbar">
        <div class="seg">
          ${views.map(([v, l, tip]) => html`<button class=${this.view === v ? 'active' : ''} title=${t(tip)} data-testid=${'activity-view-' + v} @click=${() => (this.view = v)}>${l}</button>`)}
        </div>
        <button class="sm" data-testid="activity-refresh" @click=${this._load}>${t('Refresh')}</button>
      </div>
      ${d.retired ? html`<p class="help">${t('Retired store: the action log is live-only and no longer readable; the audit trail and the model history stay.')}</p>` : nothing}
      <section class="card">
        ${
          this.view === 'console'
            ? this._console(d.console)
            : this.view === 'audit'
              ? this._audit(d.audit)
              : this.view === 'model'
                ? this._model(d.model ?? [])
                : this._events(d.events)
        }
      </section>
    `;
  }
}
customElements.define('pgc-activity', PgcActivity);
