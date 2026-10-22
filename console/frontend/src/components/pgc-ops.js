import { html, nothing } from 'lit';
import { PgcElement, help, errorBox } from '../base.js';
import { api } from '../api.js';
import { t } from '../i18n.js';
import { run, forbiddenText, fmtTime, fmtRelative, subjectOf } from '../util.js';
import { partitionsCard, readinessFacts } from './pgc-ops-shared.js';

// Operations tab of a store: can the gates be trusted (events_readiness and
// every clause's window), who may record which actions (the recorder
// allowlist), tuple maintenance (expired and redundant tuples), action-log
// retention for this store (purge_events), the changefeed position and the
// derived-permissions status, and the partitions of both logs (managed on
// Platform → Operations). Reads need can_view_audit; every action needs
// can_manage_access, runs as the person and is recorded.
export class PgcOps extends PgcElement {
  static properties = {
    store: { type: String },
    caps: { attribute: false },
    info: { attribute: false },
    d: { state: true },
    busy: { state: true },
    error: { state: true },
    form: { state: true },
    result: { state: true }, // the last action's outcome, by action
    redundant: { state: true }, // the last find: { tuples, more }
    confirming: { state: true }, // which destructive action awaits confirmation
    meta: { state: true }, // the store's types and relations (for suggestions)
  };

  constructor() {
    super();
    /** @type {import('../types.js').OpsOverview|null} */
    this.d = null;
    this.busy = false;
    this.error = '';
    /** @type {import('../types.js').OpsForm} */
    this.form = { grace: '1 day', months: 1 };
    /** @type {import('../types.js').OpsResults} */
    this.result = {};
    /** @type {import('../types.js').RedundantResult|null} */
    this.redundant = null;
    this.confirming = null;
    /** @type {import('../types.js').Meta|null} */
    this.meta = null;
  }

  willUpdate(changed) {
    if (changed.has('store') && this.store) void this._load();
  }

  async _load() {
    const d = await run(this, async () => {
      try {
        return await api.ops(this.store);
      } catch (e) {
        throw new Error(forbiddenText(e));
      }
    });
    if (d) this.d = d;
    if (!this.meta)
      api
        .meta(this.store)
        .then((m) => (this.meta = m))
        .catch(() => {});
  }

  _set(k) {
    return (e) =>
      (this.form = { ...this.form, [k]: e.target.type === 'checkbox' ? e.target.checked : e.target.value });
  }

  // Run an action as the person, remember its outcome, reload the overview.
  async _act(name, fn) {
    this.result = { ...this.result, [name]: undefined };
    const r = await run(this, async () => {
      try {
        return await fn();
      } catch (e) {
        throw new Error(forbiddenText(e));
      }
    });
    this.confirming = null;
    if (r) {
      this.result = { ...this.result, [name]: r };
      await this._load();
    }
  }

  _canAct() {
    return !!this.caps?.can_manage_access;
  }

  _recActions() {
    return String(this.form.rec_actions ?? '')
      .split(',')
      .map((x) => x.trim())
      .filter(Boolean);
  }

  _relations() {
    const names = new Set();
    for (const rels of Object.values(this.meta?.relations_by_type ?? {}))
      for (const r of rels) names.add(r.name);
    return [...names].sort();
  }

  _readiness(d) {
    const r = d.readiness;
    return html`<section class="card" data-testid="ops-readiness">
      <h3>
        ${t('Gate readiness')}
        ${help('Can the temporal gates be trusted right now? Gates count what principals did; if the retained history is shorter than the longest gate window, a quota may under-count and let more through. From authz.events_readiness.')}
        ${
          r
            ? r.gates === 0
              ? html`<span class="badge muted">${t('no gates')}</span>`
              : r.history_covers_gates
                ? html`<span class="badge ok">${t('ready')}</span>`
                : html`<span class="badge deny">${t('history too short')}</span>`
            : nothing
        }
      </h3>
      ${readinessFacts(r)}
      ${
        d.gate_windows.length
          ? html`<div class="table-wrap">
              <table class="compact" data-testid="ops-gate-windows">
                <thead>
                  <tr>
                    <th>${t('Gate')}</th>
                    <th>${t('On')}</th>
                    <th>${t('Clause')}</th>
                    <th>${t('Window')} ${help('How far back this clause looks; the retention floor.')}</th>
                  </tr>
                </thead>
                <tbody>
                  ${d.gate_windows.map(
                    (g) =>
                      html`<tr>
                        <td class="mono">${g.gate}</td>
                        <td class="mono">${g.object_type}.${g.relation}</td>
                        <td class="mono">${g.clause}</td>
                        <td class="mono">${g.window}</td>
                      </tr>`,
                  )}
                </tbody>
              </table>
            </div>`
          : nothing
      }
    </section>`;
  }

  _recorders(d) {
    const can = this._canAct();
    const f = this.form;
    const actions = this._recActions();
    return html`<section class="card" data-testid="ops-recorders">
      <h3>
        ${t('Recorder allowlist')}
        ${help('Which database roles may record which actions in this store (grant_recorder_actions). A recorder with an allowlist may record only those actions; a recorder without one may record any declared action. Events drive the gates, so narrow every ingestion service to what it really does.')}
      </h3>
      ${
        d.recorders.length
          ? html`<div class="table-wrap">
              <table class="compact" data-testid="ops-recorder-table">
                <thead>
                  <tr>
                    <th>${t('Database role')}</th>
                    <th>${t('May record')}</th>
                    ${can ? html`<th></th>` : nothing}
                  </tr>
                </thead>
                <tbody>
                  ${d.recorders.map(
                    (x) =>
                      html`<tr data-testid=${`ops-recorder-${x.db_role}`}>
                        <td class="mono">${x.db_role}</td>
                        <td class="chips">
                          ${x.actions.map(
                            (a) =>
                              html`<span class="chip"
                                >${a}
                                ${
                                  can
                                    ? html`<button
                                        type="button"
                                        class="link"
                                        title=${t('revoke this action')}
                                        data-testid=${`ops-recorder-revoke-${x.db_role}-${a}`}
                                        @click=${() => this._act('recorder', () => api.opsRecorderRevoke(this.store, x.db_role, [a]))}
                                      >
                                        ×
                                      </button>`
                                    : nothing
                                }</span
                              >`,
                          )}
                        </td>
                        ${
                          can
                            ? html`<td class="actions">
                                <button
                                  class="sm"
                                  data-testid=${`ops-recorder-revoke-all-${x.db_role}`}
                                  @click=${() => this._act('recorder', () => api.opsRecorderRevoke(this.store, x.db_role, []))}
                                >
                                  ${t('Remove allowlist')}
                                </button>
                              </td>`
                            : nothing
                        }
                      </tr>`,
                  )}
                </tbody>
              </table>
            </div>`
          : html`<p class="help">
              ${t('No allowlist: every recorder role may record any declared action of this store.')}
            </p>`
      }
      ${
        can
          ? html`<form
              class="form"
              data-testid="ops-recorder-form"
              @submit=${(e) => {
                e.preventDefault();
                void this._act('recorder', () =>
                  api.opsRecorderGrant(this.store, this.form.rec_role?.trim(), this._recActions()),
                );
              }}
            >
              <label class="field"
                ><span
                  >${t('Database role')}
                  ${help('The PostgreSQL role the recording service connects as, e.g. authz_recorder_svc. Login roles of this database are suggested.')}</span
                ><input
                  class="mono"
                  required
                  list="dl-login-roles"
                  pattern="[A-Za-z_][A-Za-z0-9_]*"
                  .value=${f.rec_role ?? ''}
                  @input=${this._set('rec_role')}
                  data-testid="ops-recorder-role"
              /></label>
              <datalist id="dl-login-roles">
                ${d.login_roles.map((r) => html`<option value=${r}></option>`)}
              </datalist>
              <label class="field wide"
                ><span
                  >${t('Actions')}
                  ${help('Declared relations of this store the role may record, comma-separated, e.g. download, pay.')}</span
                ><input
                  class="mono"
                  required
                  list="dl-ops-relations"
                  .value=${f.rec_actions ?? ''}
                  @input=${this._set('rec_actions')}
                  data-testid="ops-recorder-actions"
              /></label>
              <datalist id="dl-ops-relations">
                ${this._relations().map((r) => html`<option value=${r}></option>`)}
              </datalist>
              <div class="actions wide">
                <button
                  class="primary"
                  ?disabled=${this.busy || !actions.length}
                  data-testid="ops-recorder-submit"
                >
                  ${t('Allow')}
                </button>
                ${this.result.recorder ? html`<span class="help">${t('done')}: ${this.result.recorder.granted ?? this.result.recorder.revoked} ${t('rows')}</span>` : nothing}
              </div>
            </form>`
          : nothing
      }
    </section>`;
  }

  _tuples(d) {
    const can = this._canAct();
    const s = d.tuple_stats ?? {};
    const f = this.form;
    const red = this.redundant;
    return html`<section class="card" data-testid="ops-tuples">
      <h3>
        ${t('Tuple maintenance')}
        ${help('Expired tuples stop granting immediately but occupy storage until reclaimed (cleanup_expired_tuples, audited). Redundant tuples are direct grants already implied by another rule path (find_redundant_tuples); removing them changes no decision.')}
      </h3>
      <div class="stats">
        <span><b>${s.total ?? 0}</b> ${t('tuples')}</span>
        <span><b>${s.with_expiry ?? 0}</b> ${t('with expiry')}</span>
        <span><b>${s.expiring_24h ?? 0}</b> ${t('expiring within 24 h')}</span>
        <span><b>${s.conditional ?? 0}</b> ${t('conditional')}</span>
      </div>
      ${
        can
          ? html`<div class="ops-grid">
              <form
                class="form"
                data-testid="ops-expired-form"
                @submit=${(e) => {
                  e.preventDefault();
                  void this._act('expired', () => api.opsCleanupExpired(this.store, this.form.grace));
                }}
              >
                <h4 class="wide">${t('Expired tuples')}</h4>
                <label class="field"
                  ><span
                    >${t('Grace')}
                    ${help('Keep tuples that expired less than this long ago, so recent expiries stay inspectable in the live table.')}</span
                  ><select @change=${this._set('grace')} data-testid="ops-expired-grace">
                    ${['0', '1 hour', '1 day', '7 days', '30 days'].map((g) => html`<option value=${g} ?selected=${f.grace === g}>${g === '0' ? t('none') : g}</option>`)}
                  </select></label
                >
                <div class="actions wide">
                  <button class="sm" ?disabled=${this.busy} data-testid="ops-expired-submit">
                    ${t('Reclaim expired tuples')}
                  </button>
                  ${this.result.expired ? html`<span class="help" data-testid="ops-expired-result">${t('{n} removed', { n: this.result.expired.removed })}</span>` : nothing}
                </div>
              </form>
              <form
                class="form"
                data-testid="ops-redundant-form"
                @submit=${async (e) => {
                  e.preventDefault();
                  this.redundant = null;
                  const r = await run(this, () =>
                    api.opsRedundant(this.store, this.form.red_type ?? '', this.form.red_rel ?? '', false),
                  );
                  if (r) this.redundant = r;
                }}
              >
                <h4 class="wide">${t('Redundant tuples')}</h4>
                <label class="field"
                  ><span>${t('Object type')} ${help('Optional: limit the search to one object type.')}</span
                  ><input
                    class="mono"
                    list="dl-ops-types"
                    .value=${f.red_type ?? ''}
                    @input=${this._set('red_type')}
                    data-testid="ops-redundant-type"
                /></label>
                <datalist id="dl-ops-types">
                  ${(this.meta?.types ?? []).map((x) => html`<option value=${x}></option>`)}
                </datalist>
                <label class="field"
                  ><span>${t('Relation')} ${help('Optional: limit the search to one relation.')}</span
                  ><input
                    class="mono"
                    list="dl-ops-relations"
                    .value=${f.red_rel ?? ''}
                    @input=${this._set('red_rel')}
                    data-testid="ops-redundant-relation"
                /></label>
                <div class="actions wide">
                  <button class="sm" ?disabled=${this.busy} data-testid="ops-redundant-find">
                    ${t('Find')}
                  </button>
                  ${
                    red
                      ? red.applied
                        ? html`<span class="help" data-testid="ops-redundant-result"
                            >${t('{n} removed', { n: red.removed })}</span
                          >`
                        : html`<span class="help" data-testid="ops-redundant-count"
                              >${red.tuples.length}${red.more ? '+' : ''} ${t('found')}</span
                            >
                            ${
                              red.tuples.length
                                ? this.confirming === 'redundant'
                                  ? html`<button
                                        type="button"
                                        class="sm danger"
                                        ?disabled=${this.busy}
                                        data-testid="ops-redundant-confirm"
                                        @click=${() => this._act('redundant', async () => (this.redundant = await api.opsRedundant(this.store, this.form.red_type ?? '', this.form.red_rel ?? '', true)))}
                                      >
                                        ${t('Yes, remove them')}
                                      </button>
                                      <button
                                        type="button"
                                        class="sm"
                                        @click=${() => (this.confirming = null)}
                                      >
                                        ${t('Cancel')}
                                      </button>`
                                  : html`<button
                                      type="button"
                                      class="sm"
                                      data-testid="ops-redundant-remove"
                                      @click=${() => (this.confirming = 'redundant')}
                                    >
                                      ${t('Remove them…')}
                                    </button>`
                                : nothing
                            }`
                      : nothing
                  }
                </div>
              </form>
            </div>`
          : nothing
      }
      ${
        red?.tuples?.length && !red.applied
          ? html`<div class="table-wrap">
              <table class="compact" data-testid="ops-redundant-table">
                <thead>
                  <tr>
                    <th>${t('Subject')}</th>
                    <th>${t('Relation')}</th>
                    <th>${t('Object')}</th>
                    <th>${t('Created at')}</th>
                  </tr>
                </thead>
                <tbody>
                  ${red.tuples.map(
                    (x) =>
                      html`<tr>
                        <td class="mono">${subjectOf(x)}</td>
                        <td class="mono">${x.relation}</td>
                        <td class="mono">${x.object_type}:${x.object_id}</td>
                        <td class="muted" title=${x.created_at}>${fmtTime(x.created_at)}</td>
                      </tr>`,
                  )}
                </tbody>
              </table>
            </div>`
          : nothing
      }
    </section>`;
  }

  _retention(d) {
    const can = this._canAct();
    const f = this.form;
    const r = d.readiness;
    return html`<section class="card" data-testid="ops-retention">
      <h3>
        ${t('Action-log retention for this store')}
        ${help("Removes this store's events older than the cutoff (purge_events: a row delete, for a tenant whose retention is shorter than the fleet's). The engine refuses a cutoff inside a live gate window, since a purged range under-counts and can only relax a cap; force overrides deliberately. Fleet-wide retention is a partition drop on Platform → Operations.")}
      </h3>
      <p class="help">
        ${r?.max_gate_window ? t('The longest gate window here is {w}: a cutoff newer than that is refused unless forced.', { w: r.max_gate_window }) : t('No gate window constrains retention in this store.')}
        ${r?.oldest_event_at ? html` ${t('Oldest event')}: ${fmtTime(r.oldest_event_at)}.` : nothing}
      </p>
      ${
        can
          ? html`<form
              class="form"
              data-testid="ops-purge-form"
              @submit=${(e) => {
                e.preventDefault();
                this.confirming = 'purge';
              }}
            >
              <label class="field"
                ><span>${t('Purge events before')}</span
                ><input
                  type="datetime-local"
                  required
                  .value=${f.purge_before ?? ''}
                  @input=${this._set('purge_before')}
                  data-testid="ops-purge-before"
              /></label>
              <label class="check"
                ><input
                  type="checkbox"
                  .checked=${!!f.purge_force}
                  @change=${this._set('purge_force')}
                  data-testid="ops-purge-force"
                />
                ${t('force past the gate guard')}</label
              >
              <div class="actions wide">
                ${
                  this.confirming === 'purge'
                    ? html`<span class="help"
                          >${t('Remove every event of this store before {when}?', { when: fmtTime(f.purge_before) })}</span
                        >
                        <button
                          type="button"
                          class="sm danger"
                          ?disabled=${this.busy}
                          data-testid="ops-purge-confirm"
                          @click=${() => this._act('purge', () => api.opsPurgeEvents(this.store, new Date(this.form.purge_before).toISOString(), !!this.form.purge_force))}
                        >
                          ${t('Yes, purge')}
                        </button>
                        <button type="button" class="sm" @click=${() => (this.confirming = null)}>
                          ${t('Cancel')}
                        </button>`
                    : html`<button
                        class="sm danger"
                        ?disabled=${this.busy || !f.purge_before}
                        data-testid="ops-purge-submit"
                      >
                        ${t('Purge…')}
                      </button>`
                }
                ${this.result.purge ? html`<span class="help" data-testid="ops-purge-result">${t('{n} removed', { n: this.result.purge.purged })}</span>` : nothing}
              </div>
            </form>`
          : nothing
      }
    </section>`;
  }

  _feeds(d) {
    const c = d.changefeed;
    const dv = d.derived;
    const st = dv.status;
    return html`<section class="card" data-testid="ops-feeds">
      <h3>
        ${t('Changefeed and derived permissions')}
        ${help('The changefeed (authz.watch_changes) hands consumers every relationship change after a cursor; watch_safe_until is the instant before which committed rows are final. Derived permissions (db/replication/materialized_relations.sql) are a flattened copy kept by a worker reading that feed.')}
      </h3>
      <dl class="kv">
        <dt>
          ${t('Changefeed cursor')}
          ${help("The store's newest audit row: where a consumer that only wants future changes would start.")}
        </dt>
        <dd>
          ${c.cursor_at ? html`<span title=${c.cursor_at}>${fmtTime(c.cursor_at)}</span> <span class="mono muted">seq ${c.cursor_seq}</span> <span class="muted">(${fmtRelative(c.cursor_at)})</span>` : html`<span class="muted">${t('no changes yet')}</span>`}
        </dd>
        <dt>
          ${t('Safe until')}
          ${help('Rows performed before this instant are final; a consumer should not read past it. Held back by the oldest open transaction.')}
        </dt>
        <dd>
          <span title=${c.safe_until}>${fmtTime(c.safe_until)}</span>
          <span class="muted">(${fmtRelative(c.safe_until)})</span>
        </dd>
        <dt>${t('Derived permissions')}</dt>
        <dd>
          ${
            !dv.installed
              ? html`<span class="badge muted">${t('not installed')}</span>`
              : dv.error
                ? html`<span class="badge warn">${t('unreadable')}</span>
                    <span class="muted">${dv.error}</span>`
                : !st
                  ? html`<span class="badge muted">${t('this store is not registered')}</span>`
                  : html`${st.feed_drained ? html`<span class="badge ok">${t('up to date')}</span>` : html`<span class="badge warn">${t('catching up')}</span>`}
                      <span class="muted">${t('as of')}</span>
                      <span title=${st.as_of}>${fmtTime(st.as_of)}</span>
                      <span class="muted"
                        >· ${t('staleness')} <span class="mono">${st.staleness}</span> · ${t('pending')}
                        ${st.pending_due} (${st.pending_deferred} ${t('deferred')})</span
                      >
                      ${st.last_run_finished_at ? html`<div class="help">${t('last run')} ${fmtRelative(st.last_run_finished_at)}: ${st.last_run_changes} ${t('changes')}, ${st.last_run_pairs} ${t('pairs')}, ${st.last_run_rows_written} ${t('rows written')}</div>` : nothing}`
          }
        </dd>
      </dl>
    </section>`;
  }

  render() {
    const d = this.d;
    if (!d) return html`${this.error ? errorBox(this.error) : html`<p class="muted">${t('Loading…')}</p>`}`;
    return html`
      ${this.error ? errorBox(this.error) : nothing}
      <div class="toolbar">
        <span class="help"
          >${this._canAct() ? t("Actions run as you and are recorded in the console's action log.") : t('read-only: actions need "manage access" (owner or platform admin)')}</span
        >
        <button class="sm" data-testid="ops-refresh" @click=${this._load}>${t('Refresh')}</button>
      </div>
      ${d.retired ? html`<p class="help">${t('Retired store: gates, tuples and retention are gone; the changefeed position and the partitions remain.')}</p>` : html`${this._readiness(d)} ${this._recorders(d)} ${this._tuples(d)} ${this._retention(d)}`}
      ${this._feeds(d)}
      ${partitionsCard(d.partitions, { help: 'Both logs are partitioned by month, fleet-wide. Creating partitions ahead and dropping old ones is done on Platform → Operations.' })}
    `;
  }
}
customElements.define('pgc-ops', PgcOps);
