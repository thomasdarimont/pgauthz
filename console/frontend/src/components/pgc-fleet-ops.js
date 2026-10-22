import { html, nothing } from 'lit';
import { PgcElement, help, errorBox } from '../base.js';
import { api } from '../api.js';
import { t } from '../i18n.js';
import { run, forbiddenText, fmtTime } from '../util.js';
import { partitionsCard, fmtBytes } from './pgc-ops-shared.js';

// Platform → Operations: what is fleet-wide — the partitions of both logs
// (create ahead, drop old action-log months), every store's gate readiness
// and the longest gate window retention must keep, and store sizes.
// Reads need platform can_view_health; actions platform can_manage_access.
export class PgcFleetOps extends PgcElement {
  static properties = {
    me: { attribute: false },
    d: { state: true },
    busy: { state: true },
    error: { state: true },
    form: { state: true },
    result: { state: true },
    confirming: { state: true },
  };

  constructor() {
    super();
    /** @type {import('../types.js').PlatformOps|null} */
    this.d = null;
    this.busy = false;
    this.error = '';
    this.form = { months: 1 };
    /** @type {{ensure?: import('../types.js').FleetResult, drop?: import('../types.js').FleetResult}} */
    this.result = {};
    this.confirming = false;
  }

  connectedCallback() {
    super.connectedCallback();
    void this._load();
  }

  async _load() {
    const d = await run(this, async () => {
      try {
        return await api.platformOps();
      } catch (e) {
        throw new Error(forbiddenText(e));
      }
    });
    if (d) this.d = d;
  }

  _set(k) {
    return (e) =>
      (this.form = { ...this.form, [k]: e.target.type === 'checkbox' ? e.target.checked : e.target.value });
  }

  async _act(name, fn) {
    const r = await run(this, async () => {
      try {
        return await fn();
      } catch (e) {
        throw new Error(forbiddenText(e));
      }
    });
    this.confirming = false;
    if (r) {
      this.result = { ...this.result, [name]: r };
      await this._load();
    }
  }

  _canAct() {
    return !!this.me?.platform?.can_manage_access;
  }

  _partitionActions() {
    if (!this._canAct())
      return html`<p class="help">${t('read-only: changing partitions needs platform "manage access"')}</p>`;
    const f = this.form;
    return html`<div class="ops-grid">
      <form
        class="form"
        data-testid="fleet-ensure-form"
        @submit=${(e) => {
          e.preventDefault();
          void this._act('ensure', () => api.platformEnsurePartitions(Number(this.form.months)));
        }}
      >
        <h4 class="wide">${t('Create partitions ahead')}</h4>
        <label class="field"
          ><span
            >${t('Months ahead')}
            ${help('Creates the monthly partitions of both logs for this month and this many months after it (ensure_audit_partitions, ensure_event_partitions). Idempotent; a nightly job normally does this.')}</span
          ><input
            type="number"
            min="0"
            max="24"
            .value=${String(f.months)}
            @input=${this._set('months')}
            data-testid="fleet-ensure-months"
        /></label>
        <div class="actions wide">
          <button class="sm" ?disabled=${this.busy} data-testid="fleet-ensure-submit">
            ${t('Create partitions')}
          </button>
          ${this.result.ensure ? html`<span class="help" data-testid="fleet-ensure-result">${t('created: {a} audit, {e} action-log partitions', { a: this.result.ensure.audit_created, e: this.result.ensure.events_created })}</span>` : nothing}
        </div>
      </form>
      <form
        class="form"
        data-testid="fleet-drop-form"
        @submit=${(e) => {
          e.preventDefault();
          this.confirming = true;
        }}
      >
        <h4 class="wide">${t('Action-log retention (fleet)')}</h4>
        <label class="field"
          ><span
            >${t('Drop event partitions before')}
            ${help('Every month of the action log that lies wholly before this date is dropped (drop_event_partitions_before: DDL, O(partitions)). Refused when the cutoff falls inside any live gate window unless forced. The audit trail is not touched.')}</span
          ><input
            type="date"
            required
            .value=${f.before ?? ''}
            @input=${this._set('before')}
            data-testid="fleet-drop-before"
        /></label>
        <label class="check"
          ><input
            type="checkbox"
            .checked=${!!f.force}
            @change=${this._set('force')}
            data-testid="fleet-drop-force"
          />
          ${t('force past the gate guard')}</label
        >
        <div class="actions wide">
          ${
            this.confirming
              ? html`<span class="help"
                    >${t('Drop every action-log month before {when}, for every store?', { when: f.before })}</span
                  >
                  <button
                    type="button"
                    class="sm danger"
                    ?disabled=${this.busy}
                    data-testid="fleet-drop-confirm"
                    @click=${() => this._act('drop', () => api.platformDropEventPartitions(this.form.before, !!this.form.force))}
                  >
                    ${t('Yes, drop them')}
                  </button>
                  <button type="button" class="sm" @click=${() => (this.confirming = false)}>
                    ${t('Cancel')}
                  </button>`
              : html`<button
                  class="sm danger"
                  ?disabled=${this.busy || !f.before}
                  data-testid="fleet-drop-submit"
                >
                  ${t('Drop…')}
                </button>`
          }
          ${this.result.drop ? html`<span class="help" data-testid="fleet-drop-result">${t('{n} partitions dropped', { n: this.result.drop.dropped })}</span>` : nothing}
        </div>
      </form>
    </div>`;
  }

  render() {
    const d = this.d;
    if (!d) return html`${this.error ? errorBox(this.error) : html`<p class="muted">${t('Loading…')}</p>`}`;
    const readiness = d.readiness ?? [];
    return html`
      ${this.error ? errorBox(this.error) : nothing}
      <div class="toolbar">
        <span class="help">
          ${t('Longest gate window in the fleet')}:
          <span class="mono">${d.max_gate_window ?? t('none')}</span>
          ${help('What action-log retention must keep at least, fleet-wide (max_gate_window). Safe-until: the instant before which committed changefeed rows are final.')}
          · ${t('Safe until')}: <span title=${d.safe_until}>${fmtTime(d.safe_until)}</span>
        </span>
        <button class="sm" data-testid="fleet-refresh" @click=${this._load}>${t('Refresh')}</button>
      </div>
      ${partitionsCard(d.partitions, { actions: this._partitionActions() })}
      <section class="card" data-testid="fleet-readiness">
        <h3>
          ${t('Gate readiness by store')}
          ${help('authz.events_readiness for every store: whether the retained history covers the longest gate window, and how fresh the action log is.')}
        </h3>
        ${
          readiness.length
            ? html`<div class="table-wrap">
                <table class="compact">
                  <thead>
                    <tr>
                      <th>${t('Store')}</th>
                      <th>${t('Gates')}</th>
                      <th>${t('Longest window')}</th>
                      <th>${t('History since')}</th>
                      <th>${t('Covers')}</th>
                      <th>${t('Last recorded')}</th>
                      <th class="num">${t('Events, last hour')}</th>
                    </tr>
                  </thead>
                  <tbody>
                    ${readiness.map(
                      (r) =>
                        html`<tr data-testid=${`fleet-readiness-${r.store}`}>
                          <td class="mono">${r.store}</td>
                          <td>
                            ${r.gates}
                            <span class="muted">(${r.gates_enforce}/${r.gates_shadow}/${r.gates_off})</span>
                          </td>
                          <td class="mono">${r.max_gate_window ?? ''}</td>
                          <td class="muted">${r.history_since ? fmtTime(r.history_since) : ''}</td>
                          <td>
                            ${r.gates === 0 ? html`<span class="muted">—</span>` : r.history_covers_gates ? html`<span class="badge ok">${t('yes')}</span>` : html`<span class="badge deny">${t('no')}</span> <span class="mono muted">${r.history_deficit}</span>`}
                          </td>
                          <td class="muted">${r.last_recorded_at ? fmtTime(r.last_recorded_at) : ''}</td>
                          <td class="num">${r.events_1h}</td>
                        </tr>`,
                    )}
                  </tbody>
                </table>
              </div>`
            : html`<p class="help">${t('No stores.')}</p>`
        }
      </section>
      <section class="card" data-testid="fleet-sizes">
        <h3>
          ${t('Store sizes')}
          ${help('Live tuples per store (store_stats) and the storage its tuple partitions take on disk, table and indexes (pg_total_relation_size); largest first. The audit trail and the action log are partitioned by month, not by store, so their space is in Partitions above.')}
        </h3>
        <div class="table-wrap">
          <table class="compact" data-testid="fleet-sizes-table">
            <thead>
              <tr>
                <th>${t('Store')}</th>
                <th class="num">${t('Tuples')}</th>
                <th class="num">${t('Storage')}</th>
              </tr>
            </thead>
            <tbody>
              ${(d.store_sizes ?? []).map(
                (r) =>
                  html`<tr data-testid=${`fleet-size-${r.store}`}>
                    <td class="mono">${r.store}</td>
                    <td class="num">${r.tuples}</td>
                    <td class="num muted">${fmtBytes(r.bytes)}</td>
                  </tr>`,
              )}
            </tbody>
          </table>
        </div>
        <p class="help">
          ${t('{n} stores, {t} tuples, {b} of tuple storage', { n: (d.store_sizes ?? []).length, t: (d.store_sizes ?? []).reduce((a, r) => a + Number(r.tuples), 0), b: fmtBytes((d.store_sizes ?? []).reduce((a, r) => a + Number(r.bytes), 0)) })}
          ·
          ${t('{n} partitions, {b} in total', { n: d.partitions.length, b: fmtBytes(d.partitions.reduce((a, p) => a + Number(p.bytes), 0)) })}
        </p>
      </section>
    `;
  }
}
customElements.define('pgc-fleet-ops', PgcFleetOps);
