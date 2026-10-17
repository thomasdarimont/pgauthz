import { html, nothing } from 'lit';
import { PgcElement, help } from '../base.js';
import { api } from '../api.js';
import { t, t2 } from '../i18n.js';
import { run, subjectOf, forbiddenText, fmtTime, fmtRelative } from '../util.js';
import { selectionCell, selectAllCell, removeBar, clearSelection } from './pgc-select.js';

// Data tab: the store's relationship tuples, with grant/revoke for console
// sharers. The engine still enforces the model (type restrictions,
// conditions), and every write is audited as you. Revoking goes through
// selection and a confirmation, one transaction for all selected tuples.
export class PgcData extends PgcElement {
  static properties = {
    store: { type: String },
    caps: { attribute: false },
    nsCaps: { attribute: false }, // per-namespace capabilities (store screen)
    rows: { state: true },
    meta: { state: true },
    stats: { state: true },
    q: { state: true },
    busy: { state: true },
    error: { state: true },
    adding: { state: true },
    form: { state: true },
    selected: { state: true },
    confirming: { state: true },
    limit: { state: true },
    page: { state: true }, // 0-based, server-side
    total: { state: true }, // rows matching the filter, from the server
    expiryAbsolute: { state: true },
    sort: { state: true },
  };

  static LIMITS = [25, 50, 100, 250, 500];

  // Expiry presets for the Add form: label → duration from now. A month is
  // 30 days and a year 365, which is what people mean by "about a month".
  static EXPIRY_PRESETS = [
    ['1 h', 3600e3],
    ['12 h', 12 * 3600e3],
    ['1 day', 86400e3],
    ['1 week', 7 * 86400e3],
    ['1 month', 30 * 86400e3],
    ['1 year', 365 * 86400e3],
  ];

  constructor() {
    super();
    this.rows = null;
    this.q = '';
    this.busy = false;
    this.error = '';
    this.adding = false;
    this.form = {};
    this.selected = new Set();
    this.confirming = false;
    // Expiry column: relative ("in 2 hours") by default, absolute on toggle;
    // a per-browser preference. Sorting always uses the absolute instant.
    this.expiryAbsolute = false;
    try {
      this.expiryAbsolute = localStorage.getItem('pgc_expiry_absolute') === 'true';
    } catch {
      /* storage unavailable */
    }
    this.sort = null; // { key, dir: 1 | -1 } — server-side: the page is fetched in this order
    this.page = 0;
    this.total = 0;
    // Rows per page: a per-browser convenience, remembered across stores.
    this.limit = 100;
    try {
      const stored = Number(localStorage.getItem('pgc_tuple_limit'));
      if (PgcData.LIMITS.includes(stored)) this.limit = stored;
    } catch {
      /* storage unavailable */
    }
  }

  _setLimit(e) {
    this.limit = Number(e.target.value);
    this.page = 0;
    try {
      localStorage.setItem('pgc_tuple_limit', String(this.limit));
    } catch {
      /* storage unavailable */
    }
    this._load();
  }

  willUpdate(changed) {
    if (changed.has('store') && this.store) {
      this._load();
      api
        .meta(this.store)
        .then((m) => (this.meta = m))
        .catch(() => {});
    }
  }

  // Assignable relations (kind = relation, with a direct rule) of the object
  // type being granted — what a tuple may name.
  _assignable() {
    const typ = String(this.form.object_type ?? '').trim();
    return (this.meta?.relations_by_type?.[typ] ?? []).filter((r) => r.direct).map((r) => r.name);
  }

  _key(tu) {
    return `${subjectOf(tu)} ${tu.relation} ${tu.object_type}:${tu.object_id}`;
  }

  async _load() {
    const d = await run(this, () =>
      api.tuples(
        this.store,
        this.q,
        this.limit,
        this.page * this.limit,
        this.sort?.key ?? '',
        this.sort?.dir < 0 ? 'desc' : 'asc',
      ),
    );
    if (d) {
      this.rows = d.tuples;
      this.total = d.total ?? d.tuples.length;
      if (this.page > 0 && this.page * this.limit >= this.total) {
        this.page = Math.max(0, Math.ceil(this.total / this.limit) - 1);
        return this._load();
      }
      clearSelection(this);
    }
    api
      .tupleStats(this.store)
      .then((st) => (this.stats = st))
      .catch(() => {});
  }

  _stats() {
    const st = this.stats;
    if (!st) return nothing;
    const n = (k) => html`<b>${st[k] ?? 0}</b>`;
    return html`<div class="stats data-stats">
      <span
        >${n('total')} ${t('tuples')}
        ${help('Live tuples: what decisions see right now. Expired rows are not counted here.')}</span
      >
      <span>${n('subjects')} ${t('subjects')}</span>
      <span>${n('objects')} ${t('objects')}</span>
      <span class=${st.with_expiry ? '' : 'muted'}>${n('with_expiry')} ${t('with expiry')}</span>
      <span class=${st.expiring_24h ? 'warn-text' : 'muted'}
        >${n('expiring_24h')} ${t('expiring within 24 h')}</span
      >
      <span class=${st.expired ? 'warn-text' : 'muted'}
        >${n('expired')} ${t('expired')}
        ${help('Already expired, so they grant nothing, but still stored until cleanup_expired_tuples removes them.')}</span
      >
      <span class=${st.wildcard_subject ? '' : 'muted'}
        >${n('wildcard_subject')} ${t('subject wildcards')}</span
      >
      ${st.wildcard_object ? html`<span>${n('wildcard_object')} ${t('object wildcards')}</span>` : nothing}
      <span class=${st.conditional ? '' : 'muted'}>${n('conditional')} ${t('conditional')}</span>
      <span class=${st.usersets ? '' : 'muted'}>${n('usersets')} ${t('usersets')}</span>
      ${
        st.by_object_type?.length
          ? html`<span class="by-type"
              >${st.by_object_type.map((x) => html`<span class="badge mono" title=${t('tuples on this object type')}>${x.type} ${x.count}</span>`)}</span
            >`
          : nothing
      }
    </div>`;
  }

  _set(k) {
    return (e) => (this.form = { ...this.form, [k]: e.target.value });
  }

  _toggleExpiryMode(e) {
    e.stopPropagation();
    this.expiryAbsolute = !this.expiryAbsolute;
    try {
      localStorage.setItem('pgc_expiry_absolute', String(this.expiryAbsolute));
    } catch {
      /* storage unavailable */
    }
  }

  _toggleSort(key) {
    this.sort = this.sort?.key === key ? { key, dir: -this.sort.dir } : { key, dir: 1 };
    this.page = 0;
    this._load();
  }

  // Rows arrive in the chosen order from the server (the whole store is
  // sorted, not just the page); expiry sorts by the absolute instant.
  _sorted() {
    return this.rows ?? [];
  }

  _pages() {
    return Math.max(1, Math.ceil((this.total || 0) / this.limit));
  }

  _goto(page) {
    this.page = Math.max(0, Math.min(page, this._pages() - 1));
    this._load();
  }

  _pager() {
    const pages = this._pages();
    if (pages <= 1) return nothing;
    const from = this.page * this.limit + 1;
    const to = Math.min(this.total, (this.page + 1) * this.limit);
    return html`<div class="pager">
      <span class="muted">${t('{from}–{to} of {total}', { from, to, total: this.total })}</span>
      <button class="sm" ?disabled=${this.page === 0 || this.busy} @click=${() => this._goto(0)}>«</button>
      <button class="sm" ?disabled=${this.page === 0 || this.busy} @click=${() => this._goto(this.page - 1)}>
        ‹ ${t('Previous')}
      </button>
      <span class="muted">${t('page {n} of {pages}', { n: this.page + 1, pages })}</span>
      <button
        class="sm"
        ?disabled=${this.page >= pages - 1 || this.busy}
        @click=${() => this._goto(this.page + 1)}
      >
        ${t('Next')} ›
      </button>
      <button
        class="sm"
        ?disabled=${this.page >= pages - 1 || this.busy}
        @click=${() => this._goto(pages - 1)}
      >
        »
      </button>
    </div>`;
  }

  _sortTh(key, label, extra) {
    const active = this.sort?.key === key;
    return html`<th
      class="sortable ${active ? 'active' : ''}"
      @click=${() => this._toggleSort(key)}
      title=${t('sort')}
    >
      ${label} ${extra ?? nothing}
      <span class="sort-ind">${active ? (this.sort.dir > 0 ? '▲' : '▼') : '↕'}</span>
    </th>`;
  }

  _expiry(tu) {
    if (!tu.expires_at) return nothing;
    const d = new Date(tu.expires_at);
    const expired = d.getTime() < Date.now();
    const shown = this.expiryAbsolute ? fmtTime(tu.expires_at) : fmtRelative(tu.expires_at);
    const other = this.expiryAbsolute ? fmtRelative(tu.expires_at) : fmtTime(tu.expires_at);
    return html`<span class=${expired ? 'expired' : ''} title=${other}>${shown}</span
      >${expired ? html` <span class="badge deny">${t('expired')}</span>` : nothing}`;
  }

  // Fill the datetime-local field with now + ms (local time, minute precision), or clear it.
  _preset(ms) {
    if (ms === null) {
      this.form = { ...this.form, expires_at: '' };
      return;
    }
    const d = new Date(Date.now() + ms);
    const pad = (n) => String(n).padStart(2, '0');
    const local = `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
    this.form = { ...this.form, expires_at: local };
  }

  _wrap(fn) {
    return run(this, async () => {
      try {
        return await fn();
      } catch (e) {
        throw new Error(forbiddenText(e));
      }
    });
  }

  async _write(e) {
    e.preventDefault();
    const f = { ...this.form };
    if (f.condition_context) {
      try {
        f.condition_context = JSON.parse(f.condition_context);
      } catch {
        this.error = t('condition context must be JSON');
        return;
      }
    }
    if (f.expires_at) f.expires_at = new Date(f.expires_at).toISOString(); // local wall time → absolute instant
    const ok = await this._wrap(() => api.writeTuple(this.store, f));
    if (ok) {
      this.adding = false;
      this.form = {};
      await this._load();
      this.dispatchEvent(new CustomEvent('changed'));
    }
  }

  async _removeSelected() {
    const tuples = this.rows
      .filter((tu) => this.selected.has(this._key(tu)))
      .map((tu) => ({
        user_type: tu.user_type,
        user_id: tu.user_id,
        user_relation: tu.user_relation,
        relation: tu.relation,
        object_type: tu.object_type,
        object_id: tu.object_id,
      }));
    const ok = await this._wrap(() => api.deleteTuples(this.store, tuples));
    if (ok) {
      await this._load();
      this.dispatchEvent(new CustomEvent('changed'));
    }
  }

  render() {
    const can = !!this.caps?.can_grant || Object.values(this.nsCaps ?? {}).some((c) => c.can_grant);
    return html`
      ${this._stats()}
      <div class="toolbar">
        <label class="filter-box" aria-label=${t('Filter')}>
          <svg class="filter-icon" viewBox="0 0 16 16" width="14" height="14" aria-hidden="true">
            <path
              d="M1.5 2.5h13l-5 6v4.5l-3 1.5V8.5z"
              fill="none"
              stroke="currentColor"
              stroke-width="1.4"
              stroke-linejoin="round"
            />
          </svg>
          <input
            class="mono"
            placeholder=${t('filter: alice, viewer, document:…')}
            .value=${this.q}
            @input=${(e) => (this.q = e.target.value)}
            @keydown=${(e) => e.key === 'Enter' && this._goto(0)}
          />
          <button type="button" class="sm" @click=${() => this._goto(0)}>${t('Filter')}</button>
        </label>
        <div class="actions">
          <button class="sm" title=${t('Reload the tuples')} @click=${this._load}>↻ ${t('Refresh')}</button>
          <label class="check">
            ${t('Show')}
            <select .value=${String(this.limit)} @change=${this._setLimit} aria-label=${t('rows per page')}>
              ${PgcData.LIMITS.map((n) => html`<option value=${n} ?selected=${n === this.limit}>${n}</option>`)}
            </select>
            ${t('rows')}
          </label>
          ${
            can
              ? html`<button class="primary" @click=${() => (this.adding = !this.adding)}>
                  ${t('Add')}
                </button>`
              : html`<span class="help">${t('writing needs "share" (sharer or owner)')}</span>`
          }
        </div>
      </div>
      ${this.error ? html`<p class="error">${this.error}</p>` : nothing}
      ${
        this.adding
          ? html`<form class="card form" @submit=${this._write}>
              <label class="field"
                ><span>${t('Subject type')}</span
                ><input class="mono" required @input=${this._set('user_type')} placeholder="user"
              /></label>
              <label class="field"
                ><span
                  >${t('Subject id')}
                  ${help('The subject, or * for everyone of that type (when the rule allows wildcards).')}</span
                ><input class="mono" required @input=${this._set('user_id')} placeholder="alice"
              /></label>
              <label class="field"
                ><span
                  >${t('Subject relation (userset)')}
                  ${help('Grant to a group: member makes the subject team:x#member.')}</span
                ><input class="mono" @input=${this._set('user_relation')} placeholder="member"
              /></label>
              <label class="field"
                ><span>${t('Relation')}</span
                ><input
                  class="mono"
                  required
                  list="dl-assignable"
                  @input=${this._set('relation')}
                  placeholder="viewer"
              /></label>
              <label class="field"
                ><span>${t('Object type')}</span
                ><input
                  class="mono"
                  required
                  list="dl-object-types"
                  @input=${this._set('object_type')}
                  placeholder="document"
              /></label>
              <label class="field"
                ><span>${t('Object id')}</span
                ><input class="mono" required @input=${this._set('object_id')} placeholder="doc_1"
              /></label>
              <label class="field"
                ><span
                  >${t('Condition')}
                  ${help('A named condition of this model that must hold at decision time for this tuple to count.')}</span
                ><input class="mono" @input=${this._set('condition')} placeholder="in_office_hours"
              /></label>
              <label class="field"
                ><span
                  >${t('Condition context (JSON)')}
                  ${help('Values stored with the tuple that the condition reads ($2).')}</span
                ><input
                  class="mono"
                  @input=${this._set('condition_context')}
                  placeholder='{"tz":"Europe/Berlin"}'
              /></label>
              <label class="field wide"
                ><span
                  >${t('Expires at')}
                  ${help('Server time after which the tuple no longer counts. Pick a preset or a date and time; empty = never.')}</span
                >
                <span class="expiry">
                  <input
                    type="datetime-local"
                    .value=${this.form.expires_at ?? ''}
                    @input=${this._set('expires_at')}
                  />
                  <span class="seg">
                    ${PgcData.EXPIRY_PRESETS.map(
                      ([label, ms]) =>
                        html`<button type="button" class="sm" @click=${() => this._preset(ms)}>
                          ${t(label)}
                        </button>`,
                    )}
                    <button type="button" class="sm" @click=${() => this._preset(null)}>${t('never')}</button>
                  </span>
                </span>
              </label>
              <datalist id="dl-assignable">
                ${this._assignable().map((n) => html`<option value=${n}></option>`)}
              </datalist>
              <datalist id="dl-object-types">
                ${(this.meta?.types ?? []).map((n) => html`<option value=${n}></option>`)}
              </datalist>
              <p class="help wide">
                ${t('Only relations with a direct rule on this type take tuples; a derived permission is refused by the engine.')}
              </p>
              <div class="actions wide">
                <button class="primary" ?disabled=${this.busy}>${t('Write tuple')}</button>
                <button type="button" @click=${() => (this.adding = false)}>${t('Cancel')}</button>
              </div>
            </form>`
          : nothing
      }
      ${
        this.rows && can
          ? removeBar(this, {
              one: 'tuple',
              many: 'tuples',
              describe: (k) => k,
              warning:
                'Revoking a relationship takes effect immediately for every decision that depends on it.',
              onConfirm: () => this._removeSelected(),
            })
          : nothing
      }
      ${
        this.rows
          ? this.rows.length
            ? html`<div class="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        ${
                          can
                            ? selectAllCell(
                                this,
                                this.rows.map((tu) => this._key(tu)),
                              )
                            : nothing
                        }
                        ${this._sortTh('subject', t('Subject'), help('Who holds the relationship: type:id, or a userset like team:x#member.'))}
                        ${this._sortTh('relation', t('Relation'))} ${this._sortTh('object', t('Object'))}
                        ${this._sortTh('condition', t('Condition'), help('The condition this tuple carries, with its stored context.'))}
                        ${this._sortTh(
                          'expires',
                          t('Expires'),
                          html`<button
                            class="sm ghost"
                            title=${this.expiryAbsolute ? t('show as relative time') : t('show as date and time')}
                            @click=${(e) => this._toggleExpiryMode(e)}
                          >
                            ${this.expiryAbsolute ? t('absolute') : t('relative')}
                          </button>`,
                        )}
                      </tr>
                    </thead>
                    <tbody>
                      ${this._sorted().map(
                        (tu) =>
                          html`<tr>
                            ${can ? selectionCell(this, this._key(tu)) : nothing}
                            <td class="mono">${subjectOf(tu)}</td>
                            <td class="mono">${tu.relation}</td>
                            <td class="mono">${tu.object_type}:${tu.object_id}</td>
                            <td class="mono">
                              ${tu.condition_name}${tu.condition_context && tu.condition_context !== null ? html` <span class="muted">${JSON.stringify(tu.condition_context)}</span>` : nothing}
                            </td>
                            <td class="muted">${this._expiry(tu)}</td>
                          </tr>`,
                      )}
                    </tbody>
                  </table>
                </div>
                ${this._pager()}
                <p class="help">
                  ${
                    this.total > this.rows.length
                      ? t('{shown} of {total} tuples shown', { shown: this.rows.length, total: this.total })
                      : t2('{n} tuple shown', '{n} tuples shown', this.rows.length)
                  }
                </p>`
            : html`<div class="empty">
                ${this.q ? t('No tuples match the filter.') : t('No tuples in this store yet.')}
              </div>`
          : html`<p class="muted">${t('Loading…')}</p>`
      }
    `;
  }
}
customElements.define('pgc-data', PgcData);
