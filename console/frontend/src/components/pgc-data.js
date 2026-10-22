import { html, nothing } from 'lit';
import { PgcElement, help, errorBox } from '../base.js';
import { api } from '../api.js';
import { t, t2 } from '../i18n.js';
import { PgcJson } from './pgc-json.js';
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
    panel: { state: true }, // 'import' | 'offboard' | null
    imp: { state: true }, // import: { text, preview, result }
    off: { state: true }, // offboarding: { user_type, user_id, count, result }
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
    this.panel = null;
    this.imp = { text: '' };
    this.off = {};
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
    void this._load();
  }

  willUpdate(changed) {
    if (changed.has('store') && this.store) {
      void this._load();
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
    void this._load();
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
    void this._load();
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
        PgcJson.report(this);
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

  // Import: paste or pick a file (JSON array, OpenFGA ReadTuples JSON, or
  // CSV with the export's header), see what was understood, then write it
  // all in one transaction as you.
  async _importPreview() {
    const r = await this._wrap(() => api.tuplesImport(this.store, this.imp.text, false));
    if (r) this.imp = { ...this.imp, preview: r, result: null };
  }

  async _importApply() {
    const r = await this._wrap(() => api.tuplesImport(this.store, this.imp.text, true));
    if (r) {
      this.imp = { text: '', preview: null, result: r };
      await this._load();
      this.dispatchEvent(new CustomEvent('changed'));
    }
  }

  _importFile(e) {
    const file = e.target.files?.[0];
    if (!file) return;
    file.text().then((text) => (this.imp = { ...this.imp, text, preview: null, result: null }));
  }

  _importPanel() {
    const im = this.imp;
    const pv = im.preview;
    return html`<section class="card" data-testid="data-import">
      <h3>
        ${t('Import tuples')}
        ${help('Paste or pick a file: a JSON array of tuples (the Export JSON shape), an OpenFGA ReadTuples export ({"tuples": [{"key": {user, relation, object}}]}), or CSV with the export\'s header. Preview shows what was understood; Import writes everything in one transaction as you — an existing tuple is left as it is, a tuple the model refuses fails the whole import. Up to 10000 tuples.')}
      </h3>
      <div class="form">
        <label class="field wide"
          ><span
            >${t('Tuples')} ${help('JSON, OpenFGA JSON or CSV; the shape is detected from the text.')}</span
          ><textarea
            class="mono"
            rows="8"
            spellcheck="false"
            .value=${im.text}
            @input=${(e) => (this.imp = { ...this.imp, text: e.target.value, preview: null, result: null })}
            data-testid="data-import-text"
          ></textarea>
        </label>
        <label class="field"
          ><span>${t('or a file')}</span
          ><input
            type="file"
            accept=".json,.csv,application/json,text/csv"
            @change=${this._importFile}
            data-testid="data-import-file"
        /></label>
        <div class="actions wide">
          <button
            class="sm"
            ?disabled=${this.busy || !im.text.trim()}
            data-testid="data-import-preview"
            @click=${this._importPreview}
          >
            ${t('Preview')}
          </button>
          ${
            pv
              ? html`<span class="help" data-testid="data-import-count">
                    ${t('{n} tuples understood as {shape}, on {types}', { n: pv.count, shape: pv.shape.toUpperCase(), types: pv.object_types.join(', ') })}
                  </span>
                  <button
                    class="primary sm"
                    ?disabled=${this.busy}
                    data-testid="data-import-apply"
                    @click=${this._importApply}
                  >
                    ${t('Import {n} tuples', { n: pv.count })}
                  </button>`
              : nothing
          }
          ${im.result ? html`<span class="help" data-testid="data-import-result">${t('{n} tuples written', { n: im.result.written })}</span>` : nothing}
          <button type="button" class="sm" @click=${() => (this.panel = null)}>${t('Close')}</button>
        </div>
      </div>
      ${
        pv?.preview?.length
          ? html`<div class="table-wrap">
              <table class="compact" data-testid="data-import-table">
                <thead>
                  <tr>
                    <th>${t('Subject')}</th>
                    <th>${t('Relation')}</th>
                    <th>${t('Object')}</th>
                    <th>${t('Condition')}</th>
                    <th>${t('Expires at')}</th>
                  </tr>
                </thead>
                <tbody>
                  ${pv.preview.map(
                    (x) =>
                      html`<tr>
                        <td class="mono">${subjectOf(x)}</td>
                        <td class="mono">${x.relation}</td>
                        <td class="mono">${x.object_type}:${x.object_id}</td>
                        <td class="mono">${x.condition ?? ''}</td>
                        <td class="muted">${x.expires_at ?? ''}</td>
                      </tr>`,
                  )}
                  ${
                    pv.count > pv.preview.length
                      ? html`<tr>
                          <td colspan="5" class="muted">
                            ${t('… and {n} more', { n: pv.count - pv.preview.length })}
                          </td>
                        </tr>`
                      : nothing
                  }
                </tbody>
              </table>
            </div>`
          : nothing
      }
    </section>`;
  }

  // Offboarding: every tuple whose subject is this one — count, then remove.
  async _offboardCount() {
    const o = this.off;
    const r = await this._wrap(() => api.offboard(this.store, o.user_type?.trim(), o.user_id?.trim(), false));
    if (r) this.off = { ...this.off, count: r.count, result: null, confirming: false };
  }

  async _offboardApply() {
    const o = this.off;
    const r = await this._wrap(() => api.offboard(this.store, o.user_type?.trim(), o.user_id?.trim(), true));
    if (r) {
      this.off = { ...this.off, count: undefined, confirming: false, result: r };
      await this._load();
      this.dispatchEvent(new CustomEvent('changed'));
    }
  }

  _offboardPanel() {
    const o = this.off;
    const ready = !!(o.user_type?.trim() && o.user_id?.trim());
    return html`<section class="card" data-testid="data-offboard">
      <h3>
        ${t('Offboard a subject')}
        ${help('Removes every tuple this subject holds in the store (delete_user_tuples), as a direct subject and as the subject of usersets — a leaver, a decommissioned service account. Audited as you; every decision that depended on those tuples changes immediately. Count first, then confirm.')}
      </h3>
      <form
        class="form"
        data-testid="data-offboard-form"
        @submit=${(e) => {
          e.preventDefault();
          void this._offboardCount();
        }}
      >
        <label class="field"
          ><span>${t('Subject type')} ${help('The type of the subject, e.g. user or team.')}</span
          ><input
            class="mono"
            required
            .value=${o.user_type ?? ''}
            @input=${(e) => (this.off = { ...this.off, user_type: e.target.value, count: undefined, result: null })}
            data-testid="data-offboard-type"
        /></label>
        <label class="field"
          ><span>${t('Subject id')} ${help('The subject, e.g. alice.')}</span
          ><input
            class="mono"
            required
            .value=${o.user_id ?? ''}
            @input=${(e) => (this.off = { ...this.off, user_id: e.target.value, count: undefined, result: null })}
            data-testid="data-offboard-id"
        /></label>
        <div class="actions wide">
          <button class="sm" ?disabled=${this.busy || !ready} data-testid="data-offboard-count">
            ${t('Count tuples')}
          </button>
          ${
            o.count !== undefined
              ? o.count === 0
                ? html`<span class="help" data-testid="data-offboard-none"
                    >${t('no tuples for this subject')}</span
                  >`
                : o.confirming
                  ? html`<span class="help"
                        >${t('Remove all {n} tuples of {subject}?', { n: o.count, subject: `${o.user_type}:${o.user_id}` })}</span
                      >
                      <button
                        type="button"
                        class="sm danger"
                        ?disabled=${this.busy}
                        data-testid="data-offboard-confirm"
                        @click=${this._offboardApply}
                      >
                        ${t('Yes, remove them')}
                      </button>
                      <button
                        type="button"
                        class="sm"
                        @click=${() => (this.off = { ...this.off, confirming: false })}
                      >
                        ${t('Cancel')}
                      </button>`
                  : html`<span class="help" data-testid="data-offboard-countval"
                        >${t('{n} tuples', { n: o.count })}</span
                      >
                      <button
                        type="button"
                        class="sm danger"
                        data-testid="data-offboard-remove"
                        @click=${() => (this.off = { ...this.off, confirming: true })}
                      >
                        ${t('Remove them…')}
                      </button>`
              : nothing
          }
          ${o.result ? html`<span class="help" data-testid="data-offboard-result">${t('{n} removed', { n: o.result.removed })}</span>` : nothing}
          <button type="button" class="sm" @click=${() => (this.panel = null)}>${t('Close')}</button>
        </div>
      </form>
    </section>`;
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
            this.caps?.can_export
              ? html`<span class="seg" data-testid="data-export">
                  <a
                    class="btn sm"
                    href=${api.tuplesExportURL(this.store, 'json')}
                    download
                    title=${t('Every tuple of the store as JSON — the native shape, with conditions, context and expiry; what Import takes back.')}
                    data-testid="data-export-json"
                    >${t('Export')} JSON</a
                  >
                  <a
                    class="btn sm"
                    href=${api.tuplesExportURL(this.store, 'csv')}
                    download
                    title=${t('The same columns as CSV, for a spreadsheet; Import takes it back.')}
                    data-testid="data-export-csv"
                    >CSV</a
                  >
                  <a
                    class="btn sm"
                    href=${api.tuplesExportURL(this.store, 'openfga')}
                    download
                    title=${t('The OpenFGA ReadTuples shape (no conditions or expiry).')}
                    data-testid="data-export-openfga"
                    >OpenFGA</a
                  >
                </span>`
              : nothing
          }
          ${
            can
              ? html`<button
                    class="sm"
                    data-testid="data-import-open"
                    @click=${() => {
                      this.panel = this.panel === 'import' ? null : 'import';
                      this.adding = false;
                    }}
                  >
                    ${t('Import…')}
                  </button>
                  <button
                    class="sm"
                    data-testid="data-offboard-open"
                    @click=${() => {
                      this.panel = this.panel === 'offboard' ? null : 'offboard';
                      this.adding = false;
                    }}
                  >
                    ${t('Offboard…')}
                  </button>
                  <button
                    class="primary"
                    @click=${() => {
                      this.adding = !this.adding;
                      this.panel = null;
                    }}
                  >
                    ${t('Add')}
                  </button>`
              : html`<span class="help">${t('writing needs "share" (sharer or owner)')}</span>`
          }
        </div>
      </div>
      ${this.panel === 'import' ? this._importPanel() : this.panel === 'offboard' ? this._offboardPanel() : nothing}
      ${this.error ? errorBox(this.error) : nothing}
      ${
        this.adding
          ? html`<form class="card form" @submit=${this._write}>
              <label class="field"
                ><span>${t('Subject type')} ${help('The type of the subject, e.g. user or team.')}</span
                ><input class="mono" required @input=${this._set('user_type')}
              /></label>
              <label class="field"
                ><span
                  >${t('Subject id')}
                  ${help('The subject, e.g. alice, or * for everyone of that type (when the rule allows wildcards).')}</span
                ><input class="mono" required @input=${this._set('user_id')}
              /></label>
              <label class="field"
                ><span
                  >${t('Subject relation (userset)')}
                  ${help('Optional. Grant to a group: member makes the subject team:x#member.')}</span
                ><input class="mono" @input=${this._set('user_relation')}
              /></label>
              <label class="field"
                ><span
                  >${t('Relation')}
                  ${help('What the subject becomes on the object, e.g. viewer; only assignable relations are suggested.')}</span
                ><input class="mono" required list="dl-assignable" @input=${this._set('relation')}
              /></label>
              <label class="field"
                ><span>${t('Object type')} ${help('The type of the object, e.g. document.')}</span
                ><input class="mono" required list="dl-object-types" @input=${this._set('object_type')}
              /></label>
              <label class="field"
                ><span>${t('Object id')} ${help('The object, e.g. doc_1.')}</span
                ><input class="mono" required @input=${this._set('object_id')}
              /></label>
              <label class="field"
                ><span
                  >${t('Condition')}
                  ${help('Optional: a named condition of this model that must hold at decision time for this tuple to count.')}</span
                ><input class="mono" @input=${this._set('condition')}
              /></label>
              <label class="field"
                ><span
                  >${t('Condition context (JSON)')}
                  ${help('Values stored with the tuple that the condition reads ($2), e.g. {"tz": "Europe/Berlin"}.')}</span
                ><pgc-json
                  rows="2"
                  testid="data-input-condition-context"
                  .value=${this.form.condition_context ?? ''}
                  @json-input=${(e) => (this.form = { ...this.form, condition_context: e.detail.text })}
                ></pgc-json
              ></label>
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
            ? html`<section class="card panel" data-testid="data-table">
                <div class="table-wrap">
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
                              ${tu.condition_name}${tu.condition_context ? html` <span class="muted">${JSON.stringify(tu.condition_context)}</span>` : nothing}
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
                </p>
              </section>`
            : html`<div class="empty">
                ${this.q ? t('No tuples match the filter.') : t('No tuples in this store yet.')}
              </div>`
          : html`<p class="muted">${t('Loading…')}</p>`
      }
    `;
  }
}
customElements.define('pgc-data', PgcData);
