import { html, nothing } from 'lit';
import { PgcElement, help, errorBox } from '../base.js';
import { api } from '../api.js';
import { highlightJSON } from '../highlight.js';
import { t } from '../i18n.js';
import { run, fmtTime, fmtRelative, copyText } from '../util.js';

// Decisions tab: what pgauthzd decided for this store — the decision log
// (ADR 0013) read from its postgres sink (ADR 0015). A window and filters,
// the window's summary (outcomes; the reasons, actions and subjects behind
// the denials — the intent-versus-behaviour view), and the lines newest
// first, each expandable to the full record. A line hands over to the Test
// tab: explain the same question now, or replay it at that instant.
export class PgcDecisions extends PgcElement {
  static properties = {
    store: { type: String },
    caps: { attribute: false },
    d: { state: true },
    summary: { state: true },
    subject: { state: true },
    resource: { state: true },
    action: { state: true },
    outcome: { state: true },
    range: { state: true },
    open: { state: true },
    limit: { state: true }, // rows per page
    page: { state: true }, // 1-based; cursors[page] is the keyset cursor the page starts at
    cursors: { state: true },
    busy: { state: true },
    error: { state: true },
    copied: { state: true },
  };

  static RANGES = [
    ['1h', 3600e3],
    ['24h', 86400e3],
    ['7d', 7 * 86400e3],
    ['30d', 30 * 86400e3],
    ['all', 0],
  ];

  constructor() {
    super();
    /** @type {import('../types.js').DecisionsResponse|null} */
    this.d = null;
    this.summary = null;
    this.subject = '';
    this.resource = '';
    this.action = '';
    this.outcome = '';
    this.range = '24h';
    this.open = null;
    this.limit = 25;
    this.page = 1;
    this.cursors = [''];
    this.busy = false;
    this.error = '';
    this.copied = 0;
  }

  willUpdate(changed) {
    if (changed.has('store') && this.store) void this._load();
  }

  _params() {
    const p = {};
    if (this.subject.trim()) p.subject = this.subject.trim();
    if (this.resource.trim()) p.resource = this.resource.trim();
    if (this.action.trim()) p.action = this.action.trim();
    if (this.outcome) p.outcome = this.outcome;
    const ms = PgcDecisions.RANGES.find(([k]) => k === this.range)?.[1] ?? 0;
    if (ms) p.from = new Date(Date.now() - ms).toISOString();
    return p;
  }

  // A new question: page 1 and the window's summary (its total is the
  // page count's denominator — the summary and the list share the filters).
  async _load(e) {
    e?.preventDefault();
    this.open = null;
    this.page = 1;
    this.cursors = [''];
    const p = { ...this._params(), limit: this.limit };
    const r = await run(this, () =>
      Promise.all([api.decisions(this.store, p), api.decisionsSummary(this.store, p)]),
    );
    if (!r) return;
    [this.d, this.summary] = r;
    this.cursors = ['', this.d.next ?? ''];
  }

  // Keyset paging: a page is reached through the cursor the previous page
  // ended with, so the pager walks pages in order (first, previous, next)
  // and remembers every cursor it has seen for the way back.
  async _goto(page) {
    const pages = this._pages();
    if (page < 1 || page > pages || page === this.page || this.busy) return;
    const before = this.cursors[page - 1];
    if (page > 1 && !before) return;
    const p = { ...this._params(), limit: this.limit };
    if (before) p.before = before;
    const r = await run(this, () => api.decisions(this.store, p));
    if (!r) return;
    this.open = null;
    this.d = r;
    this.page = page;
    const cursors = this.cursors.slice();
    cursors[page] = r.next ?? '';
    this.cursors = cursors;
  }

  _pages() {
    const total = this.summary?.total ?? 0;
    return Math.max(1, Math.ceil(total / this.limit));
  }

  async _setLimit(n) {
    this.limit = n;
    await this._load();
  }

  _pager() {
    const pages = this._pages();
    const total = this.summary?.total ?? this.d?.rows.length ?? 0;
    const from = (this.page - 1) * this.limit + 1;
    const to = Math.min(total, from + (this.d?.rows.length ?? 0) - 1);
    return html`<div class="toolbar decisions-pager" data-testid="decisions-pager">
      <span class="muted"
        >${t('Page {p} of {n}', { p: this.page, n: pages })} ·
        ${t('{from}–{to} of {total}', { from, to, total })}</span
      >
      <div class="actions">
        <label class="muted"
          >${t('per page')}
          <select
            data-testid="decisions-limit"
            .value=${String(this.limit)}
            @change=${(e) => this._setLimit(Number(e.target.value))}
          >
            ${[25, 50, 100, 250].map((n) => html`<option value=${n} ?selected=${n === this.limit}>${n}</option>`)}
          </select></label
        >
        <div class="seg">
          <button
            type="button"
            class="sm"
            ?disabled=${this.page <= 1 || this.busy}
            data-testid="decisions-first"
            @click=${() => this._goto(1)}
          >
            ${t('First')}
          </button>
          <button
            type="button"
            class="sm"
            ?disabled=${this.page <= 1 || this.busy}
            data-testid="decisions-prev"
            @click=${() => this._goto(this.page - 1)}
          >
            ${t('Previous')}
          </button>
          <button
            type="button"
            class="sm"
            ?disabled=${this.page >= pages || !this.d?.next || this.busy}
            data-testid="decisions-next"
            @click=${() => this._goto(this.page + 1)}
          >
            ${t('Next')}
          </button>
        </div>
      </div>
    </div>`;
  }

  // A top-list entry narrows the question to it.
  _narrow(patch) {
    Object.assign(this, patch);
    void this._load();
  }

  // Hands the line to the Test tab: the same question explained now, or
  // replayed at the instant it was decided (audit_check_access).
  _toTest(row, at) {
    try {
      sessionStorage.setItem(
        'pgc-test-prefill',
        JSON.stringify({
          store: this.store,
          subject: `${row.subject_type}:${row.subject_id}`,
          action: row.action,
          resource: `${row.resource_type}:${row.resource_id}`,
          at: at ? row.ts : '',
          run: true,
        }),
      );
    } catch {
      /* no storage: the Test tab opens empty */
    }
    this.dispatchEvent(
      new CustomEvent('navigate', {
        detail: `stores/${this.store}/test/single-check`,
        bubbles: true,
        composed: true,
      }),
    );
  }

  async _copy(row) {
    if (await copyText(JSON.stringify(row.line, null, 2))) {
      this.copied = row.id;
      setTimeout(() => (this.copied = 0), 1200);
    }
  }

  static outcome(row) {
    if (row.error) return ['error', 'warn', t('error')];
    if (row.state === 'conditional') return ['conditional', 'warn', t('conditional')];
    if (row.decision === true) return ['allow', 'ok', t('allowed')];
    if (row.decision === false) return ['deny', 'deny', t('denied')];
    return ['', 'muted', row.endpoint];
  }

  _filters() {
    return html`<form class="card decisions-filters" @submit=${this._load}>
      <div class="toolbar">
        <h3>
          ${t('What was decided')}
          ${help("pgauthzd's decision log for this store, read from its postgres sink: every evaluation, check, explain and reserve on both listeners, with the reason, the caller and the model in effect. Context values are never logged, only key names.")}
        </h3>
        <div class="seg" role="radiogroup" aria-label=${t('Window')}>
          ${PgcDecisions.RANGES.map(
            ([k]) =>
              html`<button
                type="button"
                class="sm ${this.range === k ? 'active' : ''}"
                data-testid="decisions-range-${k}"
                @click=${() => {
                  this.range = k;
                  void this._load();
                }}
              >
                ${k === 'all' ? t('all') : k}
              </button>`,
          )}
        </div>
      </div>
      <div class="filters">
        <label
          >${t('Subject')}
          <input
            class="mono"
            placeholder="user:alice"
            data-testid="decisions-subject"
            .value=${this.subject}
            @input=${(e) => (this.subject = e.target.value)}
        /></label>
        <label
          >${t('Action')}
          <input
            class="mono"
            placeholder="can_read"
            data-testid="decisions-action"
            .value=${this.action}
            @input=${(e) => (this.action = e.target.value)}
        /></label>
        <label
          >${t('Resource')}
          <input
            class="mono"
            placeholder="doc:budget"
            data-testid="decisions-resource"
            .value=${this.resource}
            @input=${(e) => (this.resource = e.target.value)}
        /></label>
        <label
          >${t('Outcome')}
          <select
            data-testid="decisions-outcome"
            .value=${this.outcome}
            @change=${(e) => (this.outcome = e.target.value)}
          >
            <option value="">${t('any')}</option>
            <option value="allow">${t('allowed')}</option>
            <option value="deny">${t('denied')}</option>
            <option value="conditional">${t('conditional')}</option>
            <option value="error">${t('error')}</option>
          </select></label
        >
        <button class="primary" ?disabled=${this.busy} data-testid="decisions-search">${t('Search')}</button>
      </div>
      <span class="help"
        >${t('A subject or resource is type:id, or a bare id; the window is the time of the decision.')}</span
      >
    </form>`;
  }

  _summary() {
    const s = this.summary;
    if (!s?.configured) return nothing;
    const list = (title, rows, patch) =>
      html`<div>
        <h4>${title}</h4>
        ${
          rows.length
            ? html`<ol>
                ${rows.map(
                  (r) =>
                    html`<li>
                      <a
                        href="#"
                        class="mono"
                        @click=${(e) => (e.preventDefault(), this._narrow(patch(r.key)))}
                        >${r.key || '—'}</a
                      >
                      <span class="muted">${r.count}</span>
                    </li>`,
                )}
              </ol>`
            : html`<span class="muted">${t('none')}</span>`
        }
      </div>`;
    return html`<section class="card decisions-summary" data-testid="decisions-summary">
      <div class="toolbar">
        <h3>${t('{n} decision(s)', { n: s.total })}</h3>
        <div class="actions">
          <span class="badge ok">${s.allow} ${t('allowed')}</span>
          <span class="badge deny">${s.deny} ${t('denied')}</span>
          <span class="badge warn">${s.conditional} ${t('conditional')}</span>
          <span class="badge warn">${s.error} ${t('error')}</span>
        </div>
      </div>
      <div class="top-lists">
        ${list(t('Denied: by reason'), s.denied_reasons, () => ({ outcome: 'deny' }))}
        ${list(t('Denied: by action'), s.denied_actions, (k) => ({ outcome: 'deny', action: k }))}
        ${list(t('Denied: by subject'), s.denied_subjects, (k) => ({ outcome: 'deny', subject: k }))}
        ${list(t('Allowed: by reason'), s.allowed_reasons, () => ({ outcome: 'allow' }))}
      </div>
      ${help("The window divided by outcome, and what lies behind the denials: the engine's reason, the action asked for, the subject refused. Click an entry to narrow the list to it.")}
    </section>`;
  }

  _detail(row) {
    const l = row.line ?? {};
    const kv = (k, v) =>
      v
        ? html`<dt>${k}</dt>
            <dd class="mono">${v}</dd>`
        : nothing;
    return html`<tr class="decision-detail" data-testid="decisions-detail">
      <td colspan="9">
        <div class="toolbar">
          <dl class="kv">
            ${kv(t('Request'), row.request_id)}
            ${kv(t('Listener'), `${row.listener} · ${row.endpoint}${row.via ? ' · ' + row.via : ''}`)}
            ${kv(t('Actor'), row.actor)} ${kv(t('Client'), row.client)} ${kv(t('Issuer'), row.issuer)}
            ${kv(t('Model'), l.model ? `${l.model.name ? l.model.name + '@' + l.model.version + ' · ' : ''}${l.model.checksum ?? ''}` : '')}
            ${kv(t('Policy'), l.policy ? `OPA ${l.policy.opa_version ?? ''} ${(l.policy.bundles ?? []).map((b) => `${b.name}@${b.revision}`).join(', ')}` : '')}
            ${kv(t('Context keys'), (l.context_keys ?? []).join(', '))}
            ${kv(t('Contextual tuples'), l.contextual_tuples ? String(l.contextual_tuples) : '')}
            ${kv(t('Hooks'), (l.hooks ?? []).join(', '))}
            ${kv(t('Missing context'), (l.missing_context ?? []).join(', '))} ${kv(t('Error'), row.error)}
          </dl>
          <div class="actions">
            ${
              row.subject_id && row.action && row.resource_id
                ? html`<button
                      class="sm"
                      data-testid="decisions-explain"
                      @click=${() => this._toTest(row, false)}
                    >
                      ${t('Explain now')}
                    </button>
                    <button class="sm" data-testid="decisions-replay" @click=${() => this._toTest(row, true)}>
                      ${t('Replay at that instant')}
                    </button>`
                : nothing
            }
            <button class="sm" @click=${() => this._copy(row)}>
              ${this.copied === row.id ? t('Copied') : t('Copy line')}
            </button>
          </div>
        </div>
        <pre class="mono json">${highlightJSON(JSON.stringify(l, null, 2))}</pre>
      </td>
    </tr>`;
  }

  _table() {
    const d = this.d;
    if (!d?.configured) return nothing;
    if (!d.rows.length) return html`<div class="empty">${t('No decisions in this window.')}</div>`;
    return html`<section class="card">
      ${this._pager()}
      <div class="table-wrap">
        <table class="decisions" data-testid="decisions-table">
          <thead>
            <tr>
              <th>${t('When')}</th>
              <th>${t('Outcome')}</th>
              <th>${t('Subject')}</th>
              <th>${t('Action')}</th>
              <th>${t('Resource')}</th>
              <th>${t('Reason')}</th>
              <th>${t('Via')}</th>
              <th>${t('Actor')}</th>
              <th class="num">ms</th>
            </tr>
          </thead>
          <tbody>
            ${d.rows.map((r) => {
              const [, cls, label] = PgcDecisions.outcome(r);
              return html`<tr
                  class="decision-row ${this.open === r.id ? 'open' : ''}"
                  data-testid="decisions-row"
                  @click=${() => (this.open = this.open === r.id ? null : r.id)}
                >
                  <td class="muted nowrap" title=${r.ts}>
                    ${fmtTime(r.ts)} <span class="muted">${fmtRelative(r.ts)}</span>
                  </td>
                  <td><span class="badge ${cls}">${label}</span></td>
                  <td class="mono">${r.subject_id ? `${r.subject_type}:${r.subject_id}` : ''}</td>
                  <td class="mono">${r.action}</td>
                  <td class="mono">${r.resource_id ? `${r.resource_type}:${r.resource_id}` : ''}</td>
                  <td class="mono muted">${r.reason}</td>
                  <td class="muted">
                    ${r.via || r.endpoint}${r.listener === 'callback' ? ' · callback' : ''}
                  </td>
                  <td class="mono muted">${r.actor}</td>
                  <td class="num muted">${r.latency_ms.toFixed(1)}</td>
                </tr>
                ${this.open === r.id ? this._detail(r) : nothing}`;
            })}
          </tbody>
        </table>
      </div>
      ${this._pager()}
    </section>`;
  }

  render() {
    if (this.d && !this.d.configured)
      return html`<section class="card" data-testid="decisions-unconfigured">
        <h3>${t('No decision log sink')}</h3>
        <p class="help">
          ${t("pgauthzd writes its decision log to a database only when told to. Point the instances whose decisions you want to see at the console's own database: DECISION_LOG=postgres and DECISION_LOG_DSN=<the console's PG_DSN>. The table decisionlog.decisions appears on their next start; decisions are kept for DECISION_LOG_RETENTION_DAYS (30 by default).")}
        </p>
      </section>`;
    return html`<div class="decisions-tab">
      ${this._filters()} ${this.error ? errorBox(this.error) : nothing} ${this._summary()} ${this._table()}
    </div>`;
  }
}

customElements.define('pgc-decisions', PgcDecisions);
