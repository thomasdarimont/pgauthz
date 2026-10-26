import { html, nothing } from 'lit';
import { PgcElement, help, errorBox, loading } from '../base.js';
import { api } from '../api.js';
import { t } from '../i18n.js';
import { run, forbiddenText, fmtTime, parseList } from '../util.js';

// Platform → Issuers: the trusted identity providers' bindings, managed
// here for the whole fleet (authz.issuer_bindings). Trust — issuer,
// audience, signing keys — is every pgauthzd's environment (JWT_ISSUERS);
// a row replaces what an environment issuer's tokens may do (stores, DB
// roles, client roles, PEP clients, enabled) and may only narrow it. With a
// reachable pgauthzd callback the effective set is shown too: which issuers
// exist, whose bindings come from a row, and the revision in force.
export class PgcIssuers extends PgcElement {
  static properties = {
    me: { attribute: false },
    d: { state: true },
    busy: { state: true },
    error: { state: true },
    form: { state: true },
    confirming: { state: true },
    saved: { state: true },
    audit: { state: true },
    page: { state: true },
    limit: { state: true },
  };

  constructor() {
    super();
    /** @type {import('../types.js').IssuersResponse|null} */
    this.d = null;
    this.busy = false;
    this.error = '';
    /** @type {import('../types.js').IssuerForm|null} */
    this.form = null;
    this.confirming = '';
    this.saved = '';
    /** @type {import('../types.js').IssuerAuditPage|null} */
    this.audit = null;
    this.page = 1;
    this.limit = 10;
    /** @type {string[]} the cursor each page was reached with (index = page − 1) */
    this.cursors = [''];
  }

  connectedCallback() {
    super.connectedCallback();
    void this._load();
  }

  async _load() {
    const d = await run(this, async () => {
      try {
        return await api.platformIssuers();
      } catch (e) {
        throw new Error(forbiddenText(e));
      }
    });
    if (d) this.d = d;
    await this._goto(1, true);
  }

  // Keyset paging of the history: a page is reached through the cursor the
  // previous page ended with; every cursor seen is kept for the way back.
  async _goto(page, reload = false) {
    if (page < 1 || (!reload && (page === this.page || this.busy))) return;
    if (reload) this.cursors = [''];
    const before = this.cursors[page - 1];
    if (page > 1 && !before) return;
    const p = { limit: this.limit };
    if (before) p.before = before;
    const r = await run(this, () => api.platformIssuersAudit(p));
    if (!r) return;
    this.audit = r;
    this.page = page;
    const cursors = this.cursors.slice();
    cursors[page] = r.next ?? '';
    this.cursors = cursors;
  }

  _pages() {
    return Math.max(1, Math.ceil((this.audit?.total ?? 0) / this.limit));
  }

  _pager() {
    const pages = this._pages();
    const total = this.audit?.total ?? 0;
    const from = total ? (this.page - 1) * this.limit + 1 : 0;
    const to = Math.min(total, from + (this.audit?.rows.length ?? 0) - 1);
    return html`<div class="toolbar" data-testid="issuers-audit-pager">
      <span class="muted"
        >${t('Page {p} of {n}', { p: this.page, n: pages })} ·
        ${t('{from}–{to} of {total}', { from, to, total })}</span
      >
      <div class="actions">
        <label class="muted"
          >${t('per page')}
          <select
            data-testid="issuers-audit-limit"
            .value=${String(this.limit)}
            @change=${(e) => {
              this.limit = Number(e.target.value);
              void this._goto(1, true);
            }}
          >
            ${[10, 25, 50, 100].map((n) => html`<option value=${n} ?selected=${n === this.limit}>${n}</option>`)}
          </select></label
        >
        <div class="seg">
          <button
            type="button"
            class="sm"
            ?disabled=${this.page <= 1 || this.busy}
            data-testid="issuers-audit-first"
            @click=${() => this._goto(1)}
          >
            ${t('First')}
          </button>
          <button
            type="button"
            class="sm"
            ?disabled=${this.page <= 1 || this.busy}
            data-testid="issuers-audit-prev"
            @click=${() => this._goto(this.page - 1)}
          >
            ${t('Previous')}
          </button>
          <button
            type="button"
            class="sm"
            ?disabled=${this.page >= pages || !this.audit?.next || this.busy}
            data-testid="issuers-audit-next"
            @click=${() => this._goto(this.page + 1)}
          >
            ${t('Next')}
          </button>
        </div>
      </div>
    </div>`;
  }

  _blank(issuer = '') {
    return {
      issuer,
      stores: '',
      db_roles: '',
      client_db_roles: '{}',
      pep_clients: '{}',
      enabled: true,
      description: '',
      isNew: true,
    };
  }

  /** @param {import('../types.js').IssuerBinding} b */
  _edit(b) {
    this.saved = '';
    this.form = {
      issuer: b.issuer,
      stores: b.stores.join('\n'),
      db_roles: b.db_roles.join('\n'),
      client_db_roles: JSON.stringify(b.client_db_roles ?? {}, null, 2),
      pep_clients: JSON.stringify(b.pep_clients ?? {}, null, 2),
      enabled: b.enabled,
      description: b.description ?? '',
      isNew: false,
    };
  }

  _set(k) {
    return (e) =>
      (this.form = { ...this.form, [k]: e.target.type === 'checkbox' ? e.target.checked : e.target.value });
  }

  async _save(e) {
    e.preventDefault();
    const f = this.form;
    let client_db_roles, pep_clients;
    try {
      client_db_roles = JSON.parse(f.client_db_roles || '{}');
      pep_clients = JSON.parse(f.pep_clients || '{}');
    } catch (err) {
      this.error = t('Client roles and PEP clients must be JSON objects: {err}', { err: err.message });
      return;
    }
    const r = await run(this, async () => {
      try {
        return await api.platformIssuerSave({
          issuer: f.issuer.trim(),
          stores: parseList(f.stores),
          db_roles: parseList(f.db_roles),
          client_db_roles,
          pep_clients,
          enabled: !!f.enabled,
          description: f.description,
        });
      } catch (err) {
        throw new Error(forbiddenText(err));
      }
    });
    if (r) {
      this.saved = t(
        'Saved as revision {n}; every instance with ISSUERS_SOURCE=env+db applies it within its poll interval.',
        {
          n: r.revision,
        },
      );
      this.form = null;
      await this._load();
    }
  }

  async _delete(issuer) {
    const r = await run(this, async () => {
      try {
        return await api.platformIssuerDelete(issuer);
      } catch (err) {
        throw new Error(forbiddenText(err));
      }
    });
    this.confirming = '';
    if (r) {
      this.saved = t('Binding removed: the issuer is back to its environment bindings.');
      await this._load();
    }
  }

  _form() {
    const f = this.form;
    const eff = this.d?.effective;
    const known = eff?.available ? (eff.issuers ?? []).map((i) => i.issuer) : [];
    return html`<form class="form card" data-testid="issuers-form" @submit=${(e) => this._save(e)}>
      <h4 class="wide">${f.isNew ? t('New binding') : t('Edit binding')}</h4>
      <label class="field wide"
        ><span
          >${t('Issuer')}
          ${help("The token's iss, exactly as in the instances' JWT_ISSUERS. A row for an issuer no instance trusts is ignored — a binding can never add trust.")}</span
        ><input
          required
          .value=${f.issuer}
          ?readonly=${!f.isNew}
          list="issuers-known"
          placeholder="https://idp.example.com/realms/tenant-a"
          @input=${this._set('issuer')}
          data-testid="issuers-issuer"
        />
        <datalist id="issuers-known">${known.map((i) => html`<option value=${i}></option>`)}</datalist>
      </label>
      <label class="field"
        ><span
          >${t('Stores')}
          ${help('One anchored pattern per line (docs, tenant_a_.*). Tokens of this issuer may ask about these stores only. Must stay within what the environment binds — a row narrows, never widens; empty only when the environment leaves the issuer unbound.')}</span
        ><textarea
          class="list"
          rows="3"
          .value=${f.stores}
          @input=${this._set('stores')}
          data-testid="issuers-stores"
        ></textarea>
      </label>
      <label class="field"
        ><span
          >${t('DB roles')}
          ${help('Anchored patterns of the per-app DB roles tokens of this issuer may claim (DB_ROLE_CLAIM / client roles). Empty = no restriction.')}</span
        ><textarea
          class="list"
          rows="3"
          .value=${f.db_roles}
          @input=${this._set('db_roles')}
          data-testid="issuers-db-roles"
        ></textarea>
      </label>
      <label class="field"
        ><span
          >${t('Client DB roles')}
          ${help('JSON object: client id (azp) → DB role, scoped to this issuer.')}</span
        ><textarea
          class="list"
          rows="3"
          .value=${f.client_db_roles}
          @input=${this._set('client_db_roles')}
          data-testid="issuers-client-db-roles"
        ></textarea>
      </label>
      <label class="field"
        ><span
          >${t('PEP clients')}
          ${help('JSON object: client id → store patterns. These clients may assert a request-body subject (a trusted policy enforcement point), in those stores only — each pattern must be covered by the stores above.')}</span
        ><textarea
          class="list"
          rows="3"
          .value=${f.pep_clients}
          @input=${this._set('pep_clients')}
          data-testid="issuers-pep-clients"
        ></textarea>
      </label>
      <label class="field wide"
        ><span>${t('Description')}</span
        ><input .value=${f.description} @input=${this._set('description')} data-testid="issuers-description"
      /></label>
      <label class="check wide"
        ><input
          type="checkbox"
          .checked=${f.enabled}
          @change=${this._set('enabled')}
          data-testid="issuers-enabled"
        />
        ${t('Enabled')}
        ${help('Unchecked, every token of this issuer is refused (401) while its trust stays configured — pause an identity provider without a deploy.')}</label
      >
      <div class="actions wide">
        <button class="sm" ?disabled=${this.busy} data-testid="issuers-save">${t('Save binding')}</button>
        <button
          type="button"
          class="sm"
          ?disabled=${this.busy}
          @click=${() => (this.form = null)}
          data-testid="issuers-cancel"
        >
          ${t('Cancel')}
        </button>
      </div>
    </form>`;
  }

  _effective() {
    const eff = this.d?.effective;
    if (!eff?.url) return nothing;
    const db = this.d.revision;
    return html`<section class="card" data-testid="issuers-effective">
      <h3>
        ${t('In force')}
        ${help('What the pgauthzd instance the console can reach applies right now: every issuer it trusts (its environment), whether the bindings in force come from the environment or from a row here, and the revision it applied. Other instances follow the same rows.')}
      </h3>
      ${
        eff.available
          ? html`<p class="help">
                <span class="mono">${eff.url}</span> · ${t('source')}
                <span class="mono">${eff.source}</span> · ${t('revision')}
                <span class="mono" data-testid="issuers-revision">${eff.revision}</span>
                ${
                  eff.via === 'admin-api'
                    ? html` ·
                      ${t('over the admin API as {who}', { who: eff.credential === 'token' ? t('you (your own token: its scope decides)') : t('the console (its client certificate)') })}`
                    : nothing
                }
                ${
                  eff.revision === db
                    ? html`<span class="badge ok">${t('applied')}</span>`
                    : html`<span class="badge warn">${t('database is at {n}', { n: db })}</span>`
                }
              </p>
              <div class="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>${t('Issuer')}</th>
                      <th>${t('Audience')}</th>
                      <th>${t('Bindings')}</th>
                      <th>${t('Stores')}</th>
                      <th>${t('DB roles')}</th>
                      <th>${t('PEP clients')}</th>
                      <th>${t('Admin')}</th>
                    </tr>
                  </thead>
                  <tbody>
                    ${(eff.issuers ?? []).map(
                      (i) =>
                        html`<tr data-testid="issuers-effective-row" data-issuer=${i.issuer}>
                          <td class="mono">${i.issuer}</td>
                          <td class="mono">${i.audience}</td>
                          <td>
                            <span class="badge ${i.binding_source === 'db' ? 'accent' : ''}"
                              >${i.binding_source}</span
                            >
                            ${i.enabled ? nothing : html`<span class="badge deny">${t('disabled')}</span>`}
                          </td>
                          <td class="mono">
                            ${i.stores?.length ? i.stores.join(', ') : html`<span class="muted">${t('any')}</span>`}
                          </td>
                          <td class="mono">
                            ${i.db_roles?.length ? i.db_roles.join(', ') : html`<span class="muted">${t('any')}</span>`}
                          </td>
                          <td class="mono">
                            ${Object.keys(i.pep_clients ?? {}).join(', ') || html`<span class="muted">—</span>`}
                          </td>
                          <td class="mono">
                            ${i.admin?.length
                              ? i.admin.map((r) => (r.decide
                                  ? `→ ${r.decide.store} (${r.decide.subject_type ?? 'user'}:${r.decide.subject_claim ?? 'preferred_username'})`
                                  : [r.scope ?? 'issuer', ...(r.capabilities ?? []), ...(r.stores ?? [])].join(' · '))).join('; ')
                              : html`<span class="muted">—</span>`}
                          </td>
                        </tr>`,
                    )}
                  </tbody>
                </table>
              </div>`
          : html`<p class="help">
              <span class="badge deny">${t('unreachable')}</span>
              <span class="mono">${eff.url}</span> ${eff.error}
            </p>`
      }
    </section>`;
  }

  _bindings() {
    const d = this.d;
    const eff = d.effective;
    const inForce = (issuer) => {
      if (!eff?.available) return null;
      const i = (eff.issuers ?? []).find((x) => x.issuer === issuer);
      if (!i)
        return html`<span class="badge deny" title=${t('no instance trusts this issuer: the row is ignored')}
          >${t('untrusted')}</span
        >`;
      if (i.binding_source === 'db') return html`<span class="badge ok">${t('applied')}</span>`;
      return html`<span
        class="badge warn"
        title=${t('the instance kept its environment bindings: the row was rejected (it must narrow, not widen) or is not applied yet')}
        >${t('not applied')}</span
      >`;
    };
    return html`<section class="card">
      <h3>
        ${t('Bindings')}
        ${help('One row per issuer whose bindings are managed here. Everything an issuer not listed may do comes from the environment.')}
      </h3>
      ${this.saved ? html`<p class="help" data-testid="issuers-saved">${this.saved}</p>` : nothing}
      ${
        d.bindings.length
          ? html`<div class="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>${t('Issuer')}</th>
                    <th>${t('Stores')}</th>
                    <th>${t('DB roles')}</th>
                    <th>${t('State')}</th>
                    <th>${t('Description')}</th>
                    <th>${t('Changed')}</th>
                    <th>${t('Created')}</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  ${d.bindings.map(
                    (b) =>
                      html`<tr data-testid="issuers-row" data-issuer=${b.issuer}>
                        <td class="mono">${b.issuer}</td>
                        <td class="mono">
                          ${b.stores.length ? b.stores.join(', ') : html`<span class="muted">${t('as the environment')}</span>`}
                        </td>
                        <td class="mono">
                          ${b.db_roles.length ? b.db_roles.join(', ') : html`<span class="muted">${t('any')}</span>`}
                        </td>
                        <td>
                          ${b.enabled ? html`<span class="badge ok">${t('enabled')}</span>` : html`<span class="badge deny">${t('disabled')}</span>`}
                          ${inForce(b.issuer)}
                        </td>
                        <td>${b.description}</td>
                        <td class="muted">
                          ${fmtTime(b.updated_at)} · <span class="mono">${b.updated_by}</span>
                        </td>
                        <td class="muted">
                          ${fmtTime(b.created_at)} · <span class="mono">${b.created_by}</span>
                        </td>
                        <td class="actions">
                          <button
                            class="sm"
                            ?disabled=${this.busy}
                            @click=${() => this._edit(b)}
                            data-testid="issuers-edit"
                          >
                            ${t('Edit')}
                          </button>
                          ${
                            this.confirming === b.issuer
                              ? html`<button
                                    class="sm danger"
                                    ?disabled=${this.busy}
                                    @click=${() => this._delete(b.issuer)}
                                    data-testid="issuers-confirm-delete"
                                  >
                                    ${t('Really remove')}
                                  </button>
                                  <button class="sm" @click=${() => (this.confirming = '')}>
                                    ${t('Keep')}
                                  </button>`
                              : html`<button
                                  class="sm danger"
                                  ?disabled=${this.busy}
                                  @click=${() => (this.confirming = b.issuer)}
                                  data-testid="issuers-delete"
                                >
                                  ${t('Remove')}
                                </button>`
                          }
                        </td>
                      </tr>`,
                  )}
                </tbody>
              </table>
            </div>`
          : html`<p class="muted" data-testid="issuers-empty">
              ${t('No bindings yet: every issuer is bound as its environment says.')}
            </p>`
      }
      ${
        this.form
          ? nothing
          : html`<div class="actions">
              <button
                class="sm"
                @click=${() => ((this.saved = ''), (this.form = this._blank()))}
                data-testid="issuers-new"
              >
                ${t('New binding')}
              </button>
            </div>`
      }
    </section>`;
  }

  _audit() {
    const a = this.audit?.rows ?? [];
    return html`<section class="card" data-testid="issuers-audit">
      <h3>
        ${t('History')}
        ${help('Every change to the bindings (authz.issuer_bindings_audit), newest first: the row as it was after the change, or before a removal.')}
      </h3>
      ${this._pager()} ${a.length ? nothing : html`<p class="muted">${t('No changes recorded yet.')}</p>`}
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>${t('When')}</th>
              <th>${t('Who')}</th>
              <th>${t('Change')}</th>
              <th>${t('Issuer')}</th>
              <th>${t('Stores')}</th>
              <th>${t('State')}</th>
            </tr>
          </thead>
          <tbody>
            ${a.map(
              (r) =>
                html`<tr data-testid="issuers-audit-row">
                  <td class="muted">${fmtTime(r.performed_at)}</td>
                  <td class="mono">${r.performed_by}</td>
                  <td>
                    <span
                      class="badge ${r.action === 'DELETE' ? 'deny' : r.action === 'INSERT' ? 'ok' : 'accent'}"
                      >${r.action}</span
                    >
                  </td>
                  <td class="mono">${r.issuer}</td>
                  <td class="mono">${r.stores?.join(', ')}</td>
                  <td>${r.enabled === false ? t('disabled') : r.enabled === true ? t('enabled') : ''}</td>
                </tr>`,
            )}
          </tbody>
        </table>
      </div>
    </section>`;
  }

  render() {
    if (!this.d) return html`${this.error ? errorBox(this.error) : loading()}`;
    return html`
      ${this.error ? errorBox(this.error) : nothing}
      <div class="toolbar">
        <button class="sm" ?disabled=${this.busy} data-testid="issuers-refresh" @click=${() => this._load()}>
          ↻ ${t('Refresh')}
        </button>
      </div>
      <p class="help">
        ${t("Which identity providers the instances trust is their configuration (JWT_ISSUERS: issuer, audience, keys). What a trusted issuer's tokens may do here — the stores they reach, the DB roles they may claim, which clients may assert subjects, whether they are accepted at all — is decided here, for every instance running ISSUERS_SOURCE=env+db, without a restart. A row can narrow an issuer's reach, never widen it or add trust.")}
      </p>
      ${this._effective()} ${this._bindings()} ${this.form ? this._form() : nothing} ${this._audit()}
    `;
  }
}
customElements.define('pgc-issuers', PgcIssuers);
