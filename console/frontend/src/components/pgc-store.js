import { html, nothing } from 'lit';
import { PgcElement, help, errorBox } from '../base.js';
import { api } from '../api.js';
import { t, t2 } from '../i18n.js';
import { capLabel, run, forbiddenText, fmtTime } from '../util.js';
import './pgc-model.js';
import './pgc-data.js';
import './pgc-test.js';
import './pgc-rollout.js';
import './pgc-activity.js';
import './pgc-access.js';
import './pgc-admin.js';
import './pgc-ops.js';
import './pgc-policies.js';

// One store: header (description, documentation link, status, sizes, your
// capabilities) and the tab strip. Tabs are gated by the console store's
// answer: a tab you lack the capability for is shown locked, so people see
// what exists and whom to ask. A RETIRED store (soft-deleted: live APIs
// refuse it, the audit history stays) keeps only the tabs that read history
// or manage the store itself.
const TABS = [
  { id: 'model', label: 'Model', cap: 'can_view' },
  { id: 'data', label: 'Data', cap: 'can_view' },
  { id: 'test', label: 'Test', cap: 'can_run_tests' },
  { id: 'rollout', label: 'Rollout', cap: 'can_view' },
  { id: 'activity', label: 'Activity', cap: 'can_view_audit' },
  { id: 'policies', label: 'Policies', cap: 'can_view' },
  { id: 'access', label: 'Access', cap: 'can_view' },
  { id: 'ops', label: 'Operations', cap: 'can_view_audit' },
  { id: 'admin', label: 'Admin', cap: 'can_manage_access' },
];
const RETIRED_TABS = new Set(['activity', 'access', 'admin']);

export class PgcStore extends PgcElement {
  static properties = {
    me: { attribute: false },
    store: { type: String },
    tab: { type: String },
    sub: { type: String }, // the tab's own sub-path (Model: the Structure section)
    info: { state: true },
    busy: { state: true },
    error: { state: true },
    editing: { state: true },
    form: { state: true },
  };

  constructor() {
    super();
    /** @type {import('../types.js').StoreRow|null} */
    this.info = null;
    this.busy = false;
    this.error = '';
    this.editing = false;
    this.form = {};
  }

  willUpdate(changed) {
    if (changed.has('store') && this.store) void this._load();
  }

  async _load() {
    this.info = null;
    try {
      this.info = await api.store(this.store);
      this.error = '';
    } catch (e) {
      this.error = forbiddenText(e);
    }
  }

  _refresh() {
    run(this, () => api.store(this.store)).then((i) => i && (this.info = i));
  }

  async _saveSettings(e) {
    e.preventDefault();
    const ok = await run(this, async () => {
      try {
        return await api.storeSettings(this.store, {
          description: this.form.description ?? '',
          docs_url: this.form.docs_url ?? '',
        });
      } catch (err) {
        throw new Error(forbiddenText(err));
      }
    });
    if (ok) {
      this.editing = false;
      this._refresh();
    }
  }

  _tabBody(caps) {
    const tab = TABS.find((x) => x.id === this.tab) ?? TABS[0];
    if (!caps[tab.cap])
      return html`<div class="empty">
        ${t('This tab needs "{capability}" on {object}. Ask an owner of the store (see Access).', { capability: capLabel(tab.cap), object: 'store:' + this.store })}
      </div>`;
    if (this.info?.retired_at && !RETIRED_TABS.has(tab.id))
      return html`<div class="empty" data-testid="store-retired-tab">
        ${t('This store is retired: it has no live model or data any more. Its history is on the Activity tab; the Admin tab deletes it for good.')}
      </div>`;
    switch (tab.id) {
      case 'data':
        return html`<pgc-data
          .store=${this.store}
          .me=${this.me}
          .caps=${caps}
          .nsCaps=${this.info?.namespaces}
          @changed=${this._refresh}
        ></pgc-data>`;
      case 'test':
        return html`<pgc-test
          .store=${this.store}
          .caps=${caps}
          .me=${this.me}
          sub=${this.sub ?? ''}
        ></pgc-test>`;
      case 'rollout':
        return html`<pgc-rollout .store=${this.store} .caps=${caps} @changed=${this._refresh}></pgc-rollout>`;
      case 'activity':
        return html`<pgc-activity .store=${this.store} .caps=${caps}></pgc-activity>`;
      case 'access':
        return html`<pgc-access
          .store=${this.store}
          .caps=${caps}
          .me=${this.me}
          scope="store"
          @changed=${this._refresh}
        ></pgc-access>`;
      case 'policies':
        return html`<pgc-policies .store=${this.store} .caps=${caps}></pgc-policies>`;
      case 'ops':
        return html`<pgc-ops .store=${this.store} .caps=${caps} .info=${this.info}></pgc-ops>`;
      case 'admin':
        return html`<pgc-admin
          .store=${this.store}
          .caps=${caps}
          .retiredAt=${this.info?.retired_at ?? null}
          @changed=${this._refresh}
        ></pgc-admin>`;
      default:
        return html`<pgc-model
          .store=${this.store}
          section=${this.sub ?? ''}
          .caps=${caps}
          .info=${this.info}
          @changed=${this._refresh}
        ></pgc-model>`;
    }
  }

  _settingsForm(i) {
    return html`<form class="card form" @submit=${this._saveSettings}>
      <label class="field wide"
        ><span
          >${t('Description')}
          ${help('One line about what this store authorizes; shown on the store card.')}</span
        >
        <input
          .value=${this.form.description ?? i.description ?? ''}
          @input=${(e) => (this.form = { ...this.form, description: e.target.value })}
      /></label>
      <label class="field wide"
        ><span
          >${t('Documentation link')}
          ${help('An http(s) link to where this model is described in depth — a wiki page, a design document, a ticket.')}</span
        >
        <input
          type="url"
          .value=${this.form.docs_url ?? i.docs_url ?? ''}
          @input=${(e) => (this.form = { ...this.form, docs_url: e.target.value })}
      /></label>
      <div class="actions wide">
        <button class="primary" ?disabled=${this.busy}>${t('Save')}</button>
        <button type="button" @click=${() => (this.editing = false)}>${t('Cancel')}</button>
      </div>
    </form>`;
  }

  render() {
    const i = this.info;
    const caps = i?.capabilities ?? {};
    return html`
      <div class="crumbs"><a href="">${t('Stores')}</a> / <span class="mono">${this.store}</span></div>
      ${this.error ? errorBox(this.error) : nothing}
      ${
        i
          ? html`
              <div class="page-head">
                <div>
                  <h1 class="mono">${this.store}</h1>
                  <div class="store-head-desc">
                    <span>${i.description || t('no description')}</span>
                    ${i.docs_url ? html`<a href=${i.docs_url} target="_blank" rel="noopener noreferrer nofollow">${t('documentation')} ↗</a>` : nothing}
                    ${
                      caps.can_manage_access && !i.retired_at
                        ? html`<button
                            class="ghost sm"
                            @click=${() => {
                              this.editing = !this.editing;
                              this.form = {};
                            }}
                          >
                            ${t('Edit')}
                          </button>`
                        : nothing
                    }
                  </div>
                </div>
              </div>
              ${
                i.retired_at
                  ? html`<p class="notice" data-testid="store-retired-banner">
                      ${t('Retired on {when}: live checks and writes are refused, the live tuples are gone; the model dictionary and the audit history are kept for point-in-time questions and the name stays reserved. Delete the store on the Admin tab to purge it.', { when: fmtTime(i.retired_at) })}
                    </p>`
                  : nothing
              }
              ${this.editing ? this._settingsForm(i) : nothing}
              <details class="caps-details">
                <summary class="caps yours">
                  <span class="caps-label"
                    >${t('Your access')}:
                    ${t2('{n} capability', '{n} capabilities', Object.values(caps).filter(Boolean).length - (caps.can_view ? 1 : 0))}
                    ${help('What you may do with this store, as decided by the console store from your roles and team memberships. Informational — the tabs below are where you act.')}</span
                  >
                  ${!i.claimed ? html`<span class="badge warn" title=${t('no platform tuple in the console store')}>${t('not under the platform')}</span>` : nothing}
                  ${Object.entries(i.namespaces ?? {})
                    .filter(([, c]) => !caps.can_edit_model && (c.can_edit_model || c.can_grant)) // namespace-only access
                    .map(
                      ([ns, c]) =>
                        html`<span class="badge accent" title=${t('your namespace role in this store')}
                          >${ns}: ${c.can_edit_model ? t('author') : t('viewer')}</span
                        >`,
                    )}
                </summary>
                <div class="caps yours">
                  ${Object.entries(caps)
                    .filter(([k, v]) => v && k !== 'can_view')
                    .map(([k]) => html`<span class="cap">✓ ${capLabel(k)}</span>`)}
                </div>
              </details>
              <nav class="tabs">
                ${TABS.map(
                  (tab) =>
                    html`<a
                      href="stores/${this.store}/${tab.id}"
                      class="${this.tab === tab.id ? 'active' : ''} ${caps[tab.cap] && !(i.retired_at && !RETIRED_TABS.has(tab.id)) ? '' : 'locked'}"
                      title=${!caps[tab.cap] ? t('needs {capability}', { capability: capLabel(tab.cap) }) : i.retired_at && !RETIRED_TABS.has(tab.id) ? t('retired store') : ''}
                      data-testid=${'store-tab-' + tab.id}
                      >${t(tab.label)}</a
                    >`,
                )}
              </nav>
              ${this._tabBody(caps)}
            `
          : this.error
            ? nothing
            : html`<p class="muted">${t('Loading…')}</p>`
      }
    `;
  }
}
customElements.define('pgc-store', PgcStore);
