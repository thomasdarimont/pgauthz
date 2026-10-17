import { html } from 'lit';
import { PgcElement, help } from '../base.js';
import { api } from '../api.js';
import { t } from '../i18n.js';
import { run, forbiddenText } from '../util.js';

// Admin: the store's lifecycle — today, deleting it. Owners and platform
// admins only (can_manage_access); every action asks for the store's name.
export class PgcAdmin extends PgcElement {
  static properties = {
    store: { type: String },
    caps: { attribute: false },
    busy: { state: true },
    error: { state: true },
    deleting: { state: true },
    deleteName: { state: true },
    purgeAudit: { state: true },
  };

  constructor() {
    super();
    this.busy = false;
    this.error = '';
    this.deleting = false; // the confirmation is open
    this.deleteName = '';
    this.purgeAudit = false;
  }

  async _deleteStore(e) {
    e.preventDefault();
    const ok = await run(this, async () => {
      try {
        return await api.deleteStore(this.store, this.deleteName.trim(), this.purgeAudit);
      } catch (err) {
        throw new Error(forbiddenText(err));
      }
    });
    if (ok) this.dispatchEvent(new CustomEvent('navigate', { detail: '', bubbles: true, composed: true }));
  }

  render() {
    return html`
      ${this.error ? html`<p class="error">${this.error}</p>` : ''}
      <section class="card danger-zone">
        <h3>
          ${t('Danger zone')}
          ${help('Deleting a store removes its model, tuples, events and the console roles on it. The audit history stays queryable unless you purge it too. This cannot be undone.')}
        </h3>
        ${
          this.deleting
            ? html`<form class="form" @submit=${this._deleteStore}>
                <p class="wide">
                  ${t('Type the store name to confirm:')} <span class="mono">${this.store}</span>
                </p>
                <label class="field"
                  ><span>${t('Store name')}</span
                  ><input
                    class="mono"
                    required
                    autocomplete="off"
                    .value=${this.deleteName}
                    @input=${(e) => (this.deleteName = e.target.value)}
                /></label>
                <label class="check wide"
                  ><input
                    type="checkbox"
                    .checked=${this.purgeAudit}
                    @change=${(e) => (this.purgeAudit = e.target.checked)}
                  />
                  ${t('also purge the audit history (otherwise it stays queryable)')}</label
                >
                <div class="actions wide">
                  <button class="danger" ?disabled=${this.busy || this.deleteName.trim() !== this.store}>
                    ${t('Delete store permanently')}
                  </button>
                  <button type="button" @click=${() => (this.deleting = false)}>${t('Cancel')}</button>
                </div>
              </form>`
            : html`<div class="actions">
                <button class="danger" @click=${() => ((this.deleting = true), (this.deleteName = ''))}>
                  ${t('Delete store…')}
                </button>
                <span class="help"
                  >${t('Removes the store and everything in it. The console asks you to type its name first.')}</span
                >
              </div>`
        }
      </section>
    `;
  }
}
customElements.define('pgc-admin', PgcAdmin);
