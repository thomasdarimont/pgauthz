import { html, nothing } from 'lit';
import { PgcElement, help, errorBox } from '../base.js';
import { api } from '../api.js';
import { t } from '../i18n.js';
import { run, forbiddenText, fmtTime } from '../util.js';

// Admin: the store's lifecycle — retiring it (soft delete: the live data
// goes, the audit history and the name stay) and deleting it for good.
// Owners and platform admins only (can_manage_access); every action asks
// for the store's name.
export class PgcAdmin extends PgcElement {
  static properties = {
    store: { type: String },
    caps: { attribute: false },
    retiredAt: { attribute: false }, // set when the store is already retired
    busy: { state: true },
    error: { state: true },
    deleting: { state: true },
    retiring: { state: true },
    confirmName: { state: true },
    purgeAudit: { state: true },
  };

  constructor() {
    super();
    this.busy = false;
    this.error = '';
    this.retiredAt = null;
    this.deleting = false; // the delete confirmation is open
    this.retiring = false; // the retire confirmation is open
    this.confirmName = '';
    this.purgeAudit = false;
  }

  _open(which) {
    this.deleting = which === 'delete';
    this.retiring = which === 'retire';
    this.confirmName = '';
  }

  async _deleteStore(e) {
    e.preventDefault();
    const ok = await run(this, async () => {
      try {
        return await api.deleteStore(this.store, this.confirmName.trim(), this.purgeAudit);
      } catch (err) {
        throw new Error(forbiddenText(err));
      }
    });
    if (ok) this.dispatchEvent(new CustomEvent('navigate', { detail: '', bubbles: true, composed: true }));
  }

  async _retireStore(e) {
    e.preventDefault();
    const ok = await run(this, async () => {
      try {
        return await api.retireStore(this.store, this.confirmName.trim());
      } catch (err) {
        throw new Error(forbiddenText(err));
      }
    });
    if (ok) {
      this._open(null);
      this.dispatchEvent(new CustomEvent('changed'));
    }
  }

  // The typed-name confirmation every lifecycle action goes through.
  _confirm(testid) {
    return html`<p class="wide">
        ${t('Type the store name to confirm:')} <span class="mono">${this.store}</span>
      </p>
      <label class="field"
        ><span>${t('Store name')}</span
        ><input
          class="mono"
          required
          autocomplete="off"
          data-testid=${testid}
          .value=${this.confirmName}
          @input=${(e) => (this.confirmName = e.target.value)}
      /></label>`;
  }

  _retireSection() {
    if (this.retiredAt)
      return html`<section class="card" data-testid="admin-retired">
        <h3>${t('Retired')}</h3>
        <p class="help">
          ${t('Retired on {when}. Live checks and writes are refused; the model dictionary and the audit history are kept, so point-in-time questions still have answers, and the name stays reserved. Deleting the store below purges it.', { when: fmtTime(this.retiredAt) })}
        </p>
      </section>`;
    return html`<section class="card" data-testid="admin-retire">
      <h3>
        ${t('Retire store')}
        ${help('The audit-safe way to decommission a store: the live tuples go and every live API refuses the store from then on, but its model dictionary and full audit history stay queryable (point-in-time checks, the Activity tab) and the name stays reserved. Console roles on the store stay so its owners can purge it later. Prefer this over deleting for regulated stores.')}
      </h3>
      ${
        this.retiring
          ? html`<form class="form" data-testid="admin-retire-form" @submit=${this._retireStore}>
              ${this._confirm('admin-retire-confirm')}
              <div class="actions wide">
                <button
                  class="danger"
                  data-testid="admin-retire-submit"
                  ?disabled=${this.busy || this.confirmName.trim() !== this.store}
                >
                  ${t('Retire store')}
                </button>
                <button type="button" @click=${() => this._open(null)}>${t('Cancel')}</button>
              </div>
            </form>`
          : html`<div class="actions">
              <button class="danger" data-testid="admin-retire-button" @click=${() => this._open('retire')}>
                ${t('Retire store…')}
              </button>
              <span class="help"
                >${t('Stops the store from serving decisions and drops its live data; keeps the history. The console asks you to type its name first.')}</span
              >
            </div>`
      }
    </section>`;
  }

  render() {
    return html`
      ${this.error ? errorBox(this.error) : nothing} ${this._retireSection()}
      <section class="card danger-zone" data-testid="admin-delete">
        <h3>
          ${t('Danger zone')}
          ${help('Deleting a store removes its model, tuples, events and the console roles on it. The audit history stays queryable unless you purge it too. This cannot be undone.')}
        </h3>
        ${
          this.deleting
            ? html`<form class="form" data-testid="admin-delete-form" @submit=${this._deleteStore}>
                ${this._confirm('admin-delete-confirm')}
                <label class="check wide"
                  ><input
                    type="checkbox"
                    data-testid="admin-delete-purge-audit"
                    .checked=${this.purgeAudit}
                    @change=${(e) => (this.purgeAudit = e.target.checked)}
                  />
                  ${t('also purge the audit history (otherwise it stays queryable)')}</label
                >
                <div class="actions wide">
                  <button
                    class="danger"
                    data-testid="admin-delete-submit"
                    ?disabled=${this.busy || this.confirmName.trim() !== this.store}
                  >
                    ${t('Delete store permanently')}
                  </button>
                  <button type="button" @click=${() => this._open(null)}>${t('Cancel')}</button>
                </div>
              </form>`
            : html`<div class="actions">
                <button class="danger" data-testid="admin-delete-button" @click=${() => this._open('delete')}>
                  ${t('Delete store…')}
                </button>
                <span class="help"
                  >${
                    this.retiredAt
                      ? t(
                          'Purges the retired store: its dictionary, its console roles and — if you choose — its audit history.',
                        )
                      : t(
                          'Removes the store and everything in it. The console asks you to type its name first.',
                        )
                  }</span
                >
              </div>`
        }
      </section>
    `;
  }
}
customElements.define('pgc-admin', PgcAdmin);
