import { html, nothing } from 'lit';
import { PgcElement, help, errorBox } from '../base.js';
import { api } from '../api.js';
import { t } from '../i18n.js';
import { run, copyText } from '../util.js';
import { highlightRego } from '../highlight.js';

// Policies: which Rego applies to this store when OPA fronts the deployment
// (ADR 0008 opt-in) — the global veto hooks, this store's hooks, the shared
// libraries and the platform policy — read from the OPA sidecar, read-only.
// Policies are authored in git and shipped as validated bundles; this tab
// shows what is live and where it came from.
export class PgcPolicies extends PgcElement {
  static properties = {
    store: { type: String },
    caps: { attribute: false },
    d: { state: true },
    busy: { state: true },
    error: { state: true },
    open: { state: true }, // policy ids whose source is expanded
  };

  constructor() {
    super();
    this.d = null;
    this.busy = false;
    this.error = '';
    this.open = new Set();
  }

  willUpdate(changed) {
    if (changed.has('store') && this.store) void this._load();
  }

  async _load() {
    const d = await run(this, () => api.policies(this.store));
    if (d) this.d = d;
  }

  _toggle(id) {
    const next = new Set(this.open);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    this.open = next;
  }

  _list(title, helpText, items, emptyText) {
    return html`<section class="card">
      <h3>${t(title)} ${help(helpText)} <span class="muted">${items.length}</span></h3>
      ${
        items.length
          ? html`<div class="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>${t('Name')}</th>
                    <th>${t('Package')}</th>
                    <th>${t('File')}</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  ${items.map(
                    (p) =>
                      html`<tr>
                          <td class="mono">${p.name}</td>
                          <td class="mono muted">${p.package}</td>
                          <td class="mono muted">${p.id}</td>
                          <td class="actions">
                            <button class="sm" @click=${() => this._toggle(p.id)}>
                              ${this.open.has(p.id) ? t('Hide') : t('Source')}
                            </button>
                          </td>
                        </tr>
                        ${
                          this.open.has(p.id)
                            ? html`<tr class="detail-row">
                                <td colspan="4">
                                  <div class="src">
                                    <div class="detail-head">
                                      <span>Rego</span>
                                      <button class="sm" @click=${() => copyText(p.raw)}>${t('Copy')}</button>
                                    </div>
                                    <pre class="code">${highlightRego(p.raw)}</pre>
                                  </div>
                                </td>
                              </tr>`
                            : nothing
                        }`,
                  )}
                </tbody>
              </table>
            </div>`
          : html`<p class="help">${t(emptyText)}</p>`
      }
    </section>`;
  }

  render() {
    const d = this.d;
    if (!d) return html`${this.error ? errorBox(this.error) : html`<p class="muted">${t('Loading…')}</p>`}`;
    if (!d.configured)
      return html`<section class="card">
        <h3>${t('OPA policies')}</h3>
        <p class="help">
          ${t('This deployment answers from the engine directly — no OPA sidecar is configured for the console (CONSOLE_OPA_URL). With OPA fronting pgauthzd, this tab lists the Rego hooks that apply to this store.')}
        </p>
      </section>`;
    const prov = d.opa ?? {};
    const bundles = prov.bundles ? Object.entries(prov.bundles) : [];
    return html`
      ${this.error ? errorBox(this.error) : nothing} ${d.error ? errorBox(d.error) : nothing}
      <section class="card">
        <h3>
          ${t('OPA')}
          ${help("The policy sidecar fronting pgauthzd and what it runs: its version and, when policies arrive as bundles, each bundle's revision. In the dev stack policies are loaded from a directory, so no bundle is listed.")}
        </h3>
        <dl class="kv">
          <dt>${t('Version')}</dt>
          <dd class="mono">
            ${prov.version ?? '—'}${prov.build_commit ? html` <span class="muted">(${String(prov.build_commit).slice(0, 12)})</span>` : nothing}
          </dd>
          <dt>${t('Bundles')}</dt>
          <dd>
            ${
              bundles.length
                ? bundles.map(
                    ([n, b]) =>
                      html`<span class="mono">${n}</span>
                        <span class="badge accent">${b.revision || t('no revision')}</span> `,
                  )
                : html`<span class="muted">${t('none — policies loaded from the policy directory')}</span>`
            }
          </dd>
          <dt>${t('Hook contract')}</dt>
          <dd class="mono">authz.hooks.${d.contract}</dd>
          <dt>${t('Changing policies')}</dt>
          <dd class="muted">
            ${t('Policies are authored in git, validated (scripts/validate-hooks.sh, opa test) and shipped as bundles; the console shows what is live.')}
          </dd>
        </dl>
      </section>
      ${this._list('Hooks for this store', 'Veto rules under authz.hooks.v1.stores.<store>: consulted only for requests bound to this store, after the engine allowed. A hook can narrow, never widen.', d.store, 'No store-specific hooks.')}
      ${this._list('Global hooks', 'Veto rules under authz.hooks.v1.global: consulted for every store (operator tier).', d.global, 'No global hooks.')}
      ${this._list('Shared libraries', 'Helper packages hooks may import (authz.hooks_lib*).', d.libs, 'No shared libraries.')}
      ${this._list('Platform policy', "The policy pgauthzd and OPA run for every request: token validation, roles, the write gate, the hook dispatcher, OPA's own API authorization.", d.platform, 'No platform policy loaded.')}
    `;
  }
}
customElements.define('pgc-policies', PgcPolicies);
