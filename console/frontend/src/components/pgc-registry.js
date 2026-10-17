import { html, nothing } from 'lit';
import { PgcElement, help } from '../base.js';
import { api } from '../api.js';
import { t, t2 } from '../i18n.js';
import { run, fmtTime } from '../util.js';

// Registry: every published model with its immutable versions and the fleet
// of stores running it. Rolling a version out happens on a store's Rollout tab.
export class PgcRegistry extends PgcElement {
  static properties = {
    me: { attribute: false },
    d: { state: true },
    busy: { state: true },
    error: { state: true },
  };

  constructor() {
    super();
    this.d = null;
    this.busy = false;
    this.error = '';
  }

  connectedCallback() {
    super.connectedCallback();
    run(this, () => api.registry()).then((d) => d && (this.d = d));
  }

  render() {
    const d = this.d;
    return html`
      <div class="page-head">
        <div>
          <h1>${t('Registry')}</h1>
          <div class="sub">
            ${t('Immutable model versions, and where each one runs.')}
            ${help("Publish from a store's Rollout tab; apply a version there too. The registry itself only lists.")}
          </div>
        </div>
      </div>
      ${this.error ? html`<p class="error">${this.error}</p>` : nothing}
      ${
        d
          ? d.models.length
            ? d.models.map(
                (m) =>
                  html`<section class="card">
                    <div class="toolbar">
                      <h3 class="mono">${m.name}</h3>
                      <span class="muted"
                        >${t2('{n} version', '{n} versions', m.versions.length)} ·
                        ${t2('{n} store', '{n} stores', m.fleet?.length ?? 0)}</span
                      >
                    </div>
                    <div class="table-wrap">
                      <table>
                        <thead>
                          <tr>
                            <th>${t('Version')}</th>
                            <th>${t('Description')}</th>
                            <th>${t('Published')}</th>
                            <th>${t('By')}</th>
                            <th>${t('Checksum')}</th>
                          </tr>
                        </thead>
                        <tbody>
                          ${[...m.versions].reverse().map(
                            (v) =>
                              html`<tr>
                                <td class="mono">@${v.version}</td>
                                <td>${v.description}</td>
                                <td class="muted">${fmtTime(v.created_at)}</td>
                                <td class="mono">${v.created_by}</td>
                                <td class="mono muted">${v.checksum.slice(0, 12)}</td>
                              </tr>`,
                          )}
                        </tbody>
                      </table>
                    </div>
                    ${
                      m.fleet?.length
                        ? html`<h3 style="margin-top:var(--s-4)">${t('Fleet')}</h3>
                            <div class="caps">
                              ${m.fleet.map(
                                (f) =>
                                  html`<a
                                    class="badge mono ${!f.in_sync ? 'warn' : f.model_version < f.latest_version ? 'muted' : 'ok'}"
                                    href="stores/${f.store}/rollout"
                                    title=${!f.in_sync ? t('drifted') : f.model_version < f.latest_version ? t('outdated') : t('current')}
                                    >${f.store} @${f.model_version}</a
                                  >`,
                              )}
                            </div>`
                        : html`<p class="help">${t('No store has applied this model yet.')}</p>`
                    }
                  </section>`,
              )
            : html`<div class="empty">
                ${t("The registry is empty. Publish a store's model from its Rollout tab.")}
              </div>`
          : html`<p class="muted">${t('Loading…')}</p>`
      }
    `;
  }
}
customElements.define('pgc-registry', PgcRegistry);
