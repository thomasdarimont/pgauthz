import { html, nothing } from 'lit';
import { PgcElement, help, errorBox } from '../base.js';
import { api } from '../api.js';
import { t } from '../i18n.js';
import { run } from '../util.js';
import './pgc-access.js';

// Platform: who administers the console (Admins), and how it is wired
// (Configuration: issuer, team-claim mapping, engine and pgauthzd health).
export class PgcPlatform extends PgcElement {
  static properties = {
    me: { attribute: false },
    tab: { type: String },
    d: { state: true },
    busy: { state: true },
    error: { state: true },
  };

  constructor() {
    super();
    this.tab = 'access';
    this.d = null;
    this.busy = false;
    this.error = '';
  }

  willUpdate(changed) {
    if (changed.has('tab') && this.tab === 'settings' && !this.d)
      run(this, () => api.platform()).then((d) => d && (this.d = d));
  }

  _settings() {
    const d = this.d;
    if (!d) return html`${this.error ? errorBox(this.error) : html`<p class="muted">${t('Loading…')}</p>`}`;
    return html`
      <section class="card">
        <h3>${t('Health')}</h3>
        <dl class="kv">
          <dt>${t('Engine')}</dt>
          <dd>
            ${d.engine.ok ? html`<span class="badge ok">${t('connected')}</span> ${t('as')} <span class="mono">${d.engine.role}</span> · ${d.engine.stores} ${t('stores')} · <span class="muted">${d.engine.version?.split(' on ')[0]}</span>` : html`<span class="badge deny">${t('unreachable')}</span> ${d.engine.error}`}
          </dd>
          ${
            d.pgauthzd
              ? html`<dt>pgauthzd</dt>
                  <dd>
                    ${d.pgauthzd.ok ? html`<span class="badge ok">${t('ready')}</span>` : html`<span class="badge deny">${t('not ready')}</span>`}
                    <span class="mono muted">${d.pgauthzd.url}</span>
                  </dd>`
              : nothing
          }
          <dt>${t('Environment')}</dt>
          <dd class="mono">${d.environment}</dd>
        </dl>
      </section>
      <section class="card">
        <h3>
          ${t('Identity')}
          ${help('How people are recognized: the OIDC issuer, the client, and which token claims become team memberships for authorization.')}
        </h3>
        <dl class="kv">
          <dt>${t('Issuer')}</dt>
          <dd class="mono">${d.issuer}</dd>
          <dt>${t('Client')}</dt>
          <dd class="mono">${d.client_id}</dd>
          <dt>${t('Subject')}</dt>
          <dd><span class="mono">${d.subject_type}:&lt;preferred_username&gt;</span></dd>
          <dt>${t('Teams from claims')}</dt>
          <dd>
            ${d.team_claims.map((c) => html`<div><span class="mono">${c.claim}</span> → <span class="mono">team:${c.prefix}_&lt;value&gt;</span></div>`)}
            <div class="help">
              ${t('Injected as contextual membership tuples on every console check; nothing is written.')}
            </div>
          </dd>
          <dt>${t('Your teams')}</dt>
          <dd class="mono">${this.me?.teams?.join(', ') || html`<span class="muted">${t('none')}</span>`}</dd>
        </dl>
      </section>
      <section class="card">
        <h3>
          ${t('Authorization store')}
          ${help('The pgauthz store that decides access to the console itself. Its owners can change how the console authorizes.')}
        </h3>
        <dl class="kv">
          <dt>${t('Store')}</dt>
          <dd><a class="mono" href="stores/${d.console_store}/model">${d.console_store}</a></dd>
          <dt>${t('Platform')}</dt>
          <dd class="mono">platform:${d.platform_id}</dd>
          <dt>${t('Registry')}</dt>
          <dd class="mono">registry:${d.registry_id}</dd>
        </dl>
      </section>
    `;
  }

  render() {
    return html`
      <div class="page-head">
        <div>
          <h1>${t('Platform')}</h1>
          <div class="sub">${t('Console administration.')}</div>
        </div>
      </div>
      <nav class="tabs">
        <a href="platform/access" class=${this.tab !== 'settings' ? 'active' : ''}>${t('Admins')}</a>
        <a href="platform/settings" class=${this.tab === 'settings' ? 'active' : ''}>${t('Configuration')}</a>
      </nav>
      ${this.tab === 'settings' ? this._settings() : html`<pgc-access scope="platform" .me=${this.me}></pgc-access>`}
    `;
  }
}
customElements.define('pgc-platform', PgcPlatform);
