import { html, nothing } from 'lit';
import { PgcElement, help, errorBox, loading } from '../base.js';
import { api } from '../api.js';
import { t } from '../i18n.js';
import { run } from '../util.js';
import './pgc-access.js';
import './pgc-fleet-ops.js';
import './pgc-issuers.js';
import './pgc-groups.js';

// Platform: who administers the console (Admins), how it is wired
// (Configuration: issuer, team-claim mapping, engine and pgauthzd health),
// the fleet's Operations, and the trusted issuers' bindings (Issuers).
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
    /** @type {import('../types.js').PlatformInfo|null} */
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
    if (!d) return html`${this.error ? errorBox(this.error) : loading()}`;
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
        <a href="platform/access" class=${!['settings', 'ops', 'issuers', 'groups'].includes(this.tab) ? 'active' : ''}
          >${t('Admins')}</a
        >
        <a href="platform/settings" class=${this.tab === 'settings' ? 'active' : ''}>${t('Configuration')}</a>
        <a href="platform/ops" class=${this.tab === 'ops' ? 'active' : ''} data-testid="platform-tab-ops"
          >${t('Operations')}</a
        >
        ${
          this.me?.platform?.can_manage_access || this.me?.groups?.any
            ? html`<a href="platform/groups" class=${this.tab === 'groups' ? 'active' : ''} data-testid="platform-tab-groups"
                >${t('Groups')}</a
              >`
            : nothing
        }
        ${
          this.me?.platform?.can_manage_issuers
            ? html`<a
                href="platform/issuers"
                class=${this.tab === 'issuers' ? 'active' : ''}
                data-testid="platform-tab-issuers"
                >${t('Issuers')}</a
              >`
            : nothing
        }
      </nav>
      ${
        this.tab === 'settings'
          ? this._settings()
          : this.tab === 'ops'
            ? html`<pgc-fleet-ops .me=${this.me}></pgc-fleet-ops>`
            : this.tab === 'issuers'
              ? html`<pgc-issuers .me=${this.me}></pgc-issuers>`
              : this.tab === 'groups'
                ? html`<pgc-groups .me=${this.me}></pgc-groups>`
              : html`<pgc-access scope="platform" .me=${this.me}></pgc-access>`
      }
    `;
  }
}
customElements.define('pgc-platform', PgcPlatform);
