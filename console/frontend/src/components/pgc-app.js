import { html, nothing } from 'lit';
import { PgcElement, errorBox, loading } from '../base.js';
import { api } from '../api.js';
import { t, initI18n } from '../i18n.js';
import { forbiddenText } from '../util.js';
import './pgc-stores.js';
import './pgc-store.js';
import './pgc-registry.js';
import './pgc-platform.js';
import './pgc-settings.js';

// The shell: top bar with the three areas, language switch, login gate, and
// a tiny path router under <base href>. Routes: "" (stores),
// "stores/<name>/<tab>[/<sub>]", "registry[/<store> | /model/<name>]", "platform/<tab>", "settings". Links are plain <a href>
// relative to the base; clicks become pushState so the BFF's SPA fallback
// serves index.html on reload.
export class PgcApp extends PgcElement {
  static properties = {
    me: { state: true },
    path: { state: true },
    error: { state: true },
    version: { state: true },
  };

  constructor() {
    super();
    /** @type {import('../types.js').Me|null|undefined} */
    this.me = undefined; // undefined = loading, null = logged out
    this.login = { oidc: true, local: false }; // sign-ins this deployment offers (from api/me)
    this.localUser = '';
    this.localPassword = '';
    this.path = this._currentPath();
    this.error = '';
    this.version = null;
    this._onPop = () => (this.path = this._currentPath());
    this._onClick = (e) => this._intercept(e);
  }

  connectedCallback() {
    super.connectedCallback();
    window.addEventListener('popstate', this._onPop);
    this.addEventListener('click', this._onClick);
    void initI18n(); // dictionaries + operator overrides; re-renders everything once loaded
    void this._load();
    api
      .version()
      .then((v) => (this.version = v))
      .catch(() => {});
  }
  disconnectedCallback() {
    window.removeEventListener('popstate', this._onPop);
    this.removeEventListener('click', this._onClick);
    super.disconnectedCallback();
  }

  get base() {
    return new URL(document.baseURI).pathname; // "/console/"
  }
  _currentPath() {
    const p = location.pathname;
    return p.startsWith(this.base) ? p.slice(this.base.length) : '';
  }
  _intercept(e) {
    const a = e.composedPath().find((n) => n.tagName === 'A');
    if (!a || a.target || a.hasAttribute('download') || e.metaKey || e.ctrlKey || e.button !== 0) return;
    const href = a.getAttribute('href');
    if (!href || href.startsWith('http') || href.startsWith('auth/') || href.startsWith('#')) return;
    e.preventDefault();
    this.navigate(href);
  }
  navigate(rel) {
    // a new sub-path of the same page (a Test-tab mode, a Model section,
    // the scenarios' view) keeps the scroll position; another page starts at the top
    const samePage = rel.split('/').slice(0, 3).join('/') === this.path.split('/').slice(0, 3).join('/');
    history.pushState(null, '', this.base + rel);
    this.path = rel;
    if (!samePage) window.scrollTo(0, 0);
  }

  // The local admin sign-in: POST the credentials, then reload who we are.
  _localLogin = async (e) => {
    e.preventDefault();
    this.error = '';
    try {
      await api.localLogin(this.localUser, this.localPassword);
      this.localPassword = '';
      this.me = undefined;
      await this._load();
    } catch (err) {
      this.error = err.status === 401 ? t('Wrong username or password.') : forbiddenText(err);
    }
  };

  async _load() {
    try {
      this.me = await api.me();
      if (this.me && this.me.authenticated === false) {
        if (this.me.login) this.login = this.me.login;
        this.me = null;
      }
    } catch (e) {
      this.me = null;
      this.error = forbiddenText(e);
    }
  }

  _area() {
    if (this.path.startsWith('registry')) return 'registry';
    if (this.path.startsWith('platform')) return 'platform';
    if (this.path.startsWith('settings')) return 'settings';
    return 'stores';
  }

  _page() {
    const parts = this.path.split('/').filter(Boolean);
    if (parts[0] === 'registry')
      return html`<pgc-registry
        .me=${this.me}
        store=${parts[1] === 'model' ? '' : (parts[1] ?? '')}
        model=${parts[1] === 'model' ? (parts[2] ?? '') : ''}
      ></pgc-registry>`;
    if (parts[0] === 'settings') return html`<pgc-settings .me=${this.me}></pgc-settings>`;
    if (parts[0] === 'platform')
      return html`<pgc-platform .me=${this.me} tab=${parts[1] ?? 'access'}></pgc-platform>`;
    if (parts[0] === 'stores' && parts[1])
      return html`<pgc-store
        .me=${this.me}
        store=${parts[1]}
        tab=${parts[2] ?? 'model'}
        sub=${parts.slice(3).join('/')}
        @navigate=${(e) => this.navigate(e.detail)}
      ></pgc-store>`;
    return html`<pgc-stores .me=${this.me} @navigate=${(e) => this.navigate(e.detail)}></pgc-stores>`;
  }

  render() {
    const me = this.me;
    const area = this._area();
    return html`
      <header class="topbar">
        <div class="inner">
          <a class="brand" href=""><span class="dot"></span>pgauthz <small>${t('console')}</small></a>
          ${
            me
              ? html`<nav class="areas">
                  <a href="" class=${area === 'stores' ? 'active' : ''}>${t('Stores')}</a>
                  ${me.registry?.can_view ? html`<a href="registry" class=${area === 'registry' ? 'active' : ''}>${t('Registry')}</a>` : nothing}
                  ${
                    me.platform?.can_view_health ||
                    me.platform?.can_manage_access ||
                    me.platform?.can_manage_issuers
                      ? html`<a href="platform" class=${area === 'platform' ? 'active' : ''}
                          >${t('Platform')}</a
                        >`
                      : nothing
                  }
                </nav>`
              : html`<nav class="areas"></nav>`
          }
          <div class="who">
            ${
              me
                ? html`<span
                      class="name"
                      title=${[
                        me.subject,
                        me.email,
                        me.teams?.length
                          ? t('teams: {teams}', { teams: me.teams.join(', ') })
                          : t('no team memberships'),
                      ]
                        .filter(Boolean)
                        .join('\n')}
                    >
                      <b>${me.name || me.username}</b></span
                    >
                    <a
                      class="settings ${area === 'settings' ? 'active' : ''}"
                      href="settings"
                      title=${t('Settings')}
                      aria-label=${t('Settings')}
                      >⚙</a
                    >
                    <button class="sm" @click=${api.logout}>${t('Sign out')}</button>`
                : me === null && this.login.oidc
                  ? html`<button class="sm primary" @click=${() => api.login()}>${t('Sign in')}</button>`
                  : nothing
            }
          </div>
        </div>
      </header>
      ${
        me === undefined
          ? html`<main>${loading(3)}</main>`
          : me === null
            ? html`<main class="login">
                <section class="login-card card">
                  <div class="login-brand">
                    <span class="dot"></span><span>pgauthz <small>${t('console')}</small></span>
                  </div>
                  <h1>${t('Sign in')}</h1>
                  <p class="muted">
                    ${t('Design, test, share and roll out authorization models — with your access decided by pgauthz itself.')}
                  </p>
                  ${this.error ? errorBox(this.error) : nothing}
                  ${
                    this.login.oidc
                      ? html`<button class="primary wide" @click=${() => api.login()}>
                          ${t('Sign in with Keycloak')}
                        </button>`
                      : nothing
                  }
                  ${this.login.oidc && this.login.local ? html`<div class="login-or"><span>${t('or')}</span></div>` : nothing}
                  ${
                    this.login.local
                      ? html`<form class="local-login" @submit=${this._localLogin}>
                          <label
                            >${t('Username')}
                            <input
                              name="username"
                              autocomplete="username"
                              autofocus
                              required
                              .value=${this.localUser}
                              @input=${(e) => (this.localUser = e.target.value)}
                          /></label>
                          <label
                            >${t('Password')}
                            <input
                              name="password"
                              type="password"
                              autocomplete="current-password"
                              required
                              .value=${this.localPassword}
                              @input=${(e) => (this.localPassword = e.target.value)}
                          /></label>
                          <button class="primary wide" type="submit">${t('Sign in')}</button>
                          <p class="login-hint muted">
                            ${t('Local admin account — a development sign-in without an identity provider.')}
                          </p>
                        </form>`
                      : nothing
                  }
                </section>
              </main>`
            : html`<main>${this._page()}</main>`
      }
      <footer class="footer">
        <span>pgauthz ${t('console')}</span>
        ${
          this.version
            ? html`<span
                class="mono"
                title=${this.version.built_at ? t('built {when}', { when: this.version.built_at }) : ''}
              >
                ${this.version.version}${this.version.revision ? ` (${this.version.revision})` : ''}
              </span>`
            : nothing
        }
        <a href="https://github.com/thomasdarimont/pgauthz" target="_blank" rel="noopener">pgauthz</a>
      </footer>
    `;
  }
}
customElements.define('pgc-app', PgcApp);
