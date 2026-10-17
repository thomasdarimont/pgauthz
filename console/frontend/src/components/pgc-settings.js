import { html } from 'lit';
import { PgcElement, help } from '../base.js';
import { t, LANGUAGES, getLang, setLang } from '../i18n.js';

// Personal settings: what the console remembers for THIS person in THIS
// browser (nothing here touches the engine). Platform-wide configuration
// lives under Platform → Configuration.
export class PgcSettings extends PgcElement {
  static properties = { me: { attribute: false } };

  render() {
    return html`
      <div class="page-head">
        <div>
          <h1>${t('Settings')}</h1>
          <div class="sub">${t('Your preferences for this console, kept in this browser.')}</div>
        </div>
      </div>
      <section class="card">
        <h3>
          ${t('Language')}
          ${help("The language of the console's own texts. Store names, relations and other identifiers stay as they are in the engine.")}
        </h3>
        <div class="lang-choice">
          ${LANGUAGES.map(
            ([code, label]) =>
              html`<label class="check">
                <input
                  type="radio"
                  name="lang"
                  value=${code}
                  .checked=${getLang() === code}
                  @change=${() => setLang(code)}
                />
                ${label}
                <span class="muted mono">${code}</span>
              </label>`,
          )}
        </div>
      </section>
      <section class="card">
        <h3>${t('Account')}</h3>
        <dl class="kv">
          <dt>${t('Signed in as')}</dt>
          <dd><b>${this.me?.name || this.me?.username}</b> <span class="mono">${this.me?.subject}</span></dd>
          <dt>${t('Your teams')}</dt>
          <dd class="mono">${this.me?.teams?.join(', ') || html`<span class="muted">${t('none')}</span>`}</dd>
        </dl>
        <p class="help">
          ${t('Teams come from your sign-in token (realm roles, groups, organization) and decide, together with explicit roles, what you may do.')}
        </p>
      </section>
    `;
  }
}
customElements.define('pgc-settings', PgcSettings);
