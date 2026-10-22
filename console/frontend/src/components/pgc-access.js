import { html, nothing } from 'lit';
import { PgcElement, help, errorBox } from '../base.js';
import { api } from '../api.js';
import { t } from '../i18n.js';
import { run, roleHelp, forbiddenText } from '../util.js';
import { selectionCell, selectAllCell, removeBar, clearSelection } from './pgc-select.js';

// Access: who may do what with this store IN THE CONSOLE — plain tuples of
// the console store (user:alice owner store:demo, team:role_x#member tester
// store:demo). Also used for the platform's admins (scope="platform").
export class PgcAccess extends PgcElement {
  static properties = {
    store: { type: String },
    scope: { type: String }, // store | platform
    caps: { attribute: false },
    me: { attribute: false },
    d: { state: true },
    busy: { state: true },
    error: { state: true },
    form: { state: true },
    selected: { state: true },
    confirming: { state: true },
    ns: { state: true }, // namespaces of the store with their role assignments
    nsForm: { state: true },
  };

  constructor() {
    super();
    this.scope = 'store';
    this.d = null;
    this.busy = false;
    this.error = '';
    this.form = { subject_type: 'user', role: '' };
    this.selected = new Set();
    this.confirming = false;
    this.ns = null;
    this.nsForm = { subject_type: 'user', role: 'author' };
  }

  willUpdate(changed) {
    if ((changed.has('store') || changed.has('scope')) && (this.store || this.scope === 'platform'))
      void this._load();
  }

  _api() {
    const s = this.store;
    return this.scope === 'platform'
      ? {
          list: () => api.platformAccess(),
          add: (a) => api.platformAccessAdd(a),
          remove: (items) => api.platformAccessRemove(items),
        }
      : {
          list: () => api.access(s),
          add: (a) => api.accessAdd(s, a),
          remove: (items) => api.accessRemove(s, items),
        };
  }

  _key(a) {
    return `${a.subject} ${t('as')} ${a.role}`;
  }

  async _load() {
    void this._loadNamespaces();
    const d = await run(this, () => this._api().list());
    if (d) {
      this.d = d;
      clearSelection(this);
      if (!this.form.role) this.form = { ...this.form, role: d.roles[0] };
    }
  }

  _set(k) {
    return (e) => (this.form = { ...this.form, [k]: e.target.value });
  }

  _wrap(fn) {
    return run(this, async () => {
      try {
        return await fn();
      } catch (e) {
        throw new Error(forbiddenText(e));
      }
    });
  }

  async _add(e) {
    e.preventDefault();
    const a = {
      subject_type: this.form.subject_type,
      subject_id: this.form.subject_id?.trim(),
      subject_relation: this.form.subject_type === 'team' ? 'member' : '',
      role: this.form.role,
    };
    const ok = await this._wrap(() => this._api().add(a));
    if (ok) {
      this.form = { ...this.form, subject_id: '' };
      await this._load();
      this.dispatchEvent(new CustomEvent('changed'));
    }
  }

  async _removeSelected() {
    const items = this.d.access
      .filter((a) => this.selected.has(this._key(a)))
      .map((a) => ({
        subject_type: a.subject_type,
        subject_id: a.subject_id,
        subject_relation: a.subject_relation,
        role: a.role,
      }));
    const ok = await this._wrap(() => this._api().remove(items));
    if (ok) {
      await this._load();
      this.dispatchEvent(new CustomEvent('changed'));
    }
  }

  // Select one row and open the confirmation — the same path as "Remove
  // selected…", so a revoke is never a single click.
  _revokeOne(a) {
    this.selected = new Set([this._key(a)]);
    this.confirming = true;
  }

  async _loadNamespaces() {
    if (this.scope === 'platform') return;
    try {
      this.ns = await api.namespaces(this.store);
    } catch {
      this.ns = null;
    }
  }

  _nsSet(k) {
    return (e) => (this.nsForm = { ...this.nsForm, [k]: e.target.value });
  }

  _nsAdd = async (e) => {
    e.preventDefault();
    const f = this.nsForm;
    const ok = await this._wrap(() =>
      api.namespaceAccessAdd(this.store, f.namespace, {
        subject_type: f.subject_type,
        subject_id: f.subject_id?.trim(),
        subject_relation: f.subject_type === 'team' ? 'member' : '',
        role: f.role,
      }),
    );
    if (ok) {
      this.nsForm = { ...this.nsForm, subject_id: '' };
      await this._loadNamespaces();
      this.dispatchEvent(new CustomEvent('changed'));
    }
  };

  async _nsRemove(ns, a) {
    const ok = await this._wrap(() =>
      api.namespaceAccessRemove(this.store, ns, [
        {
          subject_type: a.subject_type,
          subject_id: a.subject_id,
          subject_relation: a.subject_relation,
          role: a.role,
        },
      ]),
    );
    if (ok) {
      await this._loadNamespaces();
      this.dispatchEvent(new CustomEvent('changed'));
    }
  }

  // Namespace roles: an application team's slice of a shared store. author
  // edits the model and data of the types in that namespace, viewer reads;
  // both open the store. Store-wide changes still need a store role.
  _namespacesCard() {
    const n = this.ns;
    if (!n || !n.namespaces?.length) return nothing;
    const can = n.can_manage;
    return html`<section class="card">
      <h3>
        ${t('Namespaces')}
        ${help("An application team's slice of this store: types carry a namespace, and a namespace author may change the model and data of those types only (store-wide changes still need a store role). Viewers read. Both roles open the store.")}
      </h3>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>${t('Namespace')}</th>
              <th>${t('Subject')}</th>
              <th>${t('Role')}</th>
              ${can ? html`<th></th>` : nothing}
            </tr>
          </thead>
          <tbody>
            ${n.namespaces.map((x) =>
              x.access.length
                ? x.access.map(
                    (a) =>
                      html`<tr>
                        <td class="mono">${x.name}</td>
                        <td class="mono">${a.subject}</td>
                        <td><span class="badge accent">${a.role}</span></td>
                        ${
                          can
                            ? html`<td class="actions">
                                <button
                                  class="sm danger"
                                  ?disabled=${this.busy}
                                  @click=${() => this._nsRemove(x.name, a)}
                                >
                                  ${t('Revoke')}
                                </button>
                              </td>`
                            : nothing
                        }
                      </tr>`,
                  )
                : html`<tr>
                    <td class="mono">${x.name}</td>
                    <td class="muted" colspan=${can ? 3 : 2}>${t('nobody has a namespace role here')}</td>
                  </tr>`,
            )}
          </tbody>
        </table>
      </div>
      ${
        can
          ? html`<form class="form" @submit=${this._nsAdd}>
              <label class="field"
                ><span>${t('Namespace')}</span
                ><select required .value=${this.nsForm.namespace ?? ''} @change=${this._nsSet('namespace')}>
                  <option value="">${t('— choose —')}</option>
                  ${n.namespaces.map((x) => html`<option value=${x.name}>${x.name}</option>`)}
                </select></label
              >
              <label class="field"
                ><span>${t('Subject')}</span
                ><select .value=${this.nsForm.subject_type} @change=${this._nsSet('subject_type')}>
                  <option value="user">${t('user — a person (preferred_username)')}</option>
                  <option value="team">${t('team — a directory group from the token')}</option>
                </select></label
              >
              <label class="field"
                ><span
                  >${this.nsForm.subject_type === 'team' ? t('Team id') : t('Username')}
                  ${this.nsForm.subject_type === 'team' ? help('A team from the token: role_<realm role>, group_<path> or org_<alias>, e.g. role_authz_writer. Known teams are suggested.') : help('The preferred_username of the person, e.g. bob.')}</span
                ><input
                  class="mono"
                  required
                  list="dl-teams"
                  .value=${this.nsForm.subject_id ?? ''}
                  @input=${this._nsSet('subject_id')}
              /></label>
              <label class="field"
                ><span>${t('Role')}</span
                ><select .value=${this.nsForm.role} @change=${this._nsSet('role')}>
                  ${(n.roles ?? ['author', 'viewer']).map((r) => html`<option value=${r}>${r}</option>`)}
                </select></label
              >
              <div class="actions wide">
                <button class="primary" ?disabled=${this.busy}>${t('Grant')}</button>
              </div>
            </form>`
          : nothing
      }
    </section>`;
  }

  _isMe(a) {
    if (!this.me) return false;
    return a.subject_type === 'team'
      ? this.me.teams?.includes(a.subject_id)
      : a.subject_id === this.me.username;
  }

  render() {
    const d = this.d;
    if (!d) return html`${this.error ? errorBox(this.error) : html`<p class="muted">${t('Loading…')}</p>`}`;
    const platform = this.scope === 'platform';
    const what = platform ? t('the platform') : html`<span class="mono">store:${this.store}</span>`;
    return html`
      ${this.error ? errorBox(this.error) : nothing}
      <section class="card">
        <div class="toolbar">
          <h3>
            ${t('Who has access to')} ${what}
            ${help('Explicit roles in the console store. Team rows apply to everyone whose token carries that realm role, group or organization.')}
          </h3>
          ${d.can_manage ? nothing : html`<span class="help">${platform ? t('changing this needs "manage access" (an admin)') : t('changing this needs "manage access" (an owner or platform admin)')}</span>`}
        </div>
        ${
          d.can_manage
            ? removeBar(this, {
                one: 'role assignment',
                many: 'role assignments',
                describe: (k) => k,
                warning: platform
                  ? 'The last platform admin cannot be removed.'
                  : 'The last owner cannot be removed.',
                onConfirm: () => this._removeSelected(),
              })
            : nothing
        }
        ${
          d.access.length
            ? html`<div class="table-wrap">
                <table>
                  <thead>
                    <tr>
                      ${
                        d.can_manage
                          ? selectAllCell(
                              this,
                              d.access.map((a) => this._key(a)),
                            )
                          : nothing
                      }
                      <th>
                        ${t('Subject')}
                        ${help('A person (user:name) or a team (team:id#member) from the token.')}
                      </th>
                      <th>${t('Role')}</th>
                      <th>${t('Means')}</th>
                      ${d.can_manage ? html`<th></th>` : nothing}
                    </tr>
                  </thead>
                  <tbody>
                    ${d.access.map(
                      (a) =>
                        html`<tr>
                          ${d.can_manage ? selectionCell(this, this._key(a)) : nothing}
                          <td class="mono">
                            ${a.subject}${a.subject_type === 'team' ? html` <span class="badge muted" title=${t("matched from the token's roles, groups or organization")}>${t('team')}</span>` : nothing}
                            ${this._isMe(a) ? html` <span class="badge accent">${t('you')}</span>` : nothing}
                          </td>
                          <td>
                            <span class="badge ${a.role === 'owner' || a.role === 'admin' ? 'accent' : ''}"
                              >${a.role}</span
                            >
                          </td>
                          <td class="muted">${roleHelp(a.role)}</td>
                          ${
                            d.can_manage
                              ? html`<td>
                                  <button
                                    class="sm danger"
                                    title=${t('revoke this role (asks for confirmation)')}
                                    @click=${() => this._revokeOne(a)}
                                  >
                                    ${t('Revoke…')}
                                  </button>
                                </td>`
                              : nothing
                          }
                        </tr>`,
                    )}
                  </tbody>
                </table>
              </div>`
            : html`<div class="empty">${t('Nobody has an explicit role here.')}</div>`
        }
      </section>
      ${
        d.can_manage
          ? html`<form class="card form" @submit=${this._add}>
              <h3 class="wide">${t('Grant a role')}</h3>
              <label class="field"
                ><span>${t('Subject')}</span>
                <select .value=${this.form.subject_type} @change=${this._set('subject_type')}>
                  <option value="user">${t('user — a person (preferred_username)')}</option>
                  <option value="team">${t('team — a directory group from the token')}</option>
                </select></label
              >
              <label class="field"
                ><span
                  >${this.form.subject_type === 'team' ? t('Team id') : t('Username')}
                  ${this.form.subject_type === 'team' ? help('A team from the token: role_<realm role>, group_<path> or org_<alias>, e.g. role_authz_writer. Known teams are suggested.') : help('The preferred_username of the person, e.g. bob.')}</span
                >
                <input
                  class="mono"
                  required
                  list="dl-teams"
                  .value=${this.form.subject_id ?? ''}
                  @input=${this._set('subject_id')}
              /></label>
              <datalist id="dl-teams">
                ${this.form.subject_type === 'team' ? (d.teams ?? []).map((x) => html`<option value=${x}></option>`) : nothing}
              </datalist>
              <label class="field"
                ><span>${t('Role')}</span>
                <select .value=${this.form.role} @change=${this._set('role')}>
                  ${d.roles.map((r) => html`<option value=${r}>${r}</option>`)}
                </select></label
              >
              <div class="actions wide">
                <button class="primary" ?disabled=${this.busy}>${t('Grant')}</button>
                <span class="help"
                  >${roleHelp(this.form.role)}
                  ${platform ? t('The platform always keeps at least one admin.') : t('A store always keeps at least one owner.')}</span
                >
              </div>
            </form>`
          : nothing
      }
      ${this.scope !== 'platform' ? this._namespacesCard() : nothing}
    `;
  }
}
customElements.define('pgc-access', PgcAccess);
