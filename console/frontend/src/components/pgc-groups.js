import { html, nothing } from 'lit';
import { repeat } from 'lit/directives/repeat.js';
import { PgcElement, help, errorBox, loading } from '../base.js';
import { api } from '../api.js';
import { t } from '../i18n.js';
import { run, forbiddenText, fmtTime } from '../util.js';

// Platform → Groups (ADR 0017): the store groups — a named set of stores
// that shares administration (trust and models in later phases). A platform
// admin creates groups, moves stores between them (or detaches one, which
// is then its own group of one) and names group admins; a group admin sees
// their groups and manages the admins of each.
export class PgcGroups extends PgcElement {
  static properties = {
    me: { type: Object },
    d: { state: true },
    creating: { state: true },
    form: { state: true },
    open: { state: true }, // the group whose admins are shown
    access: { state: true },
    accessForm: { state: true },
    consumers: { state: true }, // the open group's model consumers
    consumerPick: { state: true },
    editing: { state: true }, // the group whose description is edited
  };

  constructor() {
    super();
    this.d = null;
    this.creating = false;
    this.form = {};
    this.open = '';
    this.access = null;
    this.accessForm = { subject_type: 'user', role: 'admin' };
    this.editing = '';
  }

  connectedCallback() {
    super.connectedCallback();
    void this._load();
  }

  async _load() {
    const d = await run(this, async () => {
      try {
        return await api.platformGroups();
      } catch (e) {
        throw new Error(forbiddenText(e));
      }
    });
    if (d) this.d = d;
    if (this.open) await this._loadAccess(this.open);
  }

  async _loadAccess(group) {
    const a = await run(this, () => api.groupAccess(group));
    if (a) this.access = a;
    const c = await run(this, () => api.groupConsumers(group));
    if (c) this.consumers = c;
  }

  async _grantConsumer(group) {
    if (!this.consumerPick) return;
    const ok = await run(this, () => api.groupConsumerGrant(group, this.consumerPick));
    if (ok) {
      this.consumerPick = '';
      await this._loadAccess(group);
    }
  }

  async _revokeConsumer(group, consumer) {
    const ok = await run(this, () => api.groupConsumerRevoke(group, consumer));
    if (ok) await this._loadAccess(group);
  }

  // Models shared with: the groups that may apply this group's registry
  // models (group:A model_consumer group:B, ADR 0017 phase 3). The default
  // group's models are everyone's; sharing is for the other groups.
  _sharing(group) {
    const c = this.consumers;
    if (!c) return nothing;
    const others = (this.d?.groups ?? []).map((g) => g.name).filter((n) => n !== group && !c.consumers.some((x) => x.group === n));
    return html`<div class="card" data-testid="groups-consumers-${group}">
      <h4>${t('Models shared with')} ${help('The groups whose stores may apply this group\'s registry models. A group always applies its own models and the default group\'s; another group\'s only with this grant, which the plan reports as a blocker otherwise.')}</h4>
      ${
        group === 'default'
          ? html`<p class="help">${t('The default group\'s models are the platform\'s: every store may apply them.')}</p>`
          : html`${
                c.consumers.length
                  ? html`<table class="table compact">
                      <tbody>
                        ${c.consumers.map(
                          (x) => html`<tr>
                            <td class="mono">${x.group}</td>
                            <td class="muted">${t('since {when} by {who}', { when: fmtTime(x.created_at), who: x.created_by })}</td>
                            <td>
                              ${c.can_manage ? html`<button type="button" class="small" @click=${() => this._revokeConsumer(group, x.group)}>${t('Revoke')}</button>` : nothing}
                            </td>
                          </tr>`,
                        )}
                      </tbody>
                    </table>`
                  : html`<p class="help">${t('No other group may apply this group\'s models yet.')}</p>`
              }
              ${
                c.can_manage && others.length
                  ? html`<form class="form inline" @submit=${(e) => { e.preventDefault(); this._grantConsumer(group); }}>
                      <select .value=${this.consumerPick ?? ''} @change=${(e) => (this.consumerPick = e.target.value)} data-testid="groups-consumer-pick">
                        <option value="">${t('— choose a group —')}</option>
                        ${others.map((n) => html`<option value=${n}>${n}</option>`)}
                      </select>
                      <button class="primary" ?disabled=${this.busy || !this.consumerPick} data-testid="groups-consumer-grant">${t('Share models')}</button>
                    </form>`
                  : nothing
              }`
      }
    </div>`;
  }

  _set(k) {
    return (e) => (this.form = { ...this.form, [k]: e.target.value });
  }

  async _create(e) {
    e.preventDefault();
    const ok = await run(this, () => api.groupCreate(this.form.name?.trim(), this.form.description?.trim() ?? ''));
    if (ok) {
      this.creating = false;
      this.form = {};
      await this._load();
    }
  }

  async _saveDescription(e, group) {
    e.preventDefault();
    const ok = await run(this, () => api.groupUpdate(group, this.form.description ?? ''));
    if (ok) {
      this.editing = '';
      this.form = {};
      await this._load();
    }
  }

  async _delete(group) {
    const ok = await run(this, () => api.groupDelete(group));
    if (ok) {
      if (this.open === group) this.open = '';
      await this._load();
    }
  }

  async _move(store, group) {
    const ok = await run(this, () => api.storeGroupSet(store, group));
    if (ok) await this._load();
  }

  async _toggle(group) {
    this.open = this.open === group ? '' : group;
    this.access = null;
    if (this.open) await this._loadAccess(group);
  }

  _setAccess(k) {
    return (e) => (this.accessForm = { ...this.accessForm, [k]: e.target.value });
  }

  async _addAccess(e, group) {
    e.preventDefault();
    const f = this.accessForm;
    const ok = await run(this, () =>
      api.groupAccessAdd(group, {
        subject_type: f.subject_type,
        subject_id: f.subject_id?.trim(),
        subject_relation: f.subject_type === 'team' ? 'member' : '',
        role: f.role,
      }),
    );
    if (ok) {
      this.accessForm = { ...this.accessForm, subject_id: '' };
      await this._loadAccess(group);
    }
  }

  async _removeAccess(group, a) {
    const ok = await run(this, () =>
      api.groupAccessRemove(group, [
        { subject_type: a.subject_type, subject_id: a.subject_id, subject_relation: a.subject_relation, role: a.role },
      ]),
    );
    if (ok) await this._loadAccess(group);
  }

  _moveSelect(store, current) {
    const groups = this.d?.groups ?? [];
    return html`<select
      class="mono"
      title=${t('Move the store to another group, or detach it')}
      data-testid="groups-move-${store}"
      @change=${(e) => this._move(store, e.target.value)}
    >
      ${groups.map((g) => html`<option value=${g.name} ?selected=${g.name === current}>${g.name}</option>`)}
      <option value="" ?selected=${!current}>${t('— ungrouped (its own group) —')}</option>
    </select>`;
  }

  _admins(group) {
    const a = this.access;
    if (!a) return loading(2);
    return html`<div class="card" data-testid="groups-access-${group}">
      <h4>${t('Group admins')} ${help('Group admins see and administer every store of the group; issuer admins manage the group\'s identity providers (Platform → Issuers).')}</h4>
      ${
        a.access.length
          ? html`<table class="table compact">
              <tbody>
                ${a.access.map(
                  (x) => html`<tr>
                    <td class="mono">${x.subject}</td>
                    <td>${x.role}</td>
                    <td>
                      ${
                        a.can_manage
                          ? html`<button type="button" class="small" @click=${() => this._removeAccess(group, x)}>${t('Remove')}</button>`
                          : nothing
                      }
                    </td>
                  </tr>`,
                )}
              </tbody>
            </table>`
          : html`<p class="help">${t('No one yet: the platform admins administer this group.')}</p>`
      }
      ${
        a.can_manage
          ? html`<form class="form inline" @submit=${(e) => this._addAccess(e, group)}>
              <select .value=${this.accessForm.subject_type} @change=${this._setAccess('subject_type')}>
                <option value="user">${t('user — a person (preferred_username)')}</option>
                <option value="team">${t('team — a directory group from the token')}</option>
                <option value="service_account">${t('service account — a technical user (an OAuth client)')}</option>
              </select>
              <input
                class="mono"
                required
                placeholder=${this.accessForm.subject_type === 'team' ? 'role_x' : this.accessForm.subject_type === 'service_account' ? 'ci' : 'bob'}
                .value=${this.accessForm.subject_id ?? ''}
                @input=${this._setAccess('subject_id')}
                data-testid="groups-access-subject"
              />
              <select .value=${this.accessForm.role} @change=${this._setAccess('role')}>
                ${a.roles.map((r) => html`<option value=${r}>${r}</option>`)}
              </select>
              <button class="primary" ?disabled=${this.busy} data-testid="groups-access-add">${t('Grant')}</button>
            </form>`
          : nothing
      }
    </div>`;
  }

  render() {
    const d = this.d;
    return html`
      <p class="help">
        ${t('A store group is a named set of stores that shares administration: its admins see and administer every store in it. The default group is the platform\'s own; a store outside every group is its own group of one.')}
      </p>
      ${this.error ? errorBox(this.error) : nothing}
      ${
        d?.can_manage
          ? html`<div class="toolbar">
              <button class="primary" @click=${() => (this.creating = !this.creating)} data-testid="groups-new">
                ${t('New group')}
              </button>
            </div>`
          : nothing
      }
      ${
        this.creating
          ? html`<form class="card form" @submit=${this._create} data-testid="groups-form">
              <label class="field"
                ><span>${t('Group name')} ${help('Letters, digits and underscores, e.g. tenant_acme.')}</span>
                <input class="mono" required pattern="[a-zA-Z_][a-zA-Z0-9_]*" @input=${this._set('name')} data-testid="groups-name"
              /></label>
              <label class="field wide"
                ><span>${t('Description')}</span>
                <input @input=${this._set('description')} data-testid="groups-description"
              /></label>
              <div class="actions wide">
                <button class="primary" ?disabled=${this.busy} data-testid="groups-submit">${t('Create')}</button>
                <button type="button" @click=${() => (this.creating = false)}>${t('Cancel')}</button>
              </div>
            </form>`
          : nothing
      }
      ${
        !d
          ? loading(3)
          : html`
              ${repeat(
                d.groups,
                (g) => g.name,
                (g) => html`<section class="card" data-testid="groups-row-${g.name}">
                  <div class="row-head">
                    <h3 class="mono">${g.name}</h3>
                    ${
                      this.editing === g.name
                        ? html`<form class="form inline" @submit=${(e) => this._saveDescription(e, g.name)}>
                            <input .value=${this.form.description ?? g.description} @input=${this._set('description')} />
                            <button class="primary small" ?disabled=${this.busy}>${t('Save')}</button>
                            <button type="button" class="small" @click=${() => (this.editing = '')}>${t('Cancel')}</button>
                          </form>`
                        : html`<span class="muted">${g.description || t('no description')}</span>
                            ${
                              g.capabilities?.can_manage_access
                                ? html`<button
                                    type="button"
                                    class="small"
                                    @click=${() => {
                                      this.editing = g.name;
                                      this.form = { description: g.description };
                                    }}
                                  >
                                    ${t('Edit')}
                                  </button>`
                                : nothing
                            }`
                    }
                    <span class="muted dim"
                      >${t('{n} stores', { n: g.store_count })} · ${t('created {when} by {who}', { when: fmtTime(g.created_at), who: g.created_by })}</span
                    >
                    <button type="button" class="small" @click=${() => this._toggle(g.name)} data-testid="groups-admins-${g.name}">
                      ${this.open === g.name ? t('Hide admins & sharing') : t('Admins & sharing')}
                    </button>
                    ${
                      d.can_manage && g.name !== 'default' && g.store_count === 0
                        ? html`<button type="button" class="small danger" @click=${() => this._delete(g.name)} data-testid="groups-delete-${g.name}">
                            ${t('Delete')}
                          </button>`
                        : nothing
                    }
                  </div>
                  ${
                    g.stores.length
                      ? html`<table class="table compact">
                          <tbody>
                            ${repeat(
                              g.stores,
                              (st) => st,
                              (st) => html`<tr>
                                <td><a class="mono" href=${`stores/${st}/model`}>${st}</a></td>
                                <td>${d.can_manage ? this._moveSelect(st, g.name) : nothing}</td>
                              </tr>`,
                            )}
                          </tbody>
                        </table>`
                      : html`<p class="help">${t('No stores in this group yet.')}</p>`
                  }
                  ${this.open === g.name ? html`${this._admins(g.name)}${this._sharing(g.name)}` : nothing}
                </section>`,
              )}
              ${
                d.ungrouped?.length
                  ? html`<section class="card" data-testid="groups-ungrouped">
                      <div class="row-head">
                        <h3>${t('Ungrouped stores')}</h3>
                        <span class="muted">${t('Each is its own group of one; the platform admins administer it.')}</span>
                      </div>
                      <table class="table compact">
                        <tbody>
                          ${repeat(
                            d.ungrouped,
                            (st) => st,
                            (st) => html`<tr>
                              <td><a class="mono" href=${`stores/${st}/model`}>${st}</a></td>
                              <td>${this._moveSelect(st, '')}</td>
                            </tr>`,
                          )}
                        </tbody>
                      </table>
                    </section>`
                  : nothing
              }
            `
      }
    `;
  }
}
customElements.define('pgc-groups', PgcGroups);
