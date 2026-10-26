import { html, nothing } from 'lit';
import { PgcElement, help, errorBox } from '../base.js';
import { api } from '../api.js';
import { t, t2 } from '../i18n.js';
import { capLabel, statusBadge, run, forbiddenText, fmtTime, fmtRelative } from '../util.js';

// Home: the stores this person can see, each with what they may do there.
// Platform admins also see unclaimed stores (created outside the console) and
// can create new ones — the creator becomes the first owner.
export class PgcStores extends PgcElement {
  static properties = {
    me: { attribute: false },
    data: { state: true },
    busy: { state: true },
    error: { state: true },
    creating: { state: true },
    form: { state: true },
    groups: { state: true }, // the store groups a new store can be placed in (ADR 0017)
    deleting: { state: true },
    deleteName: { state: true },
    q: { state: true }, // search text: matches name and description, instantly
    sort: { state: true }, // { key, dir }
    pageSize: { state: true },
    showRetired: { state: true }, // retired stores are hidden unless asked for (per browser)
    page: { state: true }, // 0-based
  };

  static PAGE_SIZES = [25, 50, 100, 500];

  constructor() {
    super();
    /** @type {import('../types.js').StoreList|null} */
    this.data = null;
    this.busy = false;
    this.error = '';
    this.creating = false;
    this.form = {};
    this.deleting = null; // unclaimed store whose deletion is being confirmed
    this.deleteName = '';
    this.q = '';
    this.sort = { key: 'name', dir: 1 };
    this.pageSize = 25;
    this.showRetired = false;
    try {
      this.showRetired = localStorage.getItem('pgc_stores_show_retired') === '1';
    } catch {
      /* storage unavailable */
    }
    this.page = 0;
    try {
      const stored = Number(localStorage.getItem('pgc_store_page_size'));
      if (PgcStores.PAGE_SIZES.includes(stored)) this.pageSize = stored;
    } catch {
      /* storage unavailable */
    }
  }

  _setPageSize(e) {
    this.pageSize = Number(e.target.value);
    this.page = 0;
    try {
      localStorage.setItem('pgc_store_page_size', String(this.pageSize));
    } catch {
      /* storage unavailable */
    }
  }

  // The rows of the current page, with the page clamped when a search or a
  // size change leaves fewer pages than before.
  _paged() {
    const all = this._visible();
    const pages = Math.max(1, Math.ceil(all.length / this.pageSize));
    const page = Math.min(this.page, pages - 1);
    return {
      rows: all.slice(page * this.pageSize, (page + 1) * this.pageSize),
      total: all.length,
      page,
      pages,
    };
  }

  _pager(p) {
    if (p.pages <= 1) return nothing;
    const from = p.page * this.pageSize + 1;
    const to = Math.min(p.total, (p.page + 1) * this.pageSize);
    return html`<div class="pager">
      <span class="muted">${t('{from}–{to} of {total}', { from, to, total: p.total })}</span>
      <button class="sm" ?disabled=${p.page === 0} @click=${() => (this.page = p.page - 1)}>
        ‹ ${t('Previous')}
      </button>
      <span class="muted">${t('page {n} of {pages}', { n: p.page + 1, pages: p.pages })}</span>
      <button class="sm" ?disabled=${p.page >= p.pages - 1} @click=${() => (this.page = p.page + 1)}>
        ${t('Next')} ›
      </button>
    </div>`;
  }

  connectedCallback() {
    super.connectedCallback();
    void this._load();
  }

  async _load() {
    const d = await run(this, () => api.stores());
    if (d) this.data = d;
    if (d?.can_create) {
      try {
        const g = await api.platformGroups();
        this.groups = g.groups.map((x) => x.name);
      } catch {
        this.groups = ['default'];
      }
    }
  }

  _set(k) {
    return (e) => (this.form = { ...this.form, [k]: e.target.value });
  }

  async _create(e) {
    e.preventDefault();
    const ok = await run(this, async () => {
      try {
        const r = await api.createStore(
          this.form.name?.trim(),
          this.form.description?.trim() ?? '',
          this.form.group === undefined ? undefined : this.form.group,
        );
        if (this.form.docs_url?.trim())
          await api.storeSettings(r.name, {
            description: this.form.description?.trim() ?? '',
            docs_url: this.form.docs_url.trim(),
          });
        return r;
      } catch (err) {
        throw new Error(forbiddenText(err));
      }
    });
    if (ok) {
      this.creating = false;
      this.dispatchEvent(new CustomEvent('navigate', { detail: `stores/${ok.name}/model` }));
    }
  }

  async _adopt(name) {
    if (await run(this, () => api.adoptStore(name))) await this._load();
  }

  // Search is client-side (the list is small and already loaded): a store
  // matches when its name or description contains every word typed.
  _retired() {
    return (this.data?.stores ?? []).filter((st) => st.retired_at).length;
  }

  _toggleRetired(e) {
    this.showRetired = e.target.checked;
    this.page = 0;
    try {
      localStorage.setItem('pgc_stores_show_retired', this.showRetired ? '1' : '0');
    } catch {
      /* storage unavailable */
    }
  }

  _visible() {
    const words = this.q.trim().toLowerCase().split(/\s+/).filter(Boolean);
    const rows = (this.data?.stores ?? []).filter(
      (st) =>
        (this.showRetired || !st.retired_at) &&
        words.every((w) => `${st.name} ${st.description ?? ''}`.toLowerCase().includes(w)),
    );
    const { key, dir } = this.sort;
    const val = (st) => {
      switch (key) {
        case 'created':
          return st.created_at ? new Date(st.created_at).getTime() : 0;
        case 'updated':
          return st.last_change_at ? new Date(st.last_change_at).getTime() : 0;
        case 'model':
          return st.status?.model_name ? `${st.status.model_name}@${st.status.model_version}` : '';
        default:
          return st.name;
      }
    };
    return rows.sort((a, b) => {
      const x = val(a);
      const y = val(b);
      const c = typeof x === 'number' && typeof y === 'number' ? x - y : String(x).localeCompare(String(y));
      return (c || a.name.localeCompare(b.name)) * dir;
    });
  }

  _toggleSort(key) {
    this.sort = this.sort.key === key ? { key, dir: -this.sort.dir } : { key, dir: 1 };
  }

  _sortTh(key, label, extra) {
    const active = this.sort.key === key;
    return html`<th
      class="sortable ${active ? 'active' : ''}"
      @click=${() => this._toggleSort(key)}
      title=${t('sort')}
    >
      ${label} ${extra ?? nothing}
      <span class="sort-ind">${active ? (this.sort.dir > 0 ? '▲' : '▼') : '↕'}</span>
    </th>`;
  }

  _row(st) {
    const caps = Object.entries(st.capabilities ?? {})
      .filter(([k, v]) => v && k !== 'can_view')
      .map(([k]) => capLabel(k));
    const href = `stores/${st.name}/model`;
    const open = (e) => {
      if (e.target.closest('a, button')) return;
      this.dispatchEvent(new CustomEvent('navigate', { detail: href, bubbles: true, composed: true }));
    };
    return html`<tr class="store-row" @click=${open}>
      <td>
        <a class="store-link" href=${href}>
          <span class="store-mark" aria-hidden="true">${st.name.slice(0, 1).toUpperCase()}</span>
          <span class="mono">${st.name}</span>
        </a>
      </td>
      <td class="muted desc">
        ${
          st.retired_at
            ? html`<span
                class="badge warn"
                data-testid="store-retired-badge"
                title=${t('retired on {when}', { when: fmtTime(st.retired_at) })}
                >${t('retired')}</span
              > `
            : nothing
        }
        ${
          st.store_group
            ? html`<span class="badge muted" title=${t('store group')} data-testid="store-group-badge">${st.store_group}</span> `
            : nothing
        }
        ${st.description || html`<span class="dim">${t('no description')}</span>`}
        ${
          st.docs_url
            ? html`<a
                class="badge doc"
                href=${st.docs_url}
                target="_blank"
                rel="noopener noreferrer nofollow"
                title=${st.docs_url}
                >${t('documentation')} ↗</a
              >`
            : nothing
        }
      </td>
      <td>${statusBadge(st.status)}</td>
      <td>
        <div class="caps chips" title=${caps.join(', ')}>
          ${
            caps.length
              ? html`${caps.slice(0, 3).map((c) => html`<span class="chip">${c}</span>`)}
                ${caps.length > 3 ? html`<span class="chip more">+${caps.length - 3}</span>` : nothing}`
              : html`<span class="chip dim">${t('read-only')}</span>`
          }
        </div>
      </td>
      <td class="muted nowrap" title=${st.created_at ?? ''}>${fmtTime(st.created_at)}</td>
      <td class="muted nowrap" title=${st.last_change_at ? fmtTime(st.last_change_at) : ''}>
        ${st.last_change_at ? fmtRelative(st.last_change_at) : '—'}
      </td>
      <td class="open"><a class="btn sm" href=${href}>${t('Open')} →</a></td>
    </tr>`;
  }

  async _deleteUnclaimed(e) {
    e.preventDefault();
    const name = this.deleting;
    const ok = await run(this, async () => {
      try {
        return await api.deleteStore(name, this.deleteName.trim(), false);
      } catch (err) {
        throw new Error(forbiddenText(err));
      }
    });
    if (ok) {
      this.deleting = null;
      this.deleteName = '';
      await this._load();
    }
  }

  render() {
    const d = this.data;
    return html`
      <div class="page-head">
        <div>
          <h1>${t('Stores')}</h1>
          <div class="sub">
            ${d ? t2('{n} store you can see', '{n} stores you can see', d.stores.length) : t('Loading…')}
            ${help('Which stores you see, and what you may do in each, is decided by the console store: your explicit roles plus the teams your token carries (realm roles, groups, organization).')}
          </div>
        </div>
        ${d?.can_create ? html`<button class="primary" @click=${() => (this.creating = !this.creating)}>${t('New store')}</button>` : nothing}
      </div>
      ${this.error ? errorBox(this.error) : nothing}
      ${
        this.creating
          ? html`<form class="card form" @submit=${this._create}>
              <label class="field"
                ><span
                  >${t('Store name')}
                  ${help('Letters, digits and underscores, e.g. tenant_acme; also the package segment of OPA hooks for this store.')}</span
                >
                <input class="mono" required pattern="[a-zA-Z_][a-zA-Z0-9_]*" @input=${this._set('name')}
              /></label>
              <label class="field wide"
                ><span
                  >${t('Description')}
                  ${help('One line about what this store authorizes; shown on the store card.')}</span
                >
                <input @input=${this._set('description')}
              /></label>
              <label class="field"
                ><span
                  >${t('Store group')}
                  ${help('Which group administers the store (ADR 0017): the default group is the platform\'s own; ungrouped means the store is its own group of one.')}</span
                >
                <select class="mono" @change=${this._set('group')} data-testid="store-create-group">
                  ${(this.groups ?? ['default']).map((g) => html`<option value=${g} ?selected=${g === 'default'}>${g}</option>`)}
                  <option value="">${t('— ungrouped (its own group) —')}</option>
                </select></label
              >
              <label class="field wide"
                ><span
                  >${t('Documentation link')}
                  ${help('An http(s) link to where this model is described in depth — a wiki page, a design document, a ticket.')}</span
                >
                <input type="url" @input=${this._set('docs_url')}
              /></label>
              <div class="actions wide">
                <button class="primary" ?disabled=${this.busy}>${t('Create — you become its owner')}</button>
                <button type="button" @click=${() => (this.creating = false)}>${t('Cancel')}</button>
              </div>
            </form>`
          : nothing
      }
      ${
        d
          ? html`
              ${
                d.stores.length
                  ? html`<div class="toolbar">
                        <label class="filter-box" aria-label=${t('Search')}>
                          <svg
                            class="filter-icon"
                            viewBox="0 0 16 16"
                            width="14"
                            height="14"
                            aria-hidden="true"
                          >
                            <circle
                              cx="6.5"
                              cy="6.5"
                              r="4.5"
                              fill="none"
                              stroke="currentColor"
                              stroke-width="1.4"
                            />
                            <path
                              d="M10 10l4.5 4.5"
                              stroke="currentColor"
                              stroke-width="1.4"
                              stroke-linecap="round"
                            />
                          </svg>
                          <input
                            type="search"
                            placeholder=${t('search stores by name or description')}
                            .value=${this.q}
                            @input=${(e) => {
                              this.q = e.target.value;
                              this.page = 0;
                            }}
                          />
                        </label>
                        ${
                          this.q && this._visible().length !== d.stores.length
                            ? html`<span class="muted"
                                >${t2('{n} match', '{n} matches', this._visible().length)}</span
                              >`
                            : nothing
                        }
                        <button
                          class="sm"
                          title=${t('Reload the stores')}
                          ?disabled=${this.busy}
                          @click=${this._load}
                        >
                          ↻ ${t('Refresh')}
                        </button>
                        ${
                          this._retired()
                            ? html`<label
                                class="check"
                                title=${t('Retired stores keep their history and name; they serve no decisions.')}
                              >
                                <input
                                  type="checkbox"
                                  .checked=${this.showRetired}
                                  @change=${this._toggleRetired}
                                  data-testid="stores-show-retired"
                                />
                                ${t('show retired')} (${this._retired()})
                              </label>`
                            : nothing
                        }
                        <label class="check page-size">
                          ${t('Show')}
                          <select
                            .value=${String(this.pageSize)}
                            @change=${this._setPageSize}
                            aria-label=${t('stores per page')}
                          >
                            ${PgcStores.PAGE_SIZES.map((n) => html`<option value=${n} ?selected=${n === this.pageSize}>${n}</option>`)}
                          </select>
                          ${t('per page')}
                        </label>
                      </div>
                      <div class="table-wrap stores-table">
                        <table>
                          <thead>
                            <tr>
                              ${this._sortTh('name', t('Store'))}
                              <th>${t('Description')}</th>
                              ${this._sortTh('model', t('Model'), help('The registry version the store runs, or unmanaged when its model was built in place.'))}
                              <th>${t('Your access')}</th>
                              ${this._sortTh('created', t('Created at'))}
                              ${this._sortTh('updated', t('Updated at'), help('The latest model, condition or tuple change in the audit trail.'))}
                              <th></th>
                            </tr>
                          </thead>
                          <tbody>
                            ${this._paged().rows.map((s) => this._row(s))}
                          </tbody>
                        </table>
                      </div>
                      ${this._pager(this._paged())}`
                  : html`<div class="empty">
                      ${t('No store is shared with you yet. Ask a store owner for a role, or a platform admin.')}
                    </div>`
              }
              ${
                d.unclaimed?.length
                  ? html`<section class="card">
                      <h3>
                        ${t('Unclaimed stores')}
                        ${help('Stores that exist in the engine but nobody manages in the console yet. Adopting one puts it under the platform and makes you its first owner.')}
                      </h3>
                      <div class="table-wrap">
                        <table>
                          <thead>
                            <tr>
                              <th>${t('Store')}</th>
                              <th>${t('Description')}</th>
                              <th>${t('Created at')}</th>
                              <th></th>
                            </tr>
                          </thead>
                          <tbody>
                            ${d.unclaimed.map(
                              (s) =>
                                html`<tr>
                                  <td class="mono">${s.name}</td>
                                  <td class="muted">${s.description}</td>
                                  <td class="muted nowrap">${fmtTime(s.created_at)}</td>
                                  <td class="actions">
                                    <button
                                      class="sm"
                                      ?disabled=${this.busy}
                                      @click=${() => this._adopt(s.name)}
                                    >
                                      ${t('Adopt')}
                                    </button>
                                    <button
                                      class="sm danger"
                                      ?disabled=${this.busy}
                                      @click=${() => {
                                        this.deleting = s.name;
                                        this.deleteName = '';
                                      }}
                                    >
                                      ${t('Delete…')}
                                    </button>
                                  </td>
                                </tr>`,
                            )}
                          </tbody>
                        </table>
                      </div>
                      ${
                        this.deleting
                          ? html`<form class="form danger-confirm" @submit=${this._deleteUnclaimed}>
                              <p class="wide">
                                ${t('Type the store name to confirm:')}
                                <span class="mono">${this.deleting}</span> —
                                ${t('this removes the store and everything in it; the audit history stays.')}
                              </p>
                              <label class="field"
                                ><span>${t('Store name')}</span>
                                <input
                                  class="mono"
                                  required
                                  autocomplete="off"
                                  .value=${this.deleteName}
                                  @input=${(e) => (this.deleteName = e.target.value)}
                              /></label>
                              <div class="actions wide">
                                <button
                                  class="danger"
                                  ?disabled=${this.busy || this.deleteName.trim() !== this.deleting}
                                >
                                  ${t('Delete store permanently')}
                                </button>
                                <button type="button" @click=${() => (this.deleting = null)}>
                                  ${t('Cancel')}
                                </button>
                              </div>
                            </form>`
                          : nothing
                      }
                    </section>`
                  : nothing
              }
            `
          : nothing
      }
    `;
  }
}
customElements.define('pgc-stores', PgcStores);
