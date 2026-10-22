import { html, nothing } from 'lit';
import { PgcElement, help, errorBox } from '../base.js';
import { api } from '../api.js';
import { t, t2 } from '../i18n.js';
import { run, fmtTime, statusBadge } from '../util.js';

// Registry: one picker over models and stores. The models (few by design:
// one versioned model is shared across tenant stores) are the landing
// chips; typing searches stores by name, description and model as well.
// A model (registry/model/<name>) shows its versions and its fleet — every
// store running it; a store (registry/<store>) shows which model and
// version it runs, the versions with the applied one marked, and the
// fleet. Rolling a version out happens on the store's Rollout tab.
export class PgcRegistry extends PgcElement {
  static properties = {
    me: { attribute: false },
    store: { type: String }, // the selected store, from the URL (registry/<store>)
    model: { type: String }, // or the selected model (registry/model/<name>)
    d: { state: true },
    stores: { state: true },
    q: { state: true },
    busy: { state: true },
    error: { state: true },
  };

  constructor() {
    super();
    this.store = '';
    this.model = '';
    /** @type {import('../types.js').RegistryResponse|null} */
    this.d = null;
    /** @type {import('../types.js').StoreRow[]|null} */
    this.stores = null;
    this.q = '';
    this.busy = false;
    this.error = '';
  }

  connectedCallback() {
    super.connectedCallback();
    run(this, () => api.registry()).then((d) => d && (this.d = d));
    api
      .stores()
      .then((s) => (this.stores = s?.stores ?? []))
      .catch(() => (this.stores = []));
  }

  _fleetHelp() {
    return help(
      'The fleet of a model: every store that applied one of its versions, with the version it runs. Green: on the latest version. Grey: an older version. Amber: drifted — the live model was changed in place since the version was applied.',
    );
  }

  _badge(f) {
    const cls = !f.in_sync ? 'warn' : f.model_version < f.latest_version ? 'muted' : 'ok';
    const title = !f.in_sync
      ? t('drifted')
      : f.model_version < f.latest_version
        ? t('outdated')
        : t('current');
    return html`<a
      class="badge mono ${cls}"
      href="registry/${f.store}"
      title=${title}
      data-testid=${`registry-fleet-${f.store}`}
      >${f.store} @${f.model_version}</a
    >`;
  }

  _versions(m, current) {
    const latest = m.versions[m.versions.length - 1]?.version;
    return html`<div class="table-wrap">
      <table data-testid="registry-versions">
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
              html`<tr
                class=${current === v.version ? 'current' : ''}
                data-testid=${`registry-version-${m.name}-${v.version}`}
              >
                <td class="mono">
                  @${v.version}
                  ${current === v.version ? html` <span class="badge ok">${t('applied here')}</span>` : nothing}
                  ${v.version === latest ? html` <span class="badge muted">${t('latest')}</span>` : nothing}
                </td>
                <td>${v.description}</td>
                <td class="muted">${fmtTime(v.created_at)}</td>
                <td class="mono">${v.created_by}</td>
                <td class="mono muted">${v.checksum.slice(0, 12)}</td>
              </tr>`,
          )}
        </tbody>
      </table>
    </div>`;
  }

  // The selected store: its status, its model's versions, the model's fleet.
  _storeView() {
    const st = (this.stores ?? []).find((x) => x.name === this.store);
    const d = this.d;
    if (!st)
      return html`<section class="card">
        <p class="help">
          ${this.stores ? t('No store "{store}" you can see. Pick one above.', { store: this.store }) : t('Loading…')}
        </p>
      </section>`;
    const status = st.status;
    const m = status?.model_name ? d.models.find((x) => x.name === status.model_name) : null;
    const latest = m ? m.versions[m.versions.length - 1]?.version : null;
    return html`<section class="card" data-testid="registry-store">
      <div class="toolbar">
        <h3>
          <span class="mono">${st.name}</span> ${statusBadge(status)}
          ${help('Whether the store runs a registry version (name@version), and whether its live model still matches it.')}
        </h3>
        <a class="sm" href="stores/${st.name}/rollout" data-testid="registry-store-rollout"
          >${t('Rollout tab')} →</a
        >
      </div>
      ${
        !m
          ? html`<p class="help">
              ${
                status?.model_name
                  ? t('This store runs {model}, which has no versions in the registry.', {
                      model: status.model_name,
                    })
                  : t(
                      "Unmanaged: this store's model was built in place. Publish it, or apply a registry model, on its Rollout tab.",
                    )
              }
            </p>`
          : html`<p class="help">
                ${t('Runs {model}@{version}', { model: m.name, version: status.model_version })}
                ${
                  status.applied_at
                    ? html` · ${t('applied')} ${fmtTime(status.applied_at)}
                      ${status.applied_by ? html`${t('by')} <span class="mono">${status.applied_by}</span>` : nothing}`
                    : nothing
                }
                ${
                  status.in_sync === false
                    ? html` ·
                        <span class="badge warn">${t('drifted')}</span>
                        ${t('the live model was changed since')}`
                    : nothing
                }
                ${latest > status.model_version ? html` · <span class="badge muted">${t('newer version available')}</span>` : nothing}
              </p>
              ${this._versions(m, status.model_version)}
              <h3 style="margin-top:var(--s-4)">
                ${t('Fleet')} ${this._fleetHelp()}
                <span class="muted">${t2('{n} store', '{n} stores', m.fleet?.length ?? 0)}</span>
              </h3>
              <div class="caps">${(m.fleet ?? []).map((f) => this._badge(f))}</div>`
      }
    </section>`;
  }

  // The picker: models are the landing chips (there are few); typing
  // searches models and stores, at most PICK_MAX matches of each, so a
  // fleet of thousands is never rendered as chips.
  static PICK_MAX = 20;

  _picker() {
    const words = this.q.trim().toLowerCase().split(/\s+/).filter(Boolean);
    const hit = (text) => words.every((w) => text.toLowerCase().includes(w));
    const models = this.d?.models ?? [];
    const stores = this.stores ?? [];
    const modelHits = words.length ? models.filter((m) => hit(m.name)) : models;
    const storeHits = words.length
      ? stores.filter((s) => hit(`${s.name} ${s.description ?? ''} ${s.status?.model_name ?? ''}`))
      : [];
    const modelChip = (m) =>
      html`<a
        class="chip ${m.name === this.model ? 'active' : ''}"
        href="registry/model/${m.name}"
        data-testid=${`registry-pick-model-${m.name}`}
        ><span class="badge accent">${t('model')}</span> ${m.name}
        <span class="muted"
          >${t2('{n} version', '{n} versions', m.versions.length)} ·
          ${t2('{n} store', '{n} stores', m.fleet?.length ?? 0)}</span
        ></a
      >`;
    const storeChip = (s) =>
      html`<a
        class="chip ${s.name === this.store ? 'active' : ''}"
        href="registry/${s.name}"
        data-testid=${`registry-pick-${s.name}`}
        ><span class="badge muted">${t('store')}</span> ${s.name}
        ${
          s.status?.model_name
            ? html`<span class="muted">${s.status.model_name}@${s.status.model_version}</span>`
            : html`<span class="dim">${t('unmanaged')}</span>`
        }</a
      >`;
    const more = (n, testid) =>
      n > PgcRegistry.PICK_MAX
        ? html`<span class="chip dim" data-testid=${testid}
            >${t('{n} more — keep typing', { n: n - PgcRegistry.PICK_MAX })}</span
          >`
        : nothing;
    return html`<section class="card" data-testid="registry-picker">
      <div class="toolbar">
        <label class="filter-box" aria-label=${t('Search models and stores')}>
          <input
            type="search"
            .value=${this.q}
            @input=${(e) => (this.q = e.target.value)}
            data-testid="registry-search"
            autofocus
          />
        </label>
        <span class="help">
          ${
            this.d && this.stores
              ? t(
                  '{m} models, {n} stores you can see: pick a model, or type to search models and stores by name, description or model.',
                  { m: models.length, n: stores.length },
                )
              : t('Loading…')
          }
        </span>
      </div>
      <div class="caps" data-testid="registry-store-list">
        ${
          !this.d || !this.stores
            ? html`<span class="muted">${t('Loading…')}</span>`
            : modelHits.length || storeHits.length
              ? html`${modelHits.slice(0, PgcRegistry.PICK_MAX).map(modelChip)}
                ${more(modelHits.length, 'registry-more-models')}
                ${storeHits.slice(0, PgcRegistry.PICK_MAX).map(storeChip)}
                ${more(storeHits.length, 'registry-more')}`
              : words.length
                ? html`<span class="muted">${t('nothing matches')}</span>`
                : html`<span class="muted"
                    >${t("The registry is empty. Publish a store's model from its Rollout tab.")}</span
                  >`
        }
      </div>
    </section>`;
  }

  // A model: its versions and its fleet.
  _modelView() {
    const m = (this.d?.models ?? []).find((x) => x.name === this.model);
    if (!m)
      return html`<section class="card">
        <p class="help">${t('No model "{model}" in the registry. Pick one above.', { model: this.model })}</p>
      </section>`;
    return html`<section class="card" data-testid="registry-model">
      <div class="toolbar">
        <h3><span class="badge accent">${t('model')}</span> <span class="mono">${m.name}</span></h3>
        <span class="muted"
          >${t2('{n} version', '{n} versions', m.versions.length)} ·
          ${t2('{n} store', '{n} stores', m.fleet?.length ?? 0)}</span
        >
      </div>
      ${this._versions(m, null)}
      <h3 style="margin-top:var(--s-4)">${t('Fleet')} ${this._fleetHelp()}</h3>
      ${m.fleet?.length ? html`<div class="caps">${m.fleet.map((f) => this._badge(f))}</div>` : html`<p class="help">${t('No store has applied this model yet.')}</p>`}
    </section>`;
  }

  render() {
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
      ${this.error ? errorBox(this.error) : nothing} ${this._picker()}
      ${this.d ? (this.model ? this._modelView() : this.store ? this._storeView() : nothing) : nothing}
    `;
  }
}
customElements.define('pgc-registry', PgcRegistry);
