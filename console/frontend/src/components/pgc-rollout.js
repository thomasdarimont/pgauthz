import { html, nothing } from 'lit';
import { PgcElement, help, errorBox } from '../base.js';
import { api } from '../api.js';
import { t, t2 } from '../i18n.js';
import { run, fmtTime, forbiddenText } from '../util.js';

// Rollout tab: the store's managed-model state, the registry versions of its
// model, a dry-run plan for any version, and apply. Publishing a new version
// from this store's live model needs "publish" on the store AND the registry.
export class PgcRollout extends PgcElement {
  static properties = {
    store: { type: String },
    caps: { attribute: false },
    d: { state: true },
    plan: { state: true },
    planFor: { state: true },
    busy: { state: true },
    error: { state: true },
    pubName: { state: true },
    pubDesc: { state: true },
    message: { state: true },
    pick: { state: true }, // unmanaged store: the registry model whose versions are shown
  };

  constructor() {
    super();
    this.d = null;
    this.plan = null;
    this.planFor = null;
    this.busy = false;
    this.error = '';
    this.pubName = '';
    this.pubDesc = '';
    this.message = '';
    this.pick = '';
  }

  willUpdate(changed) {
    if (changed.has('store') && this.store) this._load();
  }

  async _load() {
    const d = await run(this, () => api.rollout(this.store));
    if (d) {
      this.d = d;
      if (!this.pubName) this.pubName = d.status?.model_name ?? this.store;
    }
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

  async _plan(name, version) {
    this.plan = null;
    const p = await this._wrap(() => api.plan(this.store, name, version));
    if (p) {
      this.plan = p;
      this.planFor = { name, version };
    }
  }

  async _apply(name, version) {
    const r = await this._wrap(() => api.apply(this.store, name, version));
    if (r) {
      this.message = t('Applied {model} to {store}.', { model: `${r.name}@${r.version}`, store: this.store });
      this.plan = null;
      await this._load();
      this.dispatchEvent(new CustomEvent('changed'));
    }
  }

  async _publish(e) {
    e.preventDefault();
    const r = await this._wrap(() => api.publish(this.store, this.pubName.trim(), this.pubDesc.trim()));
    if (r) {
      this.message = t('Published {model} from the live model of {store}.', {
        model: `${r.name}@${r.version}`,
        store: this.store,
      });
      this.pubDesc = '';
      await this._load();
      this.dispatchEvent(new CustomEvent('changed'));
    }
  }

  // One change as a line; the engine's plan hands rules and restrictions
  // over as objects, rendered the way the Model tab words them.
  _item(c) {
    const x = c.item;
    if (typeof x === 'string') return x;
    if (!x || typeof x !== 'object') return JSON.stringify(x);
    if (x.rule_type) {
      const src =
        x.rule_type === 'direct'
          ? 'direct'
          : x.rule_type === 'computed'
            ? x.computed_relation
            : `${x.tupleset_computed} from ${x.tupleset_relation}`;
      return `${x.object_type}.${x.relation} ← ${src}${x.negated ? ' (but not)' : ''}${x.group_id ? ` [group ${x.group_id} ${x.group_op}]` : ''}`;
    }
    if (x.allowed_user_type) {
      const subj = `${x.allowed_user_type}${x.allowed_user_relation ? '#' + x.allowed_user_relation : ''}${x.allow_wildcard ? ':*' : ''}`;
      return `${x.object_type}.${x.relation} accepts ${subj}${x.condition ? ` with ${x.condition}` : ''}`;
    }
    if (x.name && x.object_type && x.relation) return `${x.object_type}.${x.relation} / ${x.name}`;
    if (x.name) return x.name;
    return JSON.stringify(x);
  }

  _changes(list) {
    return html`<div class="plan">
      ${list.map(
        (c) =>
          html`<div class=${c.op}>
            ${{ add: '+', update: '~', remove: '-' }[c.op]}
            <span class="muted">${c.section}</span> ${this._item(c)}
          </div>`,
      )}
    </div>`;
  }

  _planView() {
    const p = this.plan;
    if (!p) return nothing;
    return html`<section class="card">
      <div class="toolbar">
        <h3>
          ${t('Plan')}: ${t('apply')}
          <span class="mono">${this.planFor.name}@${this.planFor.version || t('latest')}</span> ${t('to')}
          <span class="mono">${this.store}</span>
          ${help('A dry run: what applying this version would add, change or remove in the live model, and what blocks it (e.g. a type with tuples that would have to go).')}
        </h3>
        ${p.can_apply ? html`<span class="badge ok">${t('can apply')}</span>` : html`<span class="badge deny">${t('blocked')}</span>`}
      </div>
      ${
        p.since_label
          ? html`<h4 class="plan-head">
                ${t('What {version} changes compared to {base}', { version: `${this.planFor.name}@${this.planFor.version || t('latest')}`, base: p.since_label === 'live' ? t('the live model') : p.since_label })}
                ${help('The difference between the two definitions, section by section: + added, ~ changed, − removed. Independent of the live model: what the version carries.')}
              </h4>
              ${p.since?.length ? this._changes(p.since) : html`<p class="muted">${t('No differences.')}</p>`}`
          : nothing
      }
      <h4 class="plan-head">
        ${t('What applying it changes in the live model')}
        ${help('The dry run against the live model as it is now. A no-op means the live model already equals the version — for instance right after publishing it from here.')}
      </h4>
      ${p.plan?.no_op ? html`<p class="muted">${t('No-op: the live model already matches.')}</p>` : nothing}
      ${p.changes?.length ? this._changes(p.changes) : nothing}
      ${p.blockers?.length ? html`<p class="error">${t('Blockers')}: ${p.blockers.map((b) => (typeof b === 'string' ? b : JSON.stringify(b))).join('; ')}</p>` : nothing}
      ${
        p.can_apply && this.caps?.can_rollout
          ? html`<div class="actions plan-apply">
              <button
                class="primary"
                ?disabled=${this.busy}
                @click=${() => this._apply(this.planFor.name, this.planFor.version)}
              >
                ${t('Apply this version')}
              </button>
            </div>`
          : nothing
      }
    </section>`;
  }

  render() {
    const d = this.d;
    if (!d) return html`${this.error ? errorBox(this.error) : html`<p class="muted">${t('Loading…')}</p>`}`;
    const st = d.status;
    return html`
      ${this.error ? errorBox(this.error) : nothing}
      ${this.message ? html`<p class="notice">${this.message}</p>` : nothing}
      <section class="card">
        <h3>
          ${t('Managed model')}
          ${help('A store is managed when a registry version was applied to it; drift means the live model was changed since.')}
        </h3>
        ${
          st.model_name
            ? html`<dl class="kv">
                <dt>${t('Registry version')}</dt>
                <dd class="mono">${st.model_name}@${st.model_version}</dd>
                <dt>${t('Applied')}</dt>
                <dd>${fmtTime(st.applied_at)} ${t('by')} <span class="mono">${st.applied_by}</span></dd>
                <dt>${t('Drift')}</dt>
                <dd>
                  ${st.in_sync ? html`<span class="badge ok">${t('in sync')}</span>` : html`<span class="badge warn">${t('live model differs from {version}', { version: `${st.model_name}@${st.model_version}` })}</span>`}
                </dd>
                <dt>${t('Live checksum')}</dt>
                <dd class="mono">${st.live_checksum?.slice(0, 16)}…</dd>
              </dl>`
            : html`<p class="muted">
                ${
                  d.can_rollout || this.caps?.can_publish
                    ? t(
                        "Unmanaged: this store's model was built directly (SQL or the editor), not applied from the registry. Publish it to start versioning, or apply a registry version below.",
                      )
                    : t(
                        "Unmanaged: this store's model was built directly (SQL or the editor), not applied from the registry.",
                      )
                }
              </p>`
        }
      </section>

      ${
        this.caps?.can_publish
          ? html`<form class="card form" @submit=${this._publish}>
              <h3 class="wide">
                ${t('Publish the live model as the next registry version')}
                ${help('Snapshots the live model as an immutable version under this name. Needs "publish" on the store and on the registry.')}
              </h3>
              <label class="field"
                ><span>${t('Model name')}</span
                ><input
                  class="mono"
                  required
                  pattern="[a-zA-Z_][a-zA-Z0-9_]*"
                  .value=${this.pubName}
                  @input=${(e) => (this.pubName = e.target.value)}
              /></label>
              <label class="field wide"
                ><span>${t('Description (what changed)')}</span
                ><input .value=${this.pubDesc} @input=${(e) => (this.pubDesc = e.target.value)}
              /></label>
              <div class="actions wide">
                <button class="primary" ?disabled=${this.busy}>${t('Publish')}</button>
                <span class="help">${t('Idempotent: an unchanged model returns the existing version.')}</span>
              </div>
            </form>`
          : nothing
      }

      <section class="card">
        <h3>
          ${
            st.model_name
              ? html`${t('Versions of')} <span class="mono">${st.model_name}</span>`
              : d.can_rollout
                ? t('Apply a registry model')
                : t('Registry')
          }
          ${
            st.model_name
              ? help('Immutable versions; Plan shows what applying one would change here.')
              : help(
                  'This store is not managed yet. Pick a model from the registry to see its versions; applying one replaces the live model and puts the store under that model.',
                )
          }
        </h3>
        ${
          !st.model_name && d.versions.length && d.can_rollout
            ? html`<label class="field">
                <span>${t('Registry model')}</span>
                <select .value=${this.pick} @change=${(e) => (this.pick = e.target.value)}>
                  <option value="">${t('— choose a model —')}</option>
                  ${[...new Set(d.versions.map((v) => v.name))]
                    .sort()
                    .map(
                      (n) =>
                        html`<option value=${n} ?selected=${n === this.pick}>
                          ${n} (${d.versions.filter((v) => v.name === n).length})
                        </option>`,
                    )}
                </select>
              </label>`
            : nothing
        }
        ${
          !st.model_name && !d.can_rollout
            ? html`<p class="help">${t('Not under a registry model. Applying one needs "roll out".')}</p>`
            : !st.model_name && !this.pick
              ? nothing
              : d.versions.length
                ? html`<div class="table-wrap">
                    <table>
                      <thead>
                        <tr>
                          <th>${t('Version')}</th>
                          <th>${t('Description')}</th>
                          <th>${t('Published')}</th>
                          <th>${t('By')}</th>
                          <th>${t('Checksum')}</th>
                          <th></th>
                        </tr>
                      </thead>
                      <tbody>
                        ${d.versions
                          .filter((v) => st.model_name || v.name === this.pick)
                          .map(
                            (v) =>
                              html`<tr>
                                <td class="mono">
                                  ${v.name}@${v.version}${st.model_name === v.name && st.model_version === v.version ? html` <span class="badge accent">${t('applied')}</span>` : nothing}
                                </td>
                                <td>${v.description}</td>
                                <td class="muted">${fmtTime(v.created_at)}</td>
                                <td class="mono">${v.created_by}</td>
                                <td class="mono muted">${v.checksum.slice(0, 12)}</td>
                                <td class="actions">
                                  ${
                                    d.can_rollout
                                      ? html`<button
                                          class="sm"
                                          ?disabled=${this.busy}
                                          @click=${() => this._plan(v.name, v.version)}
                                        >
                                          ${t('Plan')}
                                        </button>`
                                      : nothing
                                  }
                                </td>
                              </tr>`,
                          )}
                      </tbody>
                    </table>
                  </div>`
                : html`<div class="empty">
                    ${!st.model_name && !d.can_rollout ? t('Not under a registry model. Applying one needs "roll out".') : t('No registry versions yet.')}
                  </div>`
        }
      </section>
      ${this._planView()}
      ${
        d.fleet?.length
          ? html`<section class="card">
              <h3>
                ${t('Fleet')}: ${t2('{n} store running', '{n} stores running', d.fleet.length)}
                <span class="mono">${st.model_name}</span>
                ${help('Every store that applied a version of this model, with its state: current, outdated (a newer version exists) or drifted.')}
              </h3>
              <div class="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>${t('Store')}</th>
                      <th>${t('Version')}</th>
                      <th>${t('Latest')}</th>
                      <th>${t('State')}</th>
                      <th>${t('Applied')}</th>
                    </tr>
                  </thead>
                  <tbody>
                    ${d.fleet.map(
                      (f) =>
                        html`<tr>
                          <td class="mono">
                            ${f.store === this.store ? html`<b>${f.store}</b>` : html`<a href="stores/${f.store}/rollout">${f.store}</a>`}
                          </td>
                          <td class="num">${f.model_version}</td>
                          <td class="num">${f.latest_version}</td>
                          <td>
                            ${!f.in_sync ? html`<span class="badge warn">${t('drifted')}</span>` : f.model_version < f.latest_version ? html`<span class="badge muted">${t('outdated')}</span>` : html`<span class="badge ok">${t('current')}</span>`}
                          </td>
                          <td class="muted">${fmtTime(f.applied_at)}</td>
                        </tr>`,
                    )}
                  </tbody>
                </table>
              </div>
            </section>`
          : nothing
      }
    `;
  }
}
customElements.define('pgc-rollout', PgcRollout);
