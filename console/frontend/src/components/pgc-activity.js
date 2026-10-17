import { html, nothing } from 'lit';
import { PgcElement, help } from '../base.js';
import { api } from '../api.js';
import { t } from '../i18n.js';
import { run, fmtTime, subjectOf } from '../util.js';

// Activity tab: what happened to this store — console actions (who edited,
// published, shared through the console), the tuple audit trail (every
// relationship change, by whom), and the store's own action log (what
// principals did, as recorded by its enforcement points).
export class PgcActivity extends PgcElement {
  static properties = {
    store: { type: String },
    caps: { attribute: false },
    d: { state: true },
    view: { state: true },
    busy: { state: true },
    error: { state: true },
  };

  constructor() {
    super();
    this.d = null;
    this.view = 'console';
    this.busy = false;
    this.error = '';
  }

  willUpdate(changed) {
    if (changed.has('store') && this.store) this._load();
  }

  async _load() {
    const d = await run(this, () => api.activity(this.store));
    if (d) this.d = d;
  }

  _console(events) {
    if (!events.length) return html`<div class="empty">${t('No console actions on this store yet.')}</div>`;
    return html`<ul class="log">
      ${events.map(
        (e) =>
          html`<li>
            <span class="when" title=${e.occurred_at}>${fmtTime(e.occurred_at)}</span>
            <span
              ><span class="mono">${e.subject_type}:${e.subject_id}</span> ·
              <span class="badge accent">${t(e.action.replace('can_', '').replaceAll('_', ' '))}</span>
              ${e.payload?.op ? html` <span class="mono muted">${e.payload.op}</span>` : nothing}
              ${e.payload?.model ? html` <span class="mono">${e.payload.model}${e.payload.version ? '@' + e.payload.version : ''}</span>` : nothing}
              ${e.payload?.edit ? html` <span class="mono muted">${JSON.stringify(e.payload.edit).slice(0, 120)}</span>` : nothing}
              ${e.payload?.ops ? html` <span class="mono muted">${e.payload.ops.length} ${t('operations')}</span>` : nothing}
              ${e.payload?.tuple ? html` <span class="mono muted">${subjectOf(e.payload.tuple)} ${e.payload.tuple.relation} ${e.payload.tuple.object_type}:${e.payload.tuple.object_id}</span>` : nothing}
              ${e.payload?.tuples ? html` <span class="mono muted">${e.payload.tuples.length} ${t('tuples')}</span>` : nothing}
              ${e.payload?.access ? html` <span class="mono muted">${e.payload.access.subject_type}:${e.payload.access.subject_id} ${t('as')} ${e.payload.access.role}</span>` : nothing}
              ${e.payload?.items ? html` <span class="mono muted">${e.payload.items.map((a) => `${a.subject_type}:${a.subject_id} ${t('as')} ${a.role}`).join(', ')}</span>` : nothing}
              ${e.payload?.docs_url !== undefined ? html` <span class="mono muted">${e.payload.description} ${e.payload.docs_url}</span>` : nothing}
            </span>
          </li>`,
      )}
    </ul>`;
  }

  _audit(rows) {
    if (!rows.length) return html`<div class="empty">${t('No relationship changes recorded.')}</div>`;
    return html`<div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>${t('When')}</th>
            <th>${t('Change')}</th>
            <th>${t('Subject')}</th>
            <th>${t('Relation')}</th>
            <th>${t('Object')}</th>
            <th>
              ${t('By')}
              ${help('performed_by: the person when the write came through the console, else the connection role.')}
            </th>
          </tr>
        </thead>
        <tbody>
          ${rows.map(
            (a) =>
              html`<tr>
                <td class="muted" title=${a.performed_at}>${fmtTime(a.performed_at)}</td>
                <td>
                  <span
                    class="badge ${a.action === 'INSERT' ? 'ok' : a.action === 'DELETE' ? 'deny' : 'warn'}"
                    >${t(a.action.toLowerCase())}</span
                  >
                </td>
                <td class="mono">${subjectOf(a)}</td>
                <td class="mono">${a.relation}</td>
                <td class="mono">${a.object_type}:${a.object_id}</td>
                <td class="mono">${a.performed_by}</td>
              </tr>`,
          )}
        </tbody>
      </table>
    </div>`;
  }

  _events(rows) {
    if (!rows.length)
      return html`<div class="empty">
        ${t('The action log is empty — PEPs record what principals did via record_event.')}
      </div>`;
    return html`<div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>${t('When')}</th>
            <th>${t('Subject')}</th>
            <th>${t('Action')}</th>
            <th>${t('Object')}</th>
            <th>
              ${t('Kind')}
              ${help('request: something was asked or done; other kinds are what the recording PEP chose.')}
            </th>
            <th>${t('Recorded by')}</th>
          </tr>
        </thead>
        <tbody>
          ${rows.map(
            (e) =>
              html`<tr>
                <td class="muted" title=${e.occurred_at}>${fmtTime(e.occurred_at)}</td>
                <td class="mono">${e.subject_type}:${e.subject_id}</td>
                <td class="mono">${e.action}</td>
                <td class="mono">${e.object_type ? `${e.object_type}:${e.object_id}` : ''}</td>
                <td>${e.kind}</td>
                <td class="mono">${e.recorded_by}</td>
              </tr>`,
          )}
        </tbody>
      </table>
    </div>`;
  }

  render() {
    const d = this.d;
    if (!d)
      return html`${this.error ? html`<p class="error">${this.error}</p>` : html`<p class="muted">${t('Loading…')}</p>`}`;
    const views = [
      [
        'console',
        t('Console actions') + ` (${d.console.length})`,
        "What people did to this store through the console, from the console store's action log.",
      ],
      [
        'audit',
        t('Relationship audit') + ` (${d.audit.length})`,
        'Every tuple written or removed in this store, with who did it (the audit trail).',
      ],
      [
        'events',
        t('Action log') + ` (${d.events.length})`,
        'What principals actually did, as recorded by enforcement points (record_event); temporal gates decide on it.',
      ],
    ];
    return html`
      <div class="toolbar">
        <div class="seg">
          ${views.map(([v, l, tip]) => html`<button class=${this.view === v ? 'active' : ''} title=${t(tip)} @click=${() => (this.view = v)}>${l}</button>`)}
        </div>
        <button class="sm" @click=${this._load}>${t('Refresh')}</button>
      </div>
      <section class="card">
        ${this.view === 'console' ? this._console(d.console) : this.view === 'audit' ? this._audit(d.audit) : this._events(d.events)}
      </section>
    `;
  }
}
customElements.define('pgc-activity', PgcActivity);
