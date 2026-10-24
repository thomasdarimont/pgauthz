import { html, nothing } from 'lit';
import { PgcElement, help, errorBox } from '../base.js';
import { api } from '../api.js';
import { t } from '../i18n.js';
import { run, forbiddenText } from '../util.js';

// Store → Data subject: a person's request about their data (GDPR). Look a
// subject up — the objects it relates to (list_subject_objects, the table
// and the CSV the application teams take to select the person's records),
// everything the store holds about it as one JSON document (export_subject
// plus the decision log) — and, for those who manage access, its erasure
// with a confirmation step. Reads need can_view_audit.
export class PgcSubject extends PgcElement {
  static properties = {
    store: { type: String },
    caps: { attribute: false },
    busy: { state: true },
    error: { state: true },
    form: { state: true },
    result: { state: true },
    confirming: { state: true },
    subject: { state: true },
    meta: { state: true },
  };

  constructor() {
    super();
    this.busy = false;
    this.error = '';
    /** @type {{subject?: string, subject_relations?: string, purge_audit?: boolean}} */
    this.form = {};
    /** @type {{erase?: import('../types.js').SubjectErased}} */
    this.result = {};
    this.confirming = null;
    /** @type {import('../types.js').SubjectExport|null} */
    this.subject = null;
    /** @type {import('../types.js').Meta|null} */
    this.meta = null;
  }

  willUpdate(changed) {
    if (changed.has('store') && this.store) {
      this.subject = null;
      this.result = {};
      api
        .meta(this.store)
        .then((m) => (this.meta = m))
        .catch(() => {});
    }
  }

  _set(k) {
    return (e) =>
      (this.form = { ...this.form, [k]: e.target.type === 'checkbox' ? e.target.checked : e.target.value });
  }

  async _lookup(e) {
    e.preventDefault();
    this.subject = null;
    this.result = {};
    const r = await run(this, async () => {
      try {
        return await api.subject(this.store, this.form.subject.trim(), this.form.subject_relations ?? '');
      } catch (err) {
        throw new Error(forbiddenText(err));
      }
    });
    if (r) this.subject = r;
  }

  async _act(name, fn) {
    const r = await run(this, async () => {
      try {
        return await fn();
      } catch (err) {
        throw new Error(forbiddenText(err));
      }
    });
    this.confirming = null;
    if (r) {
      this.result = { ...this.result, [name]: r };
      // the subject as it is now (nothing, after an erasure)
      const again = await run(this, () =>
        api.subject(this.store, this.form.subject.trim(), this.form.subject_relations ?? ''),
      );
      if (again) this.subject = again;
    }
  }

  _card() {
    const f = this.form;
    const d = this.subject;
    const can = !!this.caps?.can_manage_access;
    const count = (k) => (Array.isArray(d?.[k]) ? d[k].length : 0);
    const eff = (d?.effective ?? []).reduce((n, e) => n + (e.objects?.length ?? 0), 0);
    return html`<section class="card" data-testid="subject">
      <h3>
        ${t('Data subject')}
        ${help("A person's request about their data (GDPR): everything this store holds about a subject — their grants and memberships, the tuples about them, what they can effectively do, their recorded actions, every change that named them, and their lines of the decision log — as one document to hand over (export_subject); and its erasure (erase_subject: the tuples on either side, the actions, the decision-log lines; the audit trail only when asked).")}
      </h3>
      <form class="form" data-testid="subject-form" @submit=${(e) => this._lookup(e)}>
        <label class="field wide"
          ><span>${t('Subject')}</span
          ><input
            class="mono"
            required
            placeholder="user:alice"
            list="subject-types"
            .value=${f.subject ?? ''}
            @input=${this._set('subject')}
            data-testid="subject-id"
          />
          <datalist id="subject-types">
            ${(this.meta?.types ?? []).map((ty) => html`<option value="${ty}:"></option>`)}
          </datalist>
        </label>
        <label class="field wide"
          ><span
            >${t('Relations')}
            ${help('Narrow the objects to these relations, comma-separated (owner, can_read, …). Empty: every relation of the model.')}</span
          ><input
            class="mono"
            placeholder="owner, can_read"
            .value=${f.subject_relations ?? ''}
            @input=${this._set('subject_relations')}
            data-testid="subject-relations"
          />
        </label>
        <div class="actions wide">
          <button class="sm" ?disabled=${this.busy} data-testid="subject-lookup">${t('Look up')}</button>
        </div>
      </form>
      ${
        d
          ? html`<div class="stats" data-testid="subject-summary">
                <span><b>${count('direct')}</b> ${t('grants and memberships')}</span>
                <span><b>${count('as_object')}</b> ${t('tuples about the subject')}</span>
                <span><b>${eff}</b> ${t('objects reachable')}</span>
                <span><b>${count('events')}</b> ${t('recorded actions')}</span>
                <span><b>${count('events_about')}</b> ${t('actions on the subject')}</span>
                <span><b>${count('audit')}</b> ${t('audit rows')}</span>
                <span><b>${d.decisions ? count('decisions') : '—'}</b> ${t('decision-log lines')}</span>
                <span
                  ><b>${d.decisions_about ? count('decisions_about') : '—'}</b>
                  ${t('decision-log lines about the subject')}</span
                >
              </div>
              ${d.events_truncated || d.audit_truncated || d.decisions_truncated || d.effective.some((e) => e.truncated) ? html`<p class="help">${t('Some lists hit the cap; the download carries the same cap (export_subject with a higher p_limit in SQL for everything).')}</p>` : nothing}
              <div class="actions">
                <span class="seg">
                  <a
                    class="btn sm"
                    href=${api.subjectExportURL(this.store, `${d.subject.type}:${d.subject.id}`, 'csv', f.subject_relations ?? '')}
                    download
                    title=${t("The objects the subject relates to, one row per object and relation — what the application teams take to select the person's records.")}
                    data-testid="subject-download-csv"
                    >${t('Objects')} CSV</a
                  >
                  <a
                    class="btn sm"
                    href=${api.subjectExportURL(this.store, `${d.subject.type}:${d.subject.id}`, 'json', f.subject_relations ?? '')}
                    download
                    title=${t('The whole document: tuples, effective access, actions, audit rows, decision-log lines.')}
                    data-testid="subject-download"
                    >${t('Everything')} JSON</a
                  >
                </span>
                ${
                  can
                    ? this.confirming === 'erase'
                      ? html`<div class="danger-confirm" data-testid="subject-confirm">
                          <p>
                            <b
                              >${t('Erase {subject} from {store}?', { subject: `${d.subject.type}:${d.subject.id}`, store: this.store })}</b
                            >
                            ${t('Removes the tuples naming the subject on either side (including expired ones), its recorded actions and its decision-log lines. Gates counting those actions can only relax. The audit rows stay unless chosen below.')}
                          </p>
                          <label class="check"
                            ><input
                              type="checkbox"
                              .checked=${f.purge_audit ?? false}
                              @change=${this._set('purge_audit')}
                              data-testid="subject-purge-audit"
                            />
                            ${t('also remove the audit rows naming the subject (no history left)')}</label
                          >
                          <div class="actions">
                            <button
                              class="danger"
                              ?disabled=${this.busy}
                              data-testid="subject-erase-confirm"
                              @click=${() => this._act('erase', () => api.subjectErase(this.store, { subject: `${d.subject.type}:${d.subject.id}`, purge_audit: !!f.purge_audit }))}
                            >
                              ${t('Erase the subject')}
                            </button>
                            <button class="sm" type="button" @click=${() => (this.confirming = null)}>
                              ${t('Keep')}
                            </button>
                          </div>
                        </div>`
                      : html`<button
                          class="sm danger"
                          type="button"
                          ?disabled=${this.busy}
                          data-testid="subject-erase"
                          @click=${() => (this.confirming = 'erase')}
                        >
                          ${t('Erase…')}
                        </button>`
                    : nothing
                }
              </div>
              ${
                this.result.erase
                  ? html`<p class="help" data-testid="subject-erased">
                      ${t(
                        'Erased: {a} tuples as subject, {b} about the subject, {c} actions, {d} audit rows, {e} decision-log lines.',
                        {
                          a: this.result.erase.tuples_as_subject,
                          b: this.result.erase.tuples_as_object,
                          c: this.result.erase.events,
                          d: this.result.erase.audit,
                          e: this.result.erase.decisions,
                        },
                      )}
                      ${this.result.erase.decisions_error ? html`<span class="error">${this.result.erase.decisions_error}</span>` : nothing}
                    </p>`
                  : nothing
              }
              ${
                d.effective.length
                  ? html`<div class="table-wrap">
                      <table class="compact" data-testid="subject-objects">
                        <thead>
                          <tr>
                            <th>${t('Type')}</th>
                            <th>${t('Relation')}</th>
                            <th>${t('Objects')}</th>
                          </tr>
                        </thead>
                        <tbody>
                          ${d.effective.map(
                            (e) =>
                              html`<tr>
                                <td class="mono">${e.object_type}</td>
                                <td class="mono">${e.relation}</td>
                                <td class="mono">
                                  ${(e.objects ?? []).slice(0, 20).join(', ')}${(e.objects?.length ?? 0) > 20 ? html` <span class="muted">… ${t('{n} in total', { n: e.objects.length })}</span>` : nothing}${e.truncated ? html` <span class="badge warn">${t('capped')}</span>` : nothing}
                                  ${e.direct?.length ? html`<div class="help">${t('direct')}: ${e.direct.join(', ')}</div>` : nothing}
                                </td>
                              </tr>`,
                          )}
                        </tbody>
                      </table>
                    </div>`
                  : html`<p class="muted">${t('The subject reaches no object with these relations.')}</p>`
              }
              <details>
                <summary>${t('The document')}</summary>
                <pre class="code" data-testid="subject-json">${JSON.stringify(d, null, 2)}</pre>
              </details>`
          : nothing
      }
    </section>`;
  }

  render() {
    return html`
      ${this.error ? errorBox(this.error) : nothing}
      <p class="help">
        ${t("Which records of which applications are this person's? pgauthz knows the references — every object the subject relates to, under each type and relation — the applications hold the records. Look the subject up, hand the Objects CSV to the application teams, or download everything the store holds about the subject.")}
      </p>
      ${this._card()}
    `;
  }
}
customElements.define('pgc-subject', PgcSubject);
