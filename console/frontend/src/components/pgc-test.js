import { html, nothing } from 'lit';
import { PgcElement, help, errorBox } from '../base.js';
import { api } from '../api.js';
import { highlightJSON } from '../highlight.js';
import { t, t2 } from '../i18n.js';
import { PgcJson } from './pgc-json.js';
import { run, copyText, forbiddenText, parseList, fmtTime, fmtRelative, FieldInvalid } from '../util.js';
import { PgcExplainTree } from './pgc-explain-tree.js';
import { explainOptions } from './pgc-explain-options.js';
import { checkCaseYAML, listCaseYAML, appendCase } from './pgc-scenarios.js';

// Test tab, four ways to ask the managed store:
//   single — one subject, one action, one resource, with the resolution tree
//   matrix — many subjects × actions × resources in one engine call, as a grid
//   search — the candidates you do not know: which objects can X reach, who
//            can reach Y (list_objects / list_subjects)
//   as me  — the real PEP path: your own token through pgauthzd (and OPA
//            when it fronts the instance), with the detail envelope that says
//            who decided — engine, OPA, which hooks, any veto
// The modes' URL names: stores/<store>/test/<mode>[/<view>] — a deep link
// and the browser's history (back returns to the previous mode or view).
const MODE_SLUGS = {
  single: 'single-check',
  matrix: 'matrix',
  search: 'search',
  asme: 'as-me',
  scenarios: 'scenarios',
};
const SLUG_MODES = Object.fromEntries(Object.entries(MODE_SLUGS).map(([k, v]) => [v, k]));

const MODES = [
  ['single', 'Single check', 'One decision for any subject, with the resolution tree.'],
  ['matrix', 'Matrix', 'Many subjects, actions and resources at once — one engine call, one grid.'],
  [
    'search',
    'Search',
    'Which objects can a subject reach? Who can reach an object? For the candidates you do not know.',
  ],
  [
    'asme',
    'As me via pgauthzd',
    'Your own token through pgauthzd, the way an application asks. Shows whether OPA and which policy hooks took part.',
  ],
  [
    'scenarios',
    'Scenarios',
    "Saved checks as a tests.authz.yaml fixture, run against the store's current model in an ephemeral store — the runner behind pgauthzctl model test.",
  ],
];

export class PgcTest extends PgcElement {
  static properties = {
    store: { type: String },
    caps: { attribute: false },
    me: { attribute: false },
    sub: { type: String }, // the URL's sub-path under test/: "<mode>[/<view>]"
    mode: { state: true },
    scenarioView: { state: true }, // the scenarios' view from the URL: harness | edit-as-yaml
    ask: { state: true },
    successfulOnly: { state: true },
    at: { state: true },
    redact: { state: true },
    asked: { state: true },
    meta: { state: true },
    subject: { state: true },
    action: { state: true },
    resource: { state: true },
    subjects: { state: true },
    actions: { state: true },
    resources: { state: true },
    context: { state: true },
    searchMode: { state: true },
    decision: { state: true },
    tree: { state: true },
    cells: { state: true },
    hits: { state: true },
    decided: { state: true },
    busy: { state: true },
    error: { state: true },
    copied: { state: true },
    scenarioYaml: { state: true }, // the Scenarios editor's text; null until loaded
    added: { state: true }, // the case just appended (feedback)
  };

  constructor() {
    super();
    this.mode = 'single';
    this.scenarioView = 'harness';
    this.ask = 'can';
    this.successfulOnly = false; // explain: only the steps that decided
    this.at = ''; // single check: decide as of this instant (datetime-local, local time); '' = now
    this.redact = false; // explain: types and reasons only, no identifiers
    this.asked = null; // the question the current result answers // single check: 'can' = a permission (what they can do), 'is' = a relation (what they are)
    /** @type {import('../types.js').Meta|null} */
    this.meta = null;
    this.subject = '';
    this.action = '';
    this.resource = '';
    this.subjects = '';
    this.actions = '';
    this.resources = '';
    this.context = '';
    this.searchMode = 'objects';
    this.decision = null;
    this.tree = null;
    this.cells = null;
    this.hits = null;
    this.decided = null;
    this.busy = false;
    this.error = '';
    this.copied = false;
    this.scenarioYaml = null;
    this.added = '';
  }

  // Appends a case to the Scenarios editor (loading the saved fixture
  // first when the editor was never opened) and switches to it.
  async _addToScenarios(caseYaml) {
    if (this.scenarioYaml === null) {
      const d = await this._wrap(() => api.scenarios(this.store));
      if (!d) return;
      this.scenarioYaml = d.yaml;
    }
    this.scenarioYaml = appendCase(this.scenarioYaml, caseYaml);
    this.added = caseYaml;
    this._go('scenarios', 'harness');
  }

  willUpdate(changed) {
    if (changed.has('store') && this.store) {
      this._clear();
      this.scenarioYaml = null;
      void this._load();
    }
    if (changed.has('sub')) {
      const [slug, view] = (this.sub ?? '').split('/');
      const mode = SLUG_MODES[slug] ?? 'single';
      if (mode !== this.mode) {
        this.mode = mode;
        this._clear();
      }
      this.scenarioView = view === 'edit-as-yaml' ? 'yaml' : 'harness';
    }
  }

  // Navigates to a mode (and, for the scenarios, a view): the URL is the
  // state, the app's router turns it into properties (sub) and history.
  _go(mode, view) {
    const rel = `stores/${this.store}/test/${MODE_SLUGS[mode]}${mode === 'scenarios' && view ? '/' + view : ''}`;
    this.dispatchEvent(new CustomEvent('navigate', { detail: rel, bubbles: true, composed: true }));
  }

  _clear() {
    this.decision = null;
    this.tree = null;
    this.cells = null;
    this.hits = null;
    this.decided = null;
    this.error = '';
  }

  _setResource(v) {
    this.resource = v;
    const rels = this._rels(v);
    if (rels.length && !rels.some((r) => r.name === this.action))
      this.action = (rels.find((r) => r.kind === 'permission') ?? rels[0]).name;
  }

  async _load() {
    const m = await run(this, () => api.meta(this.store));
    if (m) {
      this.meta = m;
      // A runnable starting point: a person-like subject, an object of another type, a can_* relation.
      if (!this.subject && m.subjects[0])
        this.subject = m.subjects.find((s) => /user|person|account/.test(s.split(':')[0])) ?? m.subjects[0];
      const subjectType = this.subject.split(':')[0] + ':';
      if (!this.resource && m.objects[0])
        this.resource = m.objects.find((o) => !o.startsWith(subjectType)) ?? m.objects[0];
      if (!this.action && m.relations[0])
        this.action = m.relations.find((r) => r.startsWith('can_')) ?? m.relations[0];
    }
  }

  _ctx() {
    if (!this.context.trim()) return undefined;
    try {
      return JSON.parse(this.context);
    } catch {
      PgcJson.report(this); // the field says what is wrong, next to itself
      throw new FieldInvalid();
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

  async _runSingle(e) {
    e?.preventDefault();
    this._clear();
    await this._wrap(async () => {
      const q = {
        subject: this.subject.trim(),
        action: this.action.trim(),
        resource: this.resource.trim(),
        context: this._ctx(),
      };
      const at = this.at ? new Date(this.at).toISOString() : '';
      const [c, x] = await Promise.all([
        api.check(this.store, { ...q, at }),
        at
          ? null
          : api.explain(this.store, { ...q, successful_only: this.successfulOnly, redact: this.redact }),
      ]);
      this.asked = { ...q, ask: this.ask, at };
      this.decision = c.allowed;
      this.tree = x ? (x.tree ?? x) : null; // explain_access wraps the resolution tree; none at another instant
    });
  }

  async _runMatrix(e) {
    e?.preventDefault();
    this._clear();
    await this._wrap(async () => {
      const r = await api.checkBatch(this.store, {
        subjects: parseList(this.subjects),
        actions: parseList(this.actions),
        resources: parseList(this.resources),
        context: this._ctx(),
      });
      this.cells = r.cells;
    });
  }

  async _runSearch(e) {
    e?.preventDefault();
    this._clear();
    await this._wrap(async () => {
      this.hits = await api.search(this.store, {
        mode: this.searchMode,
        subject: this.subject.trim(),
        action: this.action.trim(),
        resource: this.resource.trim(),
        context: this._ctx(),
      });
    });
  }

  async _runAsMe(e) {
    e?.preventDefault();
    this._clear();
    await this._wrap(async () => {
      this.decided = await api.decide(this.store, {
        action: this.action.trim(),
        resource: this.resource.trim(),
        context: this._ctx(),
      });
    });
  }

  // From a matrix cell or a search hit into the single check with its tree.
  _explainCell(subject, action, resource) {
    this.subject = subject;
    this.action = action;
    this.resource = resource;
    this.mode = 'single'; // set before navigating: the URL change then finds the mode in place and keeps the result
    this._go('single');
    void this._runSingle();
  }

  _sql() {
    const esc = (x) => `'${String(x ?? '').replace(/'/g, "''")}'`;
    const [st, sid] = this.subject.split(':');
    const [ot, oid] = this.resource.split(':');
    const args = [this.store, st, sid, this.action, ot, oid].map(esc);
    if (this.context.trim()) args.push(`${esc(this.context.trim())}::jsonb`);
    return `SELECT authz.explain_access(${args.join(', ')});`;
  }

  async _copy(text) {
    if (await copyText(text)) {
      this.copied = true;
      setTimeout(() => (this.copied = false), 1200);
    }
  }

  // Relations defined on the type of the current resource (or the type
  // typed into the resource field), with their kind.
  _rels(ref) {
    const typ = String(ref ?? this.resource).split(':')[0];
    return this.meta?.relations_by_type?.[typ] ?? [];
  }

  _kindOf(action, ref) {
    return this._rels(ref).find((r) => r.name === action);
  }

  // The action picker: grouped by kind when the type's relations are known,
  // a free input with completion otherwise.
  // The relations the current question allows: single mode asks one kind.
  _askedRels() {
    const rels = this._rels();
    if (this.mode !== 'single') return rels;
    return rels.filter((r) => (this.ask === 'can' ? r.kind === 'permission' : r.kind !== 'permission'));
  }

  _setAsk(ask) {
    this.ask = ask;
    this.decision = null;
    this.tree = null;
    const rels = this._askedRels();
    if (rels.length && !rels.some((r) => r.name === this.action)) this.action = rels[0].name;
  }

  // Every relation of the store with its kind (the union over all types),
  // for pickers that are not bound to one resource type.
  _allRels() {
    const seen = new Map();
    for (const list of Object.values(this.meta?.relations_by_type ?? {}))
      for (const r of list) if (!seen.has(r.name)) seen.set(r.name, { name: r.name, kind: r.kind });
    for (const name of this.meta?.relations ?? [])
      if (!seen.has(name)) seen.set(name, { name, kind: 'relation' });
    return [...seen.values()];
  }

  // A <select> of the suitable relations: the resource type's when it is
  // known (single mode narrows to the asked kind), else every relation of
  // the store — never a free text field, whose completion list only shows
  // what matches the text already typed.
  // Placeholders drawn from the store itself (its types, a subject and an
  // object that exist, its relations), so the example is one the person can
  // type as is — "user:alice / document:doc_1" means nothing in a store of
  // repos and orgs.
  _ph() {
    const m = this.meta ?? {};
    const types = m.types ?? [];
    const subjects = m.subjects ?? [];
    const objects = m.objects ?? [];
    const person =
      types.find((x) => /user|person|account|employee|member/.test(x)) ??
      subjects[0]?.split(':')[0] ??
      'user';
    const subject = subjects.find((x) => x.startsWith(person + ':')) ?? `${person}:alice`;
    const typed = String(this.resource ?? '').split(':')[0];
    const withRels = Object.keys(m.relations_by_type ?? {}).filter((x) => x !== person);
    const objectType =
      (typed && types.includes(typed) ? typed : null) ??
      withRels[0] ??
      types.find((x) => x !== person) ??
      'document';
    const object = objects.find((x) => x.startsWith(objectType + ':')) ?? `${objectType}:id-1`;
    const object2 = objects.filter((x) => x.startsWith(objectType + ':'))[1] ?? `${objectType}:id-2`;
    const subject2 = subjects.filter((x) => x.startsWith(person + ':'))[1] ?? `${person}:bob`;
    const rels = (m.relations_by_type?.[objectType] ?? []).map((r) => r.name);
    const action = rels.find((x) => x.startsWith('can_')) ?? rels[0] ?? 'can_read';
    const action2 = rels.find((x) => x !== action) ?? 'can_edit';
    return { person, subject, subject2, objectType, object, object2, action, action2 };
  }

  // Under a sentence form: what goes into its boxes, with examples taken
  // from this model (the boxes themselves carry no placeholder text).
  _shapesHelp(search = false) {
    const p = this._ph();
    return html`<p class="help">
      ${
        search
          ? t(
              'A type alone ({type}) or a subject/resource as type:id ({subject}, {object}); actions are the relations of the resource type ({action}). The lists suggest what the store knows.',
              { type: p.objectType, subject: p.subject, object: p.object, action: p.action },
            )
          : t(
              'Subjects and resources are type:id, e.g. {subject} and {object}; actions are the relations of the resource type, e.g. {action}. The lists suggest what the store knows.',
              { subject: p.subject, object: p.object, action: p.action },
            )
      }
    </p>`;
  }

  _actionPicker(onChange, anyType = false) {
    let rels = anyType ? this._rels() : this._askedRels();
    if (!rels.length) rels = this._allRels();
    if (!rels.length)
      return html`<input
        class="mono"
        list="dl-actions"
        required
        .value=${this.action}
        @input=${onChange}
        style="width:11rem"
      />`;
    if (this.action && !rels.some((r) => r.name === this.action))
      rels = [...rels, { name: this.action, kind: 'relation' }];
    const perms = rels.filter((r) => r.kind === 'permission');
    const plain = rels.filter((r) => r.kind !== 'permission');
    const opt = (r) =>
      html`<option value=${r.name} ?selected=${r.name === this.action}>
        ${r.name}${r.kind !== 'permission' && r.derived ? ' ·' : ''}
      </option>`;
    return html`<select
      class="mono"
      required
      .value=${this.action}
      @change=${onChange}
      title=${t('· = also inherited from related objects')}
    >
      ${perms.length ? html`<optgroup label=${t('What they can do (permissions)')}>${perms.map(opt)}</optgroup>` : nothing}
      ${plain.length ? html`<optgroup label=${t('What they are (relations)')}>${plain.map(opt)}</optgroup>` : nothing}
    </select>`;
  }

  // "is X allowed can_read on Y?" for a permission, "is X a viewer of Y?" for a relation.
  _sentenceWords() {
    return this.ask === 'is' ? { before: t('a'), after: t('of') } : { before: t('allowed'), after: t('on') };
  }

  // Hints: a wildcard typed as the subject; a "no" on a relation, with the
  // permissions of the type as the next click.
  _hints(denied) {
    const out = [];
    if (this.subject.trim().endsWith(':*'))
      out.push(
        html`<p class="notice">
          ${t('* is a grant to everyone of a type, not a subject. Check a concrete subject (for example user:nobody) to see what everyone gets.')}
        </p>`,
      );
    if (denied && this.ask === 'is') {
      const perms = this._rels().filter((r) => r.kind === 'permission');
      out.push(
        html`<p class="notice">
          ${t('{action} is a relation: what a subject IS on this object, held by a tuple or inherited. To ask what they may do here, check a permission:', { action: this.action })}
          ${perms.map(
            (r) =>
              html`<button
                class="sm"
                @click=${() => {
                  this.ask = 'can';
                  this.action = r.name;
                  void this._runSingle();
                }}
              >
                ${r.name}
              </button>`,
          )}
        </p>`,
      );
    }
    if (denied && this.ask === 'can' && this._kindOf(this.action)) {
      const rels = this._rels().filter((r) => r.kind !== 'permission');
      out.push(
        html`<p class="help">
          ${t('To see what the subject IS on this object instead (its relations), switch to "Is a":')}
          ${rels.map(
            (r) =>
              html`<button
                class="sm"
                @click=${() => {
                  this.ask = 'is';
                  this.action = r.name;
                  void this._runSingle();
                }}
              >
                ${r.name}
              </button>`,
          )}
        </p>`,
      );
    }
    return out;
  }

  _datalists() {
    const m = this.meta;
    return html` <datalist id="dl-subjects">
        ${(m?.subjects ?? []).map((s) => html`<option value=${s}></option>`)}
      </datalist>
      <datalist id="dl-actions">
        ${(m?.relations ?? []).map((s) => html`<option value=${s}></option>`)}
      </datalist>
      <datalist id="dl-objects">
        ${(m?.objects ?? []).map((s) => html`<option value=${s}></option>`)}
      </datalist>
      <datalist id="dl-types">${(m?.types ?? []).map((s) => html`<option value=${s}></option>`)}</datalist>`;
  }

  // When to decide: now, or any other instant — the audit trail replayed to
  // it, with expiries applied against it. Future instants show what expiry
  // and nothing else will change; the tree is live only.
  // The test policy (console store permissions, enforced by the BFF): what
  // this person may ask beyond their own access. The UI mirrors it so the
  // forms only offer what will be allowed.
  _policy() {
    /** @type {import('../types.js').Capabilities} */
    const c = this.caps ?? {};
    return {
      others: !!c.can_test_others,
      explainFull: !!c.can_test_explain_full,
      search: !!c.can_test_search,
      history: !!c.can_test_history,
    };
  }

  _selfSubject() {
    // the store's people type: the suggestion that looks like a person, else user
    const types = (this.meta?.subjects ?? []).map((x) => x.split(':')[0]);
    const type = types.find((x) => /user|person|account|employee|member/.test(x)) ?? 'user';
    return `${type}:${this.me?.username ?? ''}`;
  }

  _policyNote(text) {
    return html`<span
      class="help policy-note"
      title=${t('Set by the console store: ask a store owner for a broader role.')}
      >${t('policy')}: ${text}</span
    >`;
  }

  _atField() {
    if (!this._policy().history) return nothing;
    const pad = (n) => String(n).padStart(2, '0');
    const local = (d) =>
      `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
    const preset = (ms) => {
      this.at = ms === null ? '' : local(new Date(Date.now() + ms));
      if (this.decision !== null) void this._runSingle();
    };
    return html`<details class="at-row" ?open=${!!this.at}>
      <summary class="help">
        ${t('Point in time')}:
        ${this.at ? html`<b>${fmtTime(new Date(this.at).toISOString())}</b> (${fmtRelative(new Date(this.at).toISOString())})` : t('now')}
        ${help('Decide as of another instant: the audit trail replayed to it (tuples and model as they were), with expiries applied against it. A future instant shows what expiry will change. Empty = now, live. The resolution tree is only available for now.')}
      </summary>
      <div class="actions">
        <input type="datetime-local" .value=${this.at} @input=${(e) => (this.at = e.target.value)} />
        <span class="seg">
          <button type="button" class="sm" @click=${() => preset(null)}>${t('now')}</button>
          <button type="button" class="sm" @click=${() => preset(3600e3)}>+1 h</button>
          <button type="button" class="sm" @click=${() => preset(86400e3)}>+1 ${t('day')}</button>
          <button type="button" class="sm" @click=${() => preset(7 * 86400e3)}>+1 ${t('week')}</button>
          <button type="button" class="sm" @click=${() => preset(30 * 86400e3)}>+1 ${t('month')}</button>
          <button type="button" class="sm" @click=${() => preset(365 * 86400e3)}>+1 ${t('year')}</button>
        </span>
      </div>
    </details>`;
  }

  // The explain options, chosen with the question: they shape the tree.
  _explainOptions() {
    return explainOptions({
      successfulOnly: this.successfulOnly,
      redact: this.redact,
      explainFull: this._policy().explainFull,
      policyNote: this._policyNote(t('identifiers are always redacted for you')),
      onChange: ({ successfulOnly, redact }) => {
        this.successfulOnly = successfulOnly;
        this.redact = redact;
        if (this.decision !== null) void this._runSingle();
      },
    });
  }

  _timeBound() {
    const found = [];
    const walk = (n) => {
      if (!n) return;
      if ((n.allowed === true || n.result === true) && n.matched_tuple) found.push(n);
      (n.children ?? []).forEach(walk);
    };
    walk(this.tree);
    const granting = found.filter((n) => n.result === true || n.allowed === true);
    if (!granting.length) return null;
    const bounded = granting.filter((n) => n.expires_at);
    if (!bounded.length) return null;
    const open = granting.length > bounded.length;
    const until = bounded.map((n) => new Date(n.expires_at).getTime()).sort((a, b) => b - a)[0];
    return {
      open,
      until: new Date(until).toISOString(),
      tuples: bounded.map((n) => ({ tuple: n.matched_tuple, expires_at: n.expires_at })),
    };
  }

  _timeBoundBadge() {
    const tb = this._timeBound();
    if (!tb) return nothing;
    const when = `${fmtTime(tb.until)} · ${fmtRelative(tb.until)}`;
    return html`<span
      class="badge warn"
      title=${tb.tuples.map((x) => `${x.tuple} — ${fmtTime(x.expires_at)}`).join('\n')}
    >
      ⏱
      ${tb.open ? t('partly time-bound, a path expires {when}', { when }) : t('time-bound, until {when}', { when })}
    </span>`;
  }

  // The question a result answers, as a caption: who, what, on which object.
  _resultCaption() {
    const a = this.asked;
    if (!a) return nothing;
    const text =
      a.ask === 'is'
        ? t('Is {subject} a {action} of {resource}?', a)
        : t('Is {subject} allowed {action} on {resource}?', a);
    return html`<div class="result-caption">
      <span class="mono">${text}</span>
      ${a.at ? html`<span class="badge warn">${t('at')} ${fmtTime(a.at)} · ${fmtRelative(a.at)}</span>` : html`<span class="badge muted">${t('now')}</span>`}
      ${this.successfulOnly ? html`<span class="badge muted">${t('deciding path only')}</span>` : nothing}
      ${this.redact ? html`<span class="badge muted">${t('redacted')}</span>` : nothing}
    </div>`;
  }

  _contextField() {
    return html`<details style="margin-top:var(--s-3)">
      <summary class="help">${t('Request context (JSON, for conditions)')}</summary>
      <span class="help"
        >${t('What a check would send for the conditions to read, e.g. {"ip": "10.1.2.3", "mfa": true}.')}</span
      >
      <pgc-json
        rows="3"
        testid="test-input-context"
        .value=${this.context}
        @json-input=${(e) => (this.context = e.detail.text)}
      ></pgc-json>
    </details>`;
  }

  _single() {
    return html`<form class="card" @submit=${this._runSingle}>
        <div class="toolbar">
          <h3>
            ${this.ask === 'is' ? t('Is the subject a …?') : t('Can the subject do it?')}
            ${help('Decided by the engine directly, for any subject of the store — the tester\'s question "would bob be allowed?".')}
          </h3>
          <span class="check-type"
            ><span class="muted">${t('Check type')}</span>
            <div class="seg" role="radiogroup" aria-label=${t('Check type')}>
              <button
                type="button"
                class=${this.ask === 'can' ? 'active' : ''}
                title=${t('Check a permission: what the subject can do (can_read, can_share)')}
                @click=${() => this._setAsk('can')}
              >
                ${t('Can do')}
              </button>
              <button
                type="button"
                class=${this.ask === 'is' ? 'active' : ''}
                title=${t('Check a relation: what the subject is on the object (viewer, editor, owner)')}
                @click=${() => this._setAsk('is')}
              >
                ${t('Is a')}
              </button>
            </div></span
          >
        </div>
        <div class="sentence">
          <span class="muted">${t('is')}</span>
          <input
            class="mono id"
            list="dl-subjects"
            required
            .value=${this._policy().others ? this.subject : (this.subject = this._selfSubject())}
            ?readonly=${!this._policy().others}
            title=${this._policy().others ? '' : t('The test policy limits you to your own access.')}
            @input=${(e) => (this.subject = e.target.value)}
          />
          <span class="muted">${this._sentenceWords().before}</span>
          ${this._actionPicker((e) => (this.action = e.target.value))}
          <span class="muted">${this._sentenceWords().after}</span>
          <input
            class="mono id"
            list="dl-objects"
            required
            .value=${this.resource}
            @input=${(e) => this._setResource(e.target.value)}
          />
          <span class="muted">?</span>
          <button class="primary" ?disabled=${this.busy}>${t('Check')}</button>
        </div>
        ${this._shapesHelp()} ${this._atField()} ${this._explainOptions()} ${this._contextField()}
      </form>
      ${this._hints(this.decision === false)}
      ${
        this.decision !== null
          ? html`<section class="card">
              ${this._resultCaption()}
              <div class="toolbar">
                <span class="decision ${this.decision ? 'allow' : 'deny'}"
                  >${this.decision ? '✔ ' + t('allowed') : '✘ ' + t('denied')}</span
                >
                <div class="actions">
                  <button class="sm" @click=${() => this._copy(this._sql())}>
                    ${this.copied ? t('Copied') : t('Copy as SQL')}
                  </button>
                  <button class="sm" @click=${() => this._copy(PgcExplainTree.toText(this.tree))}>
                    ${t('Copy resolution')}
                  </button>
                  ${
                    this.asked && !this.asked.at
                      ? html`<button
                          class="sm"
                          title=${t('Append this check with its outcome as a case of the saved scenarios (tests.authz.yaml).')}
                          data-testid="test-add-scenario"
                          @click=${() =>
                            this._addToScenarios(
                              checkCaseYAML({
                                subject: this.asked.subject,
                                action: this.asked.action,
                                resource: this.asked.resource,
                                decision: this.decision,
                                context: this.asked.context,
                              }),
                            )}
                        >
                          ${t('Add to scenarios')}
                        </button>`
                      : nothing
                  }
                </div>
              </div>
              <div class="decided-by">
                <span class="badge">${t('decided by')}: ${t('engine')}</span>
                ${this._timeBoundBadge()}
                ${help('Engine only: the graph resolution below. Use "As me via pgauthzd" to see the full path including OPA. A ⏱ badge means a granting tuple on the deciding path has an expiry; the tree marks each such tuple.')}
              </div>
              ${this.tree ? html`<pgc-explain-tree .node=${this.tree} root></pgc-explain-tree>` : html`<p class="help">${t('Decided by replaying the audit trail to that instant; the resolution tree is only available for now.')}</p>`}
            </section>`
          : nothing
      }`;
  }

  _matrix() {
    const cells = this.cells;
    let grid = nothing;
    if (cells) {
      const subjects = [...new Set(cells.map((c) => c.subject))];
      const actions = [...new Set(cells.map((c) => c.action))];
      const resources = [...new Set(cells.map((c) => c.resource))];
      const cols = actions.flatMap((a) => resources.map((r) => [a, r]));
      const at = (s, a, r) => cells.find((c) => c.subject === s && c.action === a && c.resource === r);
      grid = html`<section class="card">
        <h3>
          ${t2('{n} decision', '{n} decisions', cells.length)}
          ${help('Rows are subjects, columns are action × resource. Click a cell for its resolution tree.')}
        </h3>
        <div class="table-wrap">
          <table class="matrix">
            <thead>
              <tr>
                <th></th>
                ${cols.map(([a, r]) => html`<th class="colh">${a}<br /><span class="muted">${r}</span></th>`)}
              </tr>
            </thead>
            <tbody>
              ${subjects.map(
                (s) =>
                  html`<tr>
                    <th class="rowh">${s}</th>
                    ${cols.map(([a, r]) => {
                      const c = at(s, a, r);
                      return html`<td
                        class="cell ${c?.allowed ? 'allow' : 'deny'}"
                        title=${t('explain')}
                        @click=${() => this._explainCell(s, a, r)}
                      >
                        ${c?.allowed ? '✔' : '✘'}
                      </td>`;
                    })}
                  </tr>`,
              )}
            </tbody>
          </table>
        </div>
      </section>`;
    }
    return html`<form class="card form matrix-form" @submit=${this._runMatrix}>
        <h3 class="wide">
          ${t('Many at once')}
          ${help('One engine call (check_access_batch) over the cross product of the three lists; one per line or comma-separated. Up to 2000 decisions.')}
        </h3>
        <label class="field ids"
          ><span
            >${t('Subjects')}
            ${help('type:id, one per line or comma-separated, e.g. {a} and {b}.', { a: this._ph().subject, b: this._ph().subject2 })}</span
          ><textarea
            class="list"
            required
            spellcheck="false"
            .value=${this._policy().others ? this.subjects : (this.subjects = this._selfSubject())}
            ?readonly=${!this._policy().others}
            title=${this._policy().others ? '' : t('The test policy limits you to your own access.')}
            @input=${(e) => (this.subjects = e.target.value)}
          ></textarea>
          ${this._policy().others ? nothing : this._policyNote(t('only your own access'))}
        </label>
        <label class="field acts"
          ><span
            >${t('Actions')}
            ${help('Relations or permissions of the resource type, e.g. {a} and {b}.', { a: this._ph().action, b: this._ph().action2 })}</span
          ><textarea
            class="list"
            required
            spellcheck="false"
            .value=${this.actions}
            @input=${(e) => (this.actions = e.target.value)}
          ></textarea>
        </label>
        <label class="field ids"
          ><span
            >${t('Resources')}
            ${help('type:id, one per line or comma-separated, e.g. {a} and {b}.', { a: this._ph().object, b: this._ph().object2 })}</span
          ><textarea
            class="list"
            required
            spellcheck="false"
            .value=${this.resources}
            @input=${(e) => (this.resources = e.target.value)}
          ></textarea>
        </label>
        <div class="wide">${this._contextField()}</div>
        <div class="actions wide">
          <button class="primary" ?disabled=${this.busy}>${t('Check all')}</button>
        </div>
      </form>
      ${grid}`;
  }

  _search() {
    const objects = this.searchMode === 'objects';
    const h = this.hits;
    return html`<form class="card" @submit=${this._runSearch}>
        <h3>
          ${t('Find the candidates')}
          ${help('Reverse search over the graph: list_objects answers "which objects can this subject reach?", list_subjects answers "who can reach this object?". Paged by keyset; wildcards are marked.')}
        </h3>
        <div class="seg" style="margin-bottom:var(--s-3)">
          <button
            type="button"
            class=${objects ? 'active' : ''}
            @click=${() => (this.searchMode = 'objects')}
          >
            ${t('Which objects can a subject reach?')}
          </button>
          <button
            type="button"
            class=${!objects ? 'active' : ''}
            @click=${() => (this.searchMode = 'subjects')}
          >
            ${t('Who can reach an object?')}
          </button>
        </div>
        <div class="sentence">
          ${
            objects
              ? html`<span class="muted">${t('which')}</span>
                  <input
                    class="mono"
                    list="dl-types"
                    required
                    .value=${this.resource.includes(':') ? '' : this.resource}
                    @input=${(e) => (this.resource = e.target.value)}
                    style="width:10rem"
                  />
                  <span class="muted">${t('can')}</span>
                  <input
                    class="mono id"
                    list="dl-subjects"
                    required
                    .value=${this.subject}
                    @input=${(e) => (this.subject = e.target.value)}
                  />`
              : html`<span class="muted">${t('which')}</span>
                  <input
                    class="mono"
                    list="dl-types"
                    required
                    .value=${this.subject.includes(':') ? '' : this.subject}
                    @input=${(e) => (this.subject = e.target.value)}
                    style="width:10rem"
                  />
                  <span class="muted">${t('can')}</span>`
          }
          ${this._actionPicker((e) => (this.action = e.target.value), true)}
          ${
            objects
              ? nothing
              : html`<span class="muted">${t('on')}</span>
                  <input
                    class="mono id"
                    list="dl-objects"
                    required
                    .value=${this.resource}
                    @input=${(e) => (this.resource = e.target.value)}
                  />`
          }
          <span class="muted">?</span>
          <button class="primary" ?disabled=${this.busy}>${t('Search')}</button>
        </div>
        ${this._shapesHelp(true)} ${this._contextField()}
      </form>
      ${
        h
          ? html`<section class="card">
              <div class="toolbar">
                <h3>
                  ${t2('{n} result', '{n} results', h.hits.length)}${h.next ? ' ' + t('(more available — narrow the question)') : ''}
                </h3>
                ${
                  objects && !h.next
                    ? html`<button
                        class="sm"
                        title=${t('Append this search with its results as a list_objects case of the saved scenarios.')}
                        data-testid="test-add-scenario-search"
                        @click=${() =>
                          this._addToScenarios(
                            listCaseYAML({
                              subject: this.subject.trim(),
                              action: this.action.trim(),
                              type: this.resource.trim(),
                              ids: h.hits.map((x) => x.id),
                              context: this._ctx(),
                            }),
                          )}
                      >
                        ${t('Add to scenarios')}
                      </button>`
                    : nothing
                }
              </div>
              ${
                h.hits.length
                  ? html`<div class="table-wrap">
                      <table class="hits">
                        <thead>
                          <tr>
                            <th class="num">#</th>
                            <th>${objects ? t('Object') : t('Subject')}</th>
                            <th>
                              ${t('Granted')}
                              ${help('* marks a wildcard: the grant goes to everyone of this type, not to this one specifically.')}
                            </th>
                            <th></th>
                          </tr>
                        </thead>
                        <tbody>
                          ${h.hits.map(
                            (x, i) =>
                              html`<tr class=${x.wildcard ? 'wild' : ''}>
                                <td class="num muted">${i + 1}</td>
                                <td class="mono">
                                  ${objects ? `${this.resource}:${x.id}` : `${this.subject}:${x.id}`}
                                </td>
                                <td>
                                  ${x.wildcard ? html`<span class="badge warn">${t('everyone of this type')} *</span>` : html`<span class="badge ok">${t('specifically')}</span>`}
                                </td>
                                <td>
                                  <button
                                    class="sm"
                                    @click=${() =>
                                      objects
                                        ? this._explainCell(
                                            this.subject,
                                            this.action,
                                            `${this.resource}:${x.id}`,
                                          )
                                        : this._explainCell(
                                            `${this.subject}:${x.id}`,
                                            this.action,
                                            this.resource,
                                          )}
                                  >
                                    ${t('Explain')}
                                  </button>
                                </td>
                              </tr>`,
                          )}
                        </tbody>
                      </table>
                    </div>`
                  : html`<div class="empty">${t('Nothing matches.')}</div>`
              }
            </section>`
          : nothing
      }`;
  }

  _asMe() {
    const d = this.decided;
    /** @type {import('../types.js').DecideDetail} */
    const detail = d?.detail ?? {};
    const hooks = detail.hooks_loaded ?? [];
    const denials = detail.hook_denials ?? [];
    const viaOPA = detail.via === 'opa' || 'hooks_loaded' in detail || detail.reason === 'policy_hook';
    return html`<form class="card" @submit=${this._runAsMe}>
        <h3>
          ${t('The real path, as yourself')}
          ${help("Your session token goes to the decision instance of pgauthzd with X-PGAuthz-Detail, exactly like an application's request. The subject is you (pgauthzd and OPA take it from the token), so this mode cannot ask about other people.")}
        </h3>
        <div class="sentence">
          <span class="muted">${t('am I')}</span>
          <span class="badge mono">${this.me?.subject ?? '…'}</span>
          <span class="muted">${t('allowed')}</span>
          ${this._actionPicker((e) => (this.action = e.target.value), true)}
          <span class="muted">${t('on')}</span>
          <input
            class="mono id"
            list="dl-objects"
            required
            .value=${this.resource}
            @input=${(e) => (this.resource = e.target.value)}
          />
          <span class="muted">?</span>
          <button class="primary" ?disabled=${this.busy}>${t('Decide')}</button>
        </div>
        ${this._shapesHelp()} ${this._contextField()}
      </form>
      ${
        d
          ? html`<section class="card">
              <div class="toolbar">
                <span class="decision ${d.decision ? 'allow' : 'deny'}"
                  >${d.decision ? '✔ ' + t('allowed') : '✘ ' + t('denied')}</span
                >
                <span class="muted mono">${t('for')} ${d.subject?.type}:${d.subject?.id}</span>
              </div>
              <div class="decided-by">
                <span class="badge">${t('decided by')}: ${t('engine')}${viaOPA ? ' + OPA' : ''}</span>
                ${detail.state ? html`<span class="badge ${detail.state === 'allow' ? 'ok' : detail.state === 'deny' ? 'deny' : 'warn'}">${detail.state}</span>` : nothing}
                ${detail.reason ? html`<span class="badge muted mono">${detail.reason}</span>` : nothing}
                ${hooks.map((hk) => html`<span class="badge accent mono" title=${t('policy hook consulted')}>${hk}</span>`)}
                ${help('What took part: the engine always; OPA when the decision instance fronts it (hooks_loaded present); each badge is a policy hook that was consulted. A veto lists the hook that denied.')}
              </div>
              ${
                denials.length
                  ? html`<div class="error">
                      ${t('Denied by policy hook')}:
                      ${denials.map((x) => html`<div class="mono">${x.hook} — ${x.message}</div>`)}
                    </div>`
                  : nothing
              }
              ${detail.missing_context?.length ? html`<p class="notice">${t('Conditional: the request lacks')} <span class="mono">${detail.missing_context.join(', ')}</span></p>` : nothing}
              <details>
                <summary class="help">${t('Raw detail')}</summary>
                <pre class="code">${highlightJSON(JSON.stringify(d, null, 2))}</pre>
              </details>
            </section>`
          : nothing
      }`;
  }

  render() {
    const modes = MODES.filter(([id]) => id !== 'asme' || this.me?.decision_url_configured !== false);
    return html`
      ${this._datalists()}
      <div class="toolbar">
        <div class="seg">
          ${modes.map(([id, label, tip]) => {
            const locked = id === 'search' && !this._policy().search;
            return locked
              ? html`<button
                  class=${this.mode === id ? 'active' : ''}
                  disabled
                  title=${t('The test policy does not let you enumerate objects or subjects (needs can_test_search).')}
                >
                  ${t(label)} 🔒
                </button>`
              : html`<a
                  class="btn ${this.mode === id ? 'active' : ''}"
                  href=${`stores/${this.store}/test/${MODE_SLUGS[id]}`}
                  title=${t(tip)}
                  data-testid=${`test-mode-${id}`}
                  >${t(label)}</a
                >`;
          })}
        </div>
      </div>
      ${this.error ? errorBox(this.error) : nothing}
      ${
        this.mode === 'matrix'
          ? this._matrix()
          : this.mode === 'search'
            ? this._search()
            : this.mode === 'asme'
              ? this._asMe()
              : this.mode === 'scenarios'
                ? html`<pgc-scenarios
                    .store=${this.store}
                    .caps=${this.caps}
                    .meta=${this.meta}
                    .yaml=${this.scenarioYaml}
                    view=${this.scenarioView}
                    @yaml-change=${(e) => (this.scenarioYaml = e.detail)}
                  ></pgc-scenarios>`
                : this._single()
      }
    `;
  }
}
customElements.define('pgc-test', PgcTest);
