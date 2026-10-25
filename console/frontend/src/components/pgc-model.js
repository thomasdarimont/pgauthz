import { html, nothing } from 'lit';
import { PgcElement, help, errorBox, loading } from '../base.js';
import { api } from '../api.js';
import { t } from '../i18n.js';
import { run, copyText, forbiddenText, byOrder, statusBadge, fmtTime, fmtRelative } from '../util.js';
import { selectionCell, selectAllCell, removeBar, clearSelection } from './pgc-select.js';
import { highlightDSL, highlightSQL, highlightJSON } from '../highlight.js';
import { PgcJson } from './pgc-json.js';

// Model tab. Three read views of the SAME live model — DSL (OpenFGA-style,
// lossy), JSON (the registry's canonical export) and SQL (the engine calls
// that rebuild it; copy-and-run) — plus the structured editor, whose
// vocabulary is exactly the engine's model_* API. Edits are live: each one
// is a call as you, audited and recorded. Removal goes through selection and
// a confirmation, one transaction for all selected items.
export class PgcModel extends PgcElement {
  static properties = {
    store: { type: String },
    section: { type: String }, // the active Structure section, from the URL (stores/<store>/model/<section>)
    caps: { attribute: false },
    info: { attribute: false },
    m: { state: true },
    view: { state: true },
    busy: { state: true },
    error: { state: true },
    copied: { state: true },
    edit: { state: true },
    form: { state: true },
    selected: { state: true },
    confirming: { state: true },
    draft: { state: true },
    dragging: { state: true },
    dslEdit: { state: true },
    defOpen: { state: true }, // the definition card, collapsed by default (remembered per browser)
    dslText: { state: true },
    dslReport: { state: true },
    detail: { state: true }, // keys of the rows whose definition is expanded
    filters: { state: true }, // per-section filter text (types, relations, rules, restrictions, conditions, gates)
    sorts: { state: true }, // per-section sort: { key, dir } (relations keep their stored order)
    tryCond: { state: true }, // per-condition try-it state (contexts, result)
    renaming: { state: true }, // namespace being renamed
    renameTo: { state: true },
  };

  constructor() {
    super();
    /** @type {import('../types.js').ModelResponse|null} */
    this.m = null;
    this.view = 'dsl';
    this.busy = false;
    this.error = '';
    this.copied = false;
    this.edit = null; // which add-form is open
    this.form = {};
    this.selected = new Set(); // keys: type:<name> | rule:<id> | restriction:<id> | condition:<name> | gate:… | grant:<type>.<relation>
    this.confirming = false;
    this.dslEdit = false; // the DSL view as an editor
    this.dslText = '';
    /** @type {import('../types.js').DSLReport|null} */
    this.dslReport = null; // the importer's report after an apply
    this.defOpen = false;
    try {
      this.defOpen = localStorage.getItem('pgc_model_def_open') === '1';
    } catch {
      /* storage unavailable */
    }
    this.detail = new Set();
    this.renaming = null;
    this.renameTo = '';
    this.filters = {};
    this.sorts = {};
    this.tryCond = {};
    this.draft = {}; // unsaved drag order per group: { permission: [names], relation: [names] }
    this.dragging = null; // { group, name } while a row is being dragged
  }

  willUpdate(changed) {
    if (changed.has('store') && this.store) void this._load();
    if (changed.has('section') && this.section) {
      try {
        localStorage.setItem('pgc_model_section', this.section);
      } catch {
        /* storage unavailable */
      }
    }
  }

  async _load() {
    const m = await run(this, () => api.model(this.store));
    if (m) {
      this.m = m;
      clearSelection(this);
    }
  }

  async _copy() {
    const text = this.view === 'json' ? JSON.stringify(this.m.json, null, 2) : this.m[this.view];
    if (await copyText(text)) {
      this.copied = true;
      setTimeout(() => (this.copied = false), 1200);
    }
  }

  // A starting point for an empty store: the smallest useful model.
  static STARTER_DSL = `type user

type team
  relations
    define member: [user]

type document
  relations
    define owner: [user]
    define viewer: [user, team#member, user:*]
    define can_read: viewer or owner
    define can_write: owner
`;

  _openDSL() {
    const current = (this.m.dsl ?? '').replace(/^store:.*\n\n?/, '');
    this.dslText = this.m.json.types.length ? current : PgcModel.STARTER_DSL;
    this.dslReport = null;
    this.dslEdit = true;
    this.view = 'dsl';
  }

  async _applyDSL() {
    const r = await this._wrap(() => api.modelDSL(this.store, this.dslText));
    if (r) {
      this.dslReport = r;
      this.dslEdit = false;
      await this._load();
      this.dispatchEvent(new CustomEvent('changed'));
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

  async _op(op, body) {
    const ok = await this._wrap(() => api.modelEdit(this.store, op, body));
    if (ok) {
      this.edit = null;
      this.form = {};
      await this._load();
      this.dispatchEvent(new CustomEvent('changed'));
    }
  }

  // Selected keys → batch operations, dependants first (rules and type
  // restrictions before types; conditions before types that might need them).
  _selectedOps() {
    const order = { grant: 0, constraint: 0, gate: 1, rule: 2, restriction: 3, condition: 4, type: 5 };
    return [...this.selected]
      .map((k) => {
        const i = k.indexOf(':');
        return { kind: k.slice(0, i), id: k.slice(i + 1) };
      })
      .sort((a, b) => order[a.kind] - order[b.kind])
      .map(({ kind, id }) =>
        kind === 'rule'
          ? { op: 'remove_rule', id: Number(id) }
          : kind === 'restriction'
            ? { op: 'remove_restriction', id: Number(id) }
            : kind === 'condition'
              ? { op: 'remove_condition', name: id }
              : kind === 'gate'
                ? { op: 'remove_gate', ...this._gateRef(id) }
                : kind === 'grant'
                  ? { op: 'remove_grant_rule', ...this._grantRef(id) }
                  : kind === 'constraint'
                    ? { op: 'remove_relation_constraint', ...this._grantRef(id) }
                    : { op: 'remove_type', name: id },
      );
  }

  // Grant rule keys are "grant:<object_type>.<relation>" (one rule per pair).
  _grantRef(id) {
    const [object_type, relation] = id.split('.');
    return { object_type, relation };
  }

  _grantKey(g) {
    return `grant:${g.object_type}.${g.relation}`;
  }

  // Relation constraint keys are "constraint:<object_type>.<relation>" (one per pair).
  _constraintKey(c) {
    return `constraint:${c.object_type}.${c.relation}`;
  }

  // Gate keys are "gate:<object_type>.<relation>/<name>".
  _gateRef(id) {
    const [left, name] = id.split('/');
    const [object_type, relation] = left.split('.');
    return { object_type, relation, name };
  }

  _gateKey(g) {
    return `gate:${g.object_type}.${g.relation}/${g.name}`;
  }

  _describe(k) {
    if (k.startsWith('gate:')) {
      const r = this._gateRef(k.slice(5));
      return `${t('gate')}: ${r.object_type}.${r.relation} — ${r.name}`;
    }
    if (k.startsWith('grant:')) {
      const r = this._grantRef(k.slice(6));
      return `${t('grant rule')}: ${r.object_type}.${r.relation}`;
    }
    if (k.startsWith('constraint:')) {
      const r = this._grantRef(k.slice(11));
      return `${t('relation constraint')}: ${r.object_type}.${r.relation}`;
    }
    const i = k.indexOf(':');
    const kind = k.slice(0, i);
    const id = k.slice(i + 1);
    if (kind === 'rule') {
      const r = this.m.rules.find((x) => String(x.id) === id);
      if (!r) return k;
      const def =
        r.rule_type === 'direct'
          ? 'direct'
          : r.rule_type === 'computed'
            ? r.computed_relation
            : `${r.tupleset_computed} from ${r.tupleset_relation}`;
      return `${t('rule')}: ${r.object_type}.${r.relation} ← ${def}`;
    }
    if (kind === 'restriction') {
      const x = this.m.restrictions.find((y) => String(y.id) === id);
      if (!x) return k;
      return `${t('type restriction')}: ${x.object_type}.${x.relation} ← ${x.allowed_user_type}${x.allowed_user_relation ? '#' + x.allowed_user_relation : ''}`;
    }
    return `${t(kind)}: ${id}`;
  }

  async _removeSelected() {
    const ops = this._selectedOps();
    const ok = await this._wrap(() => api.modelBatch(this.store, ops));
    if (ok) {
      await this._load();
      this.dispatchEvent(new CustomEvent('changed'));
    }
  }

  _set(k) {
    return (e) =>
      (this.form = { ...this.form, [k]: e.target.type === 'checkbox' ? e.target.checked : e.target.value });
  }

  _submit(op) {
    return (e) => {
      e.preventDefault();
      const f = { ...this.form };
      delete f.editing;
      if (f.group_id !== undefined) f.group_id = Number(f.group_id) || 0;
      for (const k of ['max_direct', 'max_effective']) {
        if (f[k] === undefined) continue;
        f[k] = String(f[k]).trim() === '' ? null : Number(f[k]);
      }
      if (f.required_context) {
        try {
          f.required_context = JSON.parse(f.required_context);
        } catch {
          PgcJson.report(this);
          return;
        }
      }
      if (f.labels_text !== undefined) {
        f.labels = String(f.labels_text)
          .split(',')
          .map((x) => x.trim())
          .filter(Boolean);
        delete f.labels_text;
      }
      if (f.payload_schema_text !== undefined) {
        const text = String(f.payload_schema_text).trim();
        try {
          f.payload_schema = text ? JSON.parse(text) : null;
        } catch {
          PgcJson.report(this);
          return;
        }
        delete f.payload_schema_text;
      }
      this._op(op, f);
    };
  }

  _toggleType(ty, on) {
    const cur = new Set(this.form.object_types ?? []);
    if (on) cur.add(ty);
    else cur.delete(ty);
    this.form = { ...this.form, object_types: [...cur] };
  }

  // "+ relation" in one go: register the relation, then per selected object
  // type the rule that defines it there and, for a relation, the type
  // restrictions that bound its tuples — one batch, one transaction.
  _submitRelation = (e) => {
    e.preventDefault();
    const f = this.form;
    const kind = f.kind ?? 'relation';
    const types = f.object_types ?? [];
    const ops = [{ op: 'add_relation', name: f.name, description: f.description ?? '', kind }];
    const list = (text) =>
      String(text ?? '')
        .split(',')
        .map((x) => x.trim())
        .filter(Boolean);
    // A userset in "accepts" (team#member) names a relation that must exist;
    // register the ones that do not yet, as plain relations.
    const known = new Set(this._names('relations').concat([f.name]));
    if (kind !== 'permission')
      for (const acc of list(f.accepts)) {
        const ur = acc.replace(/:\*$/, '').split('#')[1];
        if (ur && !known.has(ur)) {
          ops.push({ op: 'add_relation', name: ur, kind: 'relation' });
          known.add(ur);
        }
      }
    for (const ty of types) {
      if (kind === 'permission') {
        for (const rel of list(f.derived_from))
          ops.push({
            op: 'add_rule',
            object_type: ty,
            relation: f.name,
            rule_type: 'computed',
            computed_relation: rel,
          });
      } else {
        ops.push({ op: 'add_rule', object_type: ty, relation: f.name, rule_type: 'direct' });
        for (const acc of list(f.accepts)) {
          const wildcard = acc.endsWith(':*');
          const base = wildcard ? acc.slice(0, -2) : acc;
          const [ut, ur] = base.split('#');
          if (wildcard)
            ops.push({
              op: 'add_restriction',
              object_type: ty,
              relation: f.name,
              allowed_user_type: ut,
              allow_wildcard: true,
            });
          else
            ops.push({
              op: 'add_restriction',
              object_type: ty,
              relation: f.name,
              allowed_user_type: ut,
              allowed_user_relation: ur ?? '',
            });
        }
      }
    }
    this._wrap(() => api.modelBatch(this.store, ops)).then(async (ok) => {
      if (ok) {
        this.edit = null;
        this.form = {};
        await this._load();
        this.dispatchEvent(new CustomEvent('changed'));
      }
    });
  };

  _names(kind) {
    return (this.m?.json?.[kind] ?? []).map((x) => x.name);
  }

  _datalist(id, names) {
    return html`<datalist id=${id}>${names.map((n) => html`<option value=${n}></option>`)}</datalist>`;
  }

  // Gate editor: the gate object is JSON (the engine validates and normalizes
  // it, unknown keys are refused); templates insert one clause of each
  // primitive so people start from a working shape.
  _gateTemplates = {
    count_within: { count_within: { window: '1h', kind: 'response', max: 5, plus: 1 } },
    count_distinct_within: {
      count_distinct_within: {
        window: '30 days',
        scope: 'object',
        action: 'approval_received',
        key: 'payload.input.approver',
        min: 2,
      },
    },
    sum_within: {
      sum_within: {
        window: '1h',
        kind: 'response',
        field: 'input.amount',
        plus: '$request.input.amount',
        max: 5000,
      },
    },
    formerly_within: { formerly_within: { window: '30 days', action: 'accept_nda', kind: 'response' } },
  };

  _gateClauses() {
    try {
      const v = JSON.parse(this.form.all_of || '[]');
      return Array.isArray(v) ? v : null;
    } catch {
      return null;
    }
  }

  _addClause(primitive) {
    const cur = this._gateClauses() ?? [];
    cur.push(structuredClone(this._gateTemplates[primitive]));
    this.form = { ...this.form, all_of: JSON.stringify(cur, null, 2) };
  }

  _editGate(g) {
    const { all_of, description, mode, ...rest } = g.spec;
    delete rest.required_context; // derived by the engine, not part of the editable spec
    this.form = {
      object_type: g.object_type,
      relation: g.relation,
      name: g.name,
      description: description ?? '',
      mode: mode ?? 'enforce',
      all_of: JSON.stringify(all_of ?? [], null, 2),
      extra: Object.keys(rest).length ? JSON.stringify(rest) : '',
      editing: true,
    };
    this.edit = 'add_gate';
    clearSelection(this);
    this.updateComplete.then(() =>
      this.querySelector('form.gate-form')?.scrollIntoView({ behavior: 'smooth', block: 'start' }),
    );
  }

  _submitGate = (e) => {
    e.preventDefault();
    const f = this.form;
    const clauses = this._gateClauses();
    if (!clauses && PgcJson.report(this)) return; // not JSON: said next to the field
    if (!clauses || !clauses.length) {
      this.error = t('the clauses must be a JSON array with at least one clause');
      return;
    }
    const spec = { all_of: clauses };
    if (f.description) spec.description = f.description;
    if (f.mode && f.mode !== 'enforce') spec.mode = f.mode;
    this._op('add_gate', { object_type: f.object_type, relation: f.relation, name: f.name, spec });
  };

  // One clause as a sentence: "count_within · response · 1h · max 5 (+1)".
  _clauseText(c) {
    const [prim, body] = Object.entries(c)[0] ?? ['?', {}];
    const parts = [];
    if (body.action) parts.push(body.action);
    if (body.kind) parts.push(body.kind);
    if (body.window) parts.push(body.window);
    if (body.calendar) parts.push(`${t('per')} ${body.calendar}${body.tz ? ' ' + body.tz : ''}`);
    if (body.scope === 'object') parts.push(t('this object'));
    if (body.key) parts.push(`${t('distinct')} ${body.key}`);
    if (body.field) parts.push(`${t('sum of')} ${body.field}`);
    if (body.match) parts.push(`${t('match')} ${JSON.stringify(body.match)}`);
    if (body.recorded_by) parts.push(`${t('by')} ${body.recorded_by.join(', ')}`);
    const bounds = [];
    if (body.min !== undefined) bounds.push(`min ${body.min}`);
    if (body.max !== undefined) bounds.push(`max ${body.max}`);
    if (body.plus !== undefined) bounds.push(`+${body.plus}`);
    return html`<code>${prim}</code>
      <span class="muted">${parts.join(' · ')}</span>
      ${bounds.length ? html` <b>${bounds.join(' ')}</b>` : nothing}`;
  }

  // Store-wide editing, or editing inside at least one namespace (the
  // backend checks each change against the namespace of the type it touches).
  _canEdit() {
    return (
      !!this.caps?.can_edit_model || Object.values(this.info?.namespaces ?? {}).some((c) => c.can_edit_model)
    );
  }

  _namespaces() {
    return [...new Set((this.m?.json?.types ?? []).map((x) => x.namespace).filter(Boolean))].sort();
  }

  _formActions(label) {
    return html`<div class="actions wide">
      <button class="primary" ?disabled=${this.busy} data-testid="model-form-submit">${t(label)}</button>
      <button type="button" data-testid="model-form-cancel" @click=${() => (this.edit = null)}>
        ${t('Cancel')}
      </button>
    </div>`;
  }

  _forms() {
    const types = this._names('types');
    const rels = this._names('relations');
    const conds = this._names('conditions');
    const f = this.form;
    const dl = html`${this._datalist('dl-types', types)}${this._datalist('dl-rels', rels)}${this._datalist('dl-conds', conds)}`;
    const name = (label, helpText) =>
      html`<label class="field"
        ><span>${t(label)} ${help(helpText)}</span>
        <input class="mono" required pattern="[a-zA-Z_][a-zA-Z0-9_]*" @input=${this._set('name')}
      /></label>`;
    switch (this.edit) {
      case 'add_type':
        return html`<form class="card form" @submit=${this._submit('add_type')}>
          ${dl}
          <h3 class="wide">${t('New type')}</h3>
          ${name('Type name', 'An object or subject type, e.g. document, folder, user. Letters, digits, underscores.')}
          <label class="field"
            ><span
              >${t('Namespace')}
              ${help('Optional: the application or team this type belongs to. Namespace roles (Access tab) may edit the model and data inside their namespace only; a type without one is store-wide.')}</span
            ><input class="mono" list="dl-namespaces" @input=${this._set('namespace')}
          /></label>
          <datalist id="dl-namespaces">
            ${this._namespaces().map((n) => html`<option value=${n}></option>`)}
          </datalist>
          <label class="field wide"
            ><span>${t('Description')}</span><input @input=${this._set('description')}
          /></label>
          ${this._formActions('Add type')}
        </form>`;
      case 'add_relation':
        return html`<form class="card form" @submit=${this._submitRelation}>
          ${dl}
          <h3 class="wide">${t('New relation')}</h3>
          ${name('Relation name', 'A relation or permission name shared by all types, e.g. viewer, can_read. Rules then define it per type.')}
          <label class="field"
            ><span
              >${t('Kind')}
              ${help('relation: what a subject IS (viewer, owner, member). permission: what a subject CAN DO (can_read, or a directly granted capability like run). A permission takes tuples only where it has a direct rule; otherwise it is derived and the engine refuses them.')}</span
            >
            <select @change=${this._set('kind')}>
              <option value="relation">${t('relation — what a subject is (assignable)')}</option>
              <option value="permission">${t('permission — what a subject can do (derived)')}</option>
            </select></label
          >
          <label class="field wide"
            ><span>${t('Description')}</span><input @input=${this._set('description')}
          /></label>
          <div class="field wide">
            <span
              >${t('Defined on object types')}
              ${help('The object types this relation exists on. Each gets a rule right away: a direct rule for a relation, computed rules for a permission.')}</span
            >
            <div class="caps">
              ${
                types.length
                  ? types.map(
                      (ty) =>
                        html`<label class="check">
                          <input
                            type="checkbox"
                            .checked=${(f.object_types ?? []).includes(ty)}
                            @change=${(e) => this._toggleType(ty, e.target.checked)}
                          />
                          <span class="mono">${ty}</span>
                        </label>`,
                    )
                  : html`<span class="muted">${t('Add types first.')}</span>`
              }
            </div>
          </div>
          ${
            (f.kind ?? 'relation') === 'permission'
              ? html`<label class="field wide"
                  ><span
                    >${t('Derived from')}
                    ${help('Relations this permission is implied by, on each selected type: "viewer, owner" means viewer or owner. Inheritance through related objects (ttu) is added afterwards with "+ rule".')}</span
                  ><input class="mono" list="dl-rels" @input=${this._set('derived_from')}
                /></label>`
              : html`<label class="field wide"
                  ><span
                    >${t('Accepts subject types')}
                    ${help('Type restrictions for the tuples of this relation on each selected type: "user" a user; "team#member" the members of a team (userset); "user:*" also the wildcard for everyone of that type. Empty = no restriction (any subject).')}</span
                  ><input class="mono" list="dl-types" @input=${this._set('accepts')}
                /></label>`
          }
          ${this._formActions('Add relation')}
        </form>`;
      case 'add_rule':
        return html`<form class="card form" @submit=${this._submit('add_rule')}>
          ${dl}
          <h3 class="wide">
            ${t('New rule')}
            ${help('A rule defines one relation on one object type. The checkboxes in the tables below are for removing things and have nothing to do with this form.')}
          </h3>
          <label class="field"
            ><span>${t('On object type')}</span
            ><select class="mono" required @change=${this._set('object_type')}>
              <option value="" ?selected=${!f.object_type}>${t('choose…')}</option>
              ${types.map((ty) => html`<option value=${ty} ?selected=${f.object_type === ty}>${ty}</option>`)}
            </select></label
          >
          <label class="field"
            ><span>${t('Relation')}</span
            ><select class="mono" required @change=${this._set('relation')}>
              <option value="" ?selected=${!f.relation}>${t('choose…')}</option>
              ${rels.map((r) => html`<option value=${r} ?selected=${f.relation === r}>${r}</option>`)}
            </select></label
          >
          <label class="field"
            ><span
              >${t('Rule type')}
              ${help('direct: granted by a tuple. computed: implied by another relation on the same object. ttu: inherited from a related object (tuple-to-userset).')}</span
            >
            <select @change=${this._set('rule_type')}>
              <option value="direct">${t('direct — granted by a tuple')}</option>
              <option value="computed">${t('computed — implied by another relation')}</option>
              <option value="ttu">${t('ttu — inherited through a related object')}</option>
            </select></label
          >
          ${
            f.rule_type === 'computed'
              ? html`<label class="field"
                  ><span>${t('Computed relation')}</span
                  ><input class="mono" required list="dl-rels" @input=${this._set('computed_relation')}
                /></label>`
              : nothing
          }
          ${
            f.rule_type === 'ttu'
              ? html`<label class="field"
                    ><span
                      >${t('Tupleset relation (the link)')}
                      ${help('The relation on this object that points at the related object, e.g. parent.')}</span
                    ><input class="mono" required list="dl-rels" @input=${this._set('tupleset_relation')}
                  /></label>
                  <label class="field"
                    ><span
                      >${t('Relation on the related object')}
                      ${help('The relation evaluated on the related object, e.g. viewer on the parent folder.')}</span
                    ><input class="mono" required list="dl-rels" @input=${this._set('tupleset_computed')}
                  /></label>`
              : nothing
          }
          <label class="field"
            ><span
              >${t('Group')}
              ${help('Terms in group 0 form the union; another group combined with intersection or exclusion restricts it.')}</span
            ><input type="number" min="0" value="0" @input=${this._set('group_id')}
          /></label>
          <label class="field"
            ><span>${t('Group operator')}</span>
            <select @change=${this._set('group_op')}>
              <option value="or">${t('or (union)')}</option>
              <option value="intersection">${t('intersection (and)')}</option>
              <option value="exclusion">${t('exclusion (but not)')}</option>
            </select></label
          >
          <label class="check"
            ><input type="checkbox" @change=${this._set('negated')} /> ${t('negated')}</label
          >
          ${
            (f.rule_type ?? 'direct') === 'direct'
              ? html`<label class="check"
                  ><input type="checkbox" @change=${this._set('allow_object_wildcard')} />
                  ${t('allow object wildcard')} (<code>*</code>)</label
                >`
              : nothing
          }
          ${this._formActions('Add rule')}
        </form>`;
      case 'add_restriction':
        return html`<form class="card form" @submit=${this._submit('add_restriction')}>
          ${dl}
          <h3 class="wide">${t('New type restriction')}</h3>
          <label class="field"
            ><span>${t('Object type')}</span
            ><input class="mono" required list="dl-types" @input=${this._set('object_type')}
          /></label>
          <label class="field"
            ><span>${t('Relation')}</span
            ><input class="mono" required list="dl-rels" @input=${this._set('relation')}
          /></label>
          <label class="field"
            ><span
              >${t('Allowed subject type')}
              ${help('Which subject type a tuple of this relation may name, e.g. user.')}</span
            ><input class="mono" required list="dl-types" @input=${this._set('allowed_user_type')}
          /></label>
          <label class="field"
            ><span
              >${t('Subject relation (userset)')}
              ${help('Set this to accept a group as the subject, e.g. member for team#member.')}</span
            ><input class="mono" list="dl-rels" @input=${this._set('allowed_user_relation')}
          /></label>
          <label class="field"
            ><span>${t('Required condition')} ${help('Tuples of this shape must carry this condition.')}</span
            ><input class="mono" list="dl-conds" @input=${this._set('condition')}
          /></label>
          <label class="check"
            ><input type="checkbox" @change=${this._set('allow_wildcard')} /> ${t('allow subject wildcard')}
            (<code>type:*</code>)</label
          >
          ${this._formActions('Add type restriction')}
        </form>`;
      case 'add_condition':
        return html`<form class="card form condition-form" @submit=${this._submit('add_condition')}>
          <h3 class="wide">${f.editing ? t('Edit condition') : t('New condition')}</h3>
          <label class="field"
            ><span
              >${t('Condition name')}
              ${help('A named expression evaluated against the request context (and the tuple context) at decision time. Saving under an existing name replaces that condition.')}</span
            ><input
              class="mono"
              required
              pattern="[A-Za-z_][A-Za-z0-9_]*"
              .value=${f.name ?? ''}
              ?readonly=${!!f.editing}
              @input=${this._set('name')}
          /></label>
          <label class="field"
            ><span>${t('Language')}</span
            ><select .value=${f.lang ?? 'sql'} @change=${this._set('lang')}>
              <option value="sql">sql</option>
              <option value="cel">cel (${t('needs pg_cel')})</option>
            </select></label
          >
          <label class="field wide"
            ><span
              >${t('Description')}
              ${help('What the condition is for, in words — shown in the list and carried by the registry.')}</span
            ><input .value=${f.description ?? ''} @input=${this._set('description')}
          /></label>
          <label class="field wide"
            ><span
              >${t('Expression')}
              ${help("SQL: $1 is the request context, $2 the tuple context (jsonb), e.g. ($1->>'ip')::inet << '10.0.0.0/8'::inet. CEL: request and tuple variables.")}</span
            ><textarea
              class="mono"
              rows="2"
              required
              spellcheck="false"
              .value=${f.expression ?? ''}
              @input=${this._set('expression')}
            ></textarea>
          </label>
          <label class="field wide"
            ><span
              >${t('Required context (JSON, optional)')}
              ${help('Keys the request must supply, as {"request": ["ip"]}; a decision without them is "conditional", not a silent deny.')}</span
            ><pgc-json
              rows="3"
              testid="model-input-required-context"
              .value=${f.required_context ?? ''}
              @json-input=${(e) => (this.form = { ...this.form, required_context: e.detail.text })}
            ></pgc-json
          ></label>
          ${this._formActions(f.editing ? 'Save condition' : 'Add condition')}
        </form>`;
      case 'set_type_namespace':
        return html`<form class="card form" @submit=${this._submit('set_type_namespace')}>
          <h3 class="wide">${t('Namespace of type')} <span class="mono">${f.name}</span></h3>
          <label class="field"
            ><span
              >${t('Namespace')}
              ${help('Empty moves the type out of every namespace (store-wide). A name that does not exist yet creates the namespace. Namespace roles on the Access tab follow the name.')}</span
            ><input
              class="mono"
              list="dl-namespaces"
              .value=${f.namespace ?? ''}
              @input=${this._set('namespace')}
          /></label>
          <datalist id="dl-namespaces">
            ${this._namespaces().map((n) => html`<option value=${n}></option>`)}
          </datalist>
          ${this._formActions('Save namespace')}
        </form>`;
      case 'set_type_labels':
        return html`<form
          class="card form"
          data-testid="model-form-set-type-labels"
          @submit=${this._submit('set_type_labels')}
        >
          <h3 class="wide">${t('Labels of type')} <span class="mono">${f.name}</span></h3>
          <label class="field wide"
            ><span
              >${t('Labels')}
              ${help('Advisory key:value tags for grouping and tooling (group:accounting, tier:core), comma-separated. They have no access-control effect. Empty clears them.')}</span
            ><input
              class="mono"
              .value=${f.labels_text ?? ''}
              @input=${this._set('labels_text')}
              data-testid="model-input-labels"
          /></label>
          ${this._formActions('Save labels')}
        </form>`;
      case 'set_payload_schema':
        return html`<form
          class="card form"
          data-testid="model-form-set-payload-schema"
          @submit=${this._submit('set_payload_schema')}
        >
          <h3 class="wide">${t('Payload schema of action')} <span class="mono">${f.name}</span></h3>
          <label class="field wide"
            ><span
              >${t('Schema (JSON)')}
              ${help('The shape events recorded for this action must have: "required" maps payload paths to types (input.amount: number, input.currency: string); "kinds" refines it per event kind (request, response). record_event enforces it, add_gate cross-checks it. Empty clears the schema.')}</span
            ><pgc-json
              rows="8"
              testid="model-input-payload-schema"
              .value=${f.payload_schema_text ?? ''}
              @json-input=${(e) => (this.form = { ...this.form, payload_schema_text: e.detail.text })}
            ></pgc-json>
          </label>
          ${this._formActions('Save schema')}
        </form>`;
      case 'add_grant_rule':
        return html`<form
          class="card form grant-form"
          data-testid="model-form-add-grant-rule"
          @submit=${this._submit('add_grant_rule')}
        >
          ${dl}
          <h3 class="wide">
            ${f.editing ? t('Edit grant rule') : t('New grant rule')}
            ${help('The sharing policy: an actor may grant this relation on an object through authz.grant when they are allowed the required relation on that same object, and revoke it when allowed the revoke requirement. A relation without a rule cannot be granted that way at all (the writer role is unaffected). Saving for an existing type and relation replaces that rule.')}
          </h3>
          <label class="field"
            ><span>${t('On object type')}</span
            ><select
              class="mono"
              required
              @change=${this._set('object_type')}
              data-testid="model-input-grant-object-type"
            >
              <option value="" ?selected=${!f.object_type}>${t('choose…')}</option>
              ${types.map((ty) => html`<option value=${ty} ?selected=${f.object_type === ty}>${ty}</option>`)}
            </select></label
          >
          <label class="field"
            ><span>${t('Relation granted')}</span
            ><select
              class="mono"
              required
              @change=${this._set('relation')}
              data-testid="model-input-grant-relation"
            >
              <option value="" ?selected=${!f.relation}>${t('choose…')}</option>
              ${rels.map((r) => html`<option value=${r} ?selected=${f.relation === r}>${r}</option>`)}
            </select></label
          >
          <label class="field"
            ><span
              >${t('To grant, the actor needs')}
              ${help('A relation or permission the actor must be allowed on the same object, e.g. can_share or owner.')}</span
            ><select
              class="mono"
              required
              @change=${this._set('requires')}
              data-testid="model-input-grant-requires"
            >
              <option value="" ?selected=${!f.requires}>${t('choose…')}</option>
              ${rels.map((r) => html`<option value=${r} ?selected=${f.requires === r}>${r}</option>`)}
            </select></label
          >
          <label class="field"
            ><span>${t('To revoke, the actor needs')} ${help('Empty: the same as to grant.')}</span
            ><select
              class="mono"
              @change=${this._set('requires_revoke')}
              data-testid="model-input-grant-requires-revoke"
            >
              <option value="" ?selected=${!f.requires_revoke}>${t('same as to grant')}</option>
              ${rels.map((r) => html`<option value=${r} ?selected=${f.requires_revoke === r}>${r}</option>`)}
            </select></label
          >
          ${this._formActions(f.editing ? 'Save grant rule' : 'Add grant rule')}
        </form>`;
      case 'set_relation_constraint': {
        // Only pairs a constraint can apply to: types with rules, and on the
        // chosen type the relations that have rules there. Max direct needs a
        // direct rule and no wildcard declaration on that pair (the engine
        // refuses it otherwise); max effective applies to any relation.
        const m = this.m;
        const rulesOn = (ty) => m.rules.filter((r) => r.object_type === ty);
        const ctypes = types.filter((ty) => rulesOn(ty).length);
        const crels = f.object_type
          ? byOrder(
              m.json.relations.filter((x) => rulesOn(f.object_type).some((r) => r.relation === x.name)),
            ).map((x) => x.name)
          : [];
        const hasDirect = rulesOn(f.object_type).some(
          (r) => r.relation === f.relation && r.rule_type === 'direct',
        );
        const hasWildcard =
          rulesOn(f.object_type).some((r) => r.relation === f.relation && r.allow_object_wildcard) ||
          m.restrictions.some(
            (x) => x.object_type === f.object_type && x.relation === f.relation && x.allow_wildcard,
          );
        const directOff = !!f.relation && (!hasDirect || hasWildcard);
        const directWhy = !f.relation
          ? ''
          : !hasDirect
            ? t(
                '{rel} is derived on {type} (no direct rule): nothing is assigned by tuple, so only the effective cap applies.',
                { rel: f.relation, type: f.object_type },
              )
            : hasWildcard
              ? t(
                  '{rel} on {type} allows wildcard grants (a user:* facet or an object-wildcard rule); a capped relation refuses them. Remove the wildcard first, or set only the effective cap.',
                  { rel: f.relation, type: f.object_type },
                )
              : '';
        const pickType = (e) => {
          const ty = e.target.value;
          const keep = rulesOn(ty).some((r) => r.relation === f.relation);
          this.form = { ...this.form, object_type: ty, relation: keep ? f.relation : '' };
        };
        const pickRel = (e) => {
          const rel = e.target.value;
          const direct = rulesOn(f.object_type).some((r) => r.relation === rel && r.rule_type === 'direct');
          this.form = { ...this.form, relation: rel, max_direct: direct ? f.max_direct : '' };
        };
        return html`<form
          class="card form constraint-form"
          data-testid="model-form-set-relation-constraint"
          @submit=${this._submit('set_relation_constraint')}
        >
          ${dl}
          <h3 class="wide">
            ${f.editing ? t('Edit relation constraint') : t('New relation constraint')}
            ${help('How many subjects may hold this relation on one object. The direct cap counts the ACTIVE (unexpired) tuples written on an object for the relation — a userset such as team:eng#member is one — and is enforced on every write path: the one past the cap is refused (pgauthzd answers 409 relation_full). Wildcard grants are refused on a capped relation, and the relation needs a direct rule on the type. The effective cap is advisory: relation_usage reports the resolved holder set (direct, usersets, inherited) against it, nothing is refused. Saving for an existing type and relation replaces both values; leave one empty for no cap of that kind.')}
          </h3>
          <label class="field"
            ><span
              >${t('On object type')}
              ${help('Types that have rules; a relation is constrained where it is defined.')}</span
            ><select
              class="mono"
              required
              @change=${pickType}
              data-testid="model-input-constraint-object-type"
            >
              <option value="" ?selected=${!f.object_type}>${t('choose…')}</option>
              ${ctypes.map((ty) => html`<option value=${ty} ?selected=${f.object_type === ty}>${ty}</option>`)}
            </select></label
          >
          <label class="field"
            ><span>${t('Relation')} ${help('The relations defined on the chosen type.')}</span
            ><select
              class="mono"
              required
              ?disabled=${!f.object_type}
              @change=${pickRel}
              data-testid="model-input-constraint-relation"
            >
              <option value="" ?selected=${!f.relation}>
                ${f.object_type ? t('choose…') : t('choose a type first')}
              </option>
              ${crels.map(
                (r) =>
                  html`<option value=${r} ?selected=${f.relation === r}>
                    ${r}${rulesOn(f.object_type).some((x) => x.relation === r && x.rule_type === 'direct') ? '' : ` · ${t('derived')}`}
                  </option>`,
              )}
            </select></label
          >
          <label class="field"
            ><span
              >${t('Max direct')}
              ${help('Enforced: at most this many active direct tuples per object. Empty: no direct cap.')}</span
            ><input
              class="mono"
              type="number"
              min="1"
              step="1"
              ?disabled=${directOff}
              .value=${String(f.max_direct ?? '')}
              @input=${this._set('max_direct')}
              data-testid="model-input-constraint-max-direct"
            />
            ${directOff ? html`<span class="help" data-testid="model-constraint-direct-why">${directWhy}</span>` : nothing}
          </label>
          <label class="field"
            ><span
              >${t('Max effective')}
              ${help('Advisory: the intended size of the resolved holder set, reported with headroom by relation_usage. Empty: none.')}</span
            ><input
              class="mono"
              type="number"
              min="1"
              step="1"
              .value=${String(f.max_effective ?? '')}
              @input=${this._set('max_effective')}
              data-testid="model-input-constraint-max-effective"
          /></label>
          ${this._formActions(f.editing ? 'Save relation constraint' : 'Add relation constraint')}
        </form>`;
      }
      case 'add_gate': {
        const clauses = this._gateClauses();
        return html`<form class="card form gate-form" @submit=${this._submitGate}>
          <h3 class="wide">
            ${f.editing ? t('Edit gate') : t('New temporal gate')}
            ${help('A gate vetoes a decision the graph would allow, based on what the principal already did (the action log). All clauses must hold. Saving under an existing name replaces that gate.')}
          </h3>
          <label class="field"
            ><span
              >${t('Object type')}
              ${help('The gate hangs on one object type + relation: the question it vetoes.')}</span
            ><input
              class="mono"
              required
              list="dl-types"
              .value=${f.object_type ?? ''}
              ?readonly=${!!f.editing}
              @input=${this._set('object_type')}
          /></label>
          <label class="field"
            ><span>${t('Relation')}</span
            ><input
              class="mono"
              required
              list="dl-rels"
              .value=${f.relation ?? ''}
              ?readonly=${!!f.editing}
              @input=${this._set('relation')}
          /></label>
          <label class="field"
            ><span>${t('Gate name')}</span
            ><input
              class="mono"
              required
              pattern="[A-Za-z_][A-Za-z0-9_]*"
              .value=${f.name ?? ''}
              ?readonly=${!!f.editing}
              @input=${this._set('name')}
          /></label>
          <label class="field"
            ><span
              >${t('Mode')}
              ${help('enforce: a failing clause denies. shadow: evaluated and traced but never denies — roll a gate out safely. off: not evaluated.')}</span
            ><select .value=${f.mode ?? 'enforce'} @change=${this._set('mode')}>
              <option value="enforce">enforce</option>
              <option value="shadow">shadow</option>
              <option value="off">off</option>
            </select></label
          >
          <label class="field wide"
            ><span>${t('Description')}</span
            ><input .value=${f.description ?? ''} @input=${this._set('description')}
          /></label>
          <div class="field wide">
            <span
              >${t('Clauses (all must hold)')}
              ${help('A JSON array; each clause is one primitive. Keys: window or calendar+tz, scope (subject|object), action, kind (request|response|denied), match, recorded_by, key (count_distinct), field (sum), plus, min/max (inclusive). Thresholds may be "$request.<path>". Unknown keys are refused.')}</span
            >
            <div class="actions">
              <span class="help">${t('insert a clause:')}</span>
              ${Object.keys(this._gateTemplates).map(
                (prim) =>
                  html`<button type="button" class="sm" @click=${() => this._addClause(prim)}>
                    + ${prim}
                  </button>`,
              )}
            </div>
            <pgc-json
              rows="8"
              required
              testid="model-input-gate-clauses"
              .value=${f.all_of ?? ''}
              @json-input=${(e) => (this.form = { ...this.form, all_of: e.detail.text })}
            ></pgc-json>
            ${
              clauses
                ? html`<ul class="clauses">
                    ${clauses.map((c) => html`<li>${this._clauseText(c)}</li>`)}
                  </ul>`
                : nothing
            }
          </div>
          ${this._formActions(f.editing ? 'Save gate' : 'Add gate')}
        </form>`;
      }
      default:
        return nothing;
    }
  }

  _toggleDef = (e) => {
    this.defOpen = e.target.open;
    try {
      localStorage.setItem('pgc_model_def_open', this.defOpen ? '1' : '0');
    } catch {
      /* storage unavailable */
    }
  };

  // Section filters: every word typed must appear somewhere in the row's
  // searchable fields. Client-side, since the model is already loaded.
  // What each sortable column of a section sorts by (the row → a value).
  _sorters() {
    const times = this.m?.condition_times ?? {};
    return {
      types: {
        name: (x) => x.name,
        namespace: (x) => x.namespace ?? '',
        description: (x) => x.description ?? '',
        labels: (x) => (x.labels ?? []).join(' '),
      },
      rules: {
        id: (r) => r.id,
        object_type: (r) => r.object_type,
        relation: (r) => r.relation,
        defined: (r) =>
          r.rule_type === 'direct'
            ? 'direct'
            : r.rule_type === 'computed'
              ? r.computed_relation
              : `${r.tupleset_computed} from ${r.tupleset_relation}`,
        group: (r) => r.group_id,
      },
      restrictions: {
        id: (x) => x.id,
        object_type: (x) => x.object_type,
        relation: (x) => x.relation,
        accepts: (x) => `${x.allowed_user_type}#${x.allowed_user_relation ?? ''}`,
        condition: (x) => x.condition ?? '',
      },
      conditions: {
        name: (c) => c.name,
        description: (c) => c.description ?? '',
        lang: (c) => c.lang,
        created: (c) => times[c.name]?.created_at ?? '',
        updated: (c) => times[c.name]?.updated_at ?? '',
      },
      gates: {
        on: (g) => `${g.object_type}.${g.relation}`,
        name: (g) => g.name,
        mode: (g) => g.spec?.mode ?? 'enforce',
        clauses: (g) => (g.spec?.all_of ?? []).length,
      },
      grant_rules: {
        object_type: (g) => g.object_type,
        relation: (g) => g.relation,
        requires: (g) => g.requires,
        requires_revoke: (g) => g.requires_revoke ?? '',
      },
      relation_constraints: {
        object_type: (c) => c.object_type,
        relation: (c) => c.relation,
        max_direct: (c) => c.max_direct ?? Infinity,
        max_effective: (c) => c.max_effective ?? Infinity,
      },
    };
  }

  _toggleSort(section, key) {
    const cur = this.sorts[section];
    this.sorts = { ...this.sorts, [section]: cur?.key === key ? { key, dir: -cur.dir } : { key, dir: 1 } };
  }

  // A sortable column head: click sorts, click again reverses. cls "wide"
  // marks a prose column (description, definition) that keeps room.
  _sortTh(section, key, label, extra, cls = '') {
    const cur = this.sorts[section];
    const active = cur?.key === key;
    return html`<th
      class="sortable ${active ? 'active' : ''} ${cls}"
      title=${t('sort')}
      data-testid=${`model-sort-${section}-${key}`}
      @click=${() => this._toggleSort(section, key)}
    >
      ${label} ${extra ?? nothing}
      <span class="sort-ind">${active ? (cur.dir > 0 ? '▲' : '▼') : '↕'}</span>
    </th>`;
  }

  // The rows of a section as shown: filtered, then sorted by the chosen
  // column (the engine's order otherwise).
  _filtered(section, items, fields) {
    const rows = this._filteredOnly(section, items, fields);
    const sort = this.sorts[section];
    const val = sort && this._sorters()[section]?.[sort.key];
    if (!val) return rows;
    return [...rows].sort((a, b) => {
      const x = val(a);
      const y = val(b);
      const c = typeof x === 'number' && typeof y === 'number' ? x - y : String(x).localeCompare(String(y));
      return c * sort.dir;
    });
  }

  _filteredOnly(section, items, fields) {
    const words = (this.filters[section] ?? '').trim().toLowerCase().split(/\s+/).filter(Boolean);
    if (!words.length) return items;
    return items.filter((x) => {
      const parts = fields(x).filter(Boolean).map(String);
      const hay = parts.join(' ').toLowerCase();
      // "#12" refers to one item: exact id, never a prefix of #120
      return words.every((w) =>
        w.startsWith('#') ? parts.some((p) => p.toLowerCase() === w) : hay.includes(w),
      );
    });
  }

  _filterBox(section, shown, total) {
    const q = this.filters[section] ?? '';
    return html`<div class="sec-filter">
      <span class="filter-label"
        >${t('Filter')}
        ${help('Every word typed must appear somewhere in the row; #id finds one item by its engine id.')}</span
      >
      <label class="filter-box" aria-label=${t('Filter')}>
        <svg class="filter-icon" viewBox="0 0 16 16" width="14" height="14" aria-hidden="true">
          <path
            d="M1.5 2.5h13l-5 6v4.5l-3 1.5V8.5z"
            fill="none"
            stroke="currentColor"
            stroke-width="1.4"
            stroke-linejoin="round"
          />
        </svg>
        <input
          type="search"
          .value=${q}
          @input=${(e) => (this.filters = { ...this.filters, [section]: e.target.value })}
        />
      </label>
      ${q ? html`<span class="muted">${shown} / ${total}</span>` : nothing}
    </div>`;
  }

  // Rules and type restrictions have no unique name, so their engine id is
  // the handle to refer to one ("rule #123"); everything else is named.
  _idCell(id) {
    return html`<td class="num id" title=${t('engine id — a stable handle for this item')}>
      ${id != null ? '#' + id : ''}
    </td>`;
  }

  _editTypeNamespace(x) {
    this.form = { name: x.name, namespace: x.namespace ?? '', editing: true };
    this.edit = 'set_type_namespace';
    clearSelection(this);
  }

  _editTypeLabels(x) {
    this.form = { name: x.name, labels_text: (x.labels ?? []).join(', '), editing: true };
    this.edit = 'set_type_labels';
    clearSelection(this);
  }

  _editPayloadSchema(r) {
    this.form = {
      name: r.name,
      payload_schema_text: r.payload_schema ? JSON.stringify(r.payload_schema, null, 2) : '',
      editing: true,
    };
    this.edit = 'set_payload_schema';
    clearSelection(this);
  }

  _editGrantRule(g) {
    this.form = {
      object_type: g.object_type,
      relation: g.relation,
      requires: g.requires,
      requires_revoke: g.requires_revoke ?? '',
      editing: true,
    };
    this.edit = 'add_grant_rule';
    clearSelection(this);
    this.updateComplete.then(() =>
      this.querySelector('form.grant-form')?.scrollIntoView({ behavior: 'smooth', block: 'start' }),
    );
  }

  _grantSQL(g) {
    const args = [this.store, g.object_type, g.relation, g.requires].map((x) => this._q(x));
    if (g.requires_revoke) args.push(`p_requires_revoke => ${this._q(g.requires_revoke)}`);
    return `SELECT authz.model_add_grant_rule(${args.join(', ')});`;
  }

  _editConstraint(c) {
    this.form = {
      object_type: c.object_type,
      relation: c.relation,
      max_direct: c.max_direct ?? '',
      max_effective: c.max_effective ?? '',
      editing: true,
    };
    this.edit = 'set_relation_constraint';
    clearSelection(this);
    this.updateComplete.then(() =>
      this.querySelector('form.constraint-form')?.scrollIntoView({ behavior: 'smooth', block: 'start' }),
    );
  }

  // From the Structure view: show the Relation constraints section with the
  // edit form for this constraint open.
  _openConstraint(c) {
    // the section tab is a router link: clicking it is the one way to switch
    this.querySelector('a[data-testid="model-section-relation_constraints"]')?.click();
    this._editConstraint(c);
  }

  _constraintSQL(c) {
    const args = [this.store, c.object_type, c.relation].map((x) => this._q(x));
    if (c.max_direct != null) args.push(`p_max_direct => ${c.max_direct}`);
    if (c.max_effective != null) args.push(`p_max_effective => ${c.max_effective}`);
    return `SELECT authz.model_set_relation_constraint(${args.join(', ')});`;
  }

  _renameNamespace = async (e) => {
    e.preventDefault();
    const ok = await this._wrap(() => api.namespaceRename(this.store, this.renaming, this.renameTo.trim()));
    if (ok) {
      this.renaming = null;
      await this._load();
      this.dispatchEvent(new CustomEvent('changed'));
    }
  };

  _toggleDetail(key) {
    const next = new Set(this.detail);
    if (next.has(key)) next.delete(key);
    else next.add(key);
    this.detail = next;
  }

  // The definition as the SQL call that (re)creates it — what the SQL view
  // prints, for one item — with the raw JSON next to it.
  _detailRow(span, sql, json, extra) {
    return html`<tr class="detail-row">
      <td colspan=${span}>
        <div class="detail ${extra ? 'three' : ''}">
          <div>
            <div class="detail-head">
              <span>${t('SQL definition')}</span>
              <button class="sm" @click=${() => copyText(sql)}>${t('Copy')}</button>
            </div>
            <pre class="code">${highlightSQL(sql)}</pre>
          </div>
          <div>
            <div class="detail-head"><span>JSON</span></div>
            <pre class="code">${highlightJSON(JSON.stringify(json, null, 2))}</pre>
          </div>
          ${extra ?? nothing}
        </div>
      </td>
    </tr>`;
  }

  // Try a condition: its expression against a request context and a mocked
  // stored context, without a tuple (authz.evaluate_condition). Skeletons
  // come from required_context so the keys to fill are visible.
  _tryState(name) {
    return this.tryCond[name] ?? {};
  }

  _trySet(name, patch) {
    this.tryCond = { ...this.tryCond, [name]: { ...this._tryState(name), ...patch } };
  }

  // The skeleton puts the placeholder __now__ where a key looks like a time
  // (*_time, *_at); everything else is empty. __now__ is replaced by the
  // current instant (timestamptz text) right before the JSON is parsed, and
  // may carry an offset: __now__+2h, __now__-30m, __now__+1d.
  _sampleValue(key) {
    return /(^|_)(time|at|timestamp)$/.test(key.toLowerCase()) ? '__now__' : '';
  }

  // A server-time condition gets current_time from the engine's clock, so
  // the request skeleton leaves it out (the engine ignores a supplied one).
  _skeleton(keys, c) {
    const list = (keys ?? []).filter((k) => !(c?.time_source === 'server' && k === 'current_time'));
    return JSON.stringify(Object.fromEntries(list.map((k) => [k, this._sampleValue(k)])), null, 2);
  }

  // Resolve placeholders, then parse: {value} or {error} — the error names
  // the syntax problem so it can be shown before anything is sent.
  _parseContext(text) {
    const resolved = String(text ?? '')
      .replace(/__now__([+-]\d+)([mhd])?/g, (_, n, unit) => {
        const ms = Number(n) * { m: 60e3, h: 3600e3, d: 86400e3 }[unit ?? 'h'];
        return new Date(Date.now() + ms).toISOString();
      })
      .replace(/__now__/g, () => new Date().toISOString());
    try {
      const value = JSON.parse(resolved);
      if (!value || typeof value !== 'object' || Array.isArray(value))
        return { error: t('must be a JSON object') };
      return { value };
    } catch (e) {
      return { error: String(e.message).replace(/^JSON\.parse: /, '') };
    }
  }

  async _tryCondition(c) {
    const st = this._tryState(c.name);
    const req = this._parseContext(st.request ?? this._skeleton(c.required_context?.request, c));
    const sto = this._parseContext(st.stored ?? this._skeleton(c.required_context?.stored));
    if (req.error || sto.error) {
      this._trySet(c.name, { error: t('fix the JSON first'), result: undefined });
      return;
    }
    const request = req.value;
    const stored = sto.value;
    this._trySet(c.name, { busy: true, error: '', result: undefined });
    try {
      const r = await api.evaluateCondition(this.store, c.name, { request, stored });
      this._trySet(c.name, { busy: false, result: r.result });
    } catch (e) {
      this._trySet(c.name, { busy: false, error: forbiddenText(e) });
    }
  }

  _tryPanel(c) {
    const st = this._tryState(c.name);
    const req = st.request ?? this._skeleton(c.required_context?.request, c);
    const stored = st.stored ?? this._skeleton(c.required_context?.stored);
    const reqP = this._parseContext(req);
    const stoP = this._parseContext(stored);
    const warn = (p) => (p.error ? html`<span class="json-warn">⚠ ${p.error}</span>` : nothing);
    return html`<div class="try-cond">
      <div class="detail-head">
        <span
          >${t('Try it')}
          ${help('Evaluates the expression against the two contexts below, with no tuple involved: $1 / request is what a check would send, $2 / stored is what a tuple carrying this condition would store. Missing required keys are reported as the engine would. The placeholder __now__ (also __now__+2h, __now__-30m, __now__+1d) becomes the current instant as timestamptz text just before the JSON is parsed; time-like keys (*_time, *_at) start with it.')}</span
        >
      </div>
      ${
        c.time_source === 'server'
          ? html`<span class="help"
              >${t("server time: current_time comes from the engine's clock, not from this context")}</span
            >`
          : nothing
      }
      <label class="field"
        ><span>${t('Request context')} <span class="mono muted">$1</span></span
        ><pgc-json
          rows="4"
          .value=${req}
          @json-input=${(e) => this._trySet(c.name, { request: e.detail.text })}
        ></pgc-json>
        ${warn(reqP)}
      </label>
      <label class="field"
        ><span>${t('Stored context (mocked tuple)')} <span class="mono muted">$2</span></span
        ><pgc-json
          rows="4"
          .value=${stored}
          @json-input=${(e) => this._trySet(c.name, { stored: e.detail.text })}
        ></pgc-json>
        ${warn(stoP)}
      </label>
      <div class="actions">
        <button
          class="sm primary"
          ?disabled=${st.busy || !this.caps?.can_run_tests || !!reqP.error || !!stoP.error}
          @click=${() => this._tryCondition(c)}
        >
          ${t('Evaluate')}
        </button>
        ${st.result === true ? html`<span class="badge ok">${t('true')}</span>` : nothing}
        ${st.result === false ? html`<span class="badge deny">${t('false')}</span>` : nothing}
        ${st.error ? html`<span class="error">${st.error}</span>` : nothing}
        ${!this.caps?.can_run_tests ? html`<span class="help">${t('needs "run tests"')}</span>` : nothing}
        <button
          type="button"
          class="sm"
          title=${t('Rebuild both contexts from the required keys (time-like keys get __now__)')}
          @click=${() => this._trySet(c.name, { request: undefined, stored: undefined, result: undefined, error: '' })}
        >
          ${t('Reset')}
        </button>
      </div>
    </div>`;
  }

  _q(v) {
    return "'" + String(v).replace(/'/g, "''") + "'";
  }

  _conditionSQL(c) {
    const args = [
      this._q(this.store),
      this._q(c.name),
      this._q(c.expression),
      `p_lang => ${this._q(c.lang || 'sql')}`,
    ];
    if (c.required_context)
      args.push(`p_required_context => ${this._q(JSON.stringify(c.required_context))}::jsonb`);
    if (c.time_source) args.push(`p_time_source => ${this._q(c.time_source)}`);
    if (c.description) args.push(`p_description => ${this._q(c.description)}`);
    return `SELECT authz.create_condition(${args.join(', ')});`;
  }

  _gateSQL(g) {
    const spec = { ...g.spec };
    delete spec.required_context; // derived by the engine on write
    return `SELECT authz.add_gate(${[this.store, g.object_type, g.relation, g.name].map((x) => this._q(x)).join(', ')}, ${this._q(JSON.stringify(spec, null, 2))});`;
  }

  _editCondition(c) {
    this.form = {
      name: c.name,
      lang: c.lang || 'sql',
      expression: c.expression,
      required_context: c.required_context ? JSON.stringify(c.required_context) : '',
      description: c.description ?? '',
      editing: true,
    };
    this.edit = 'add_condition';
    clearSelection(this);
    this.updateComplete.then(() =>
      this.querySelector('form.condition-form')?.scrollIntoView({ behavior: 'smooth', block: 'start' }),
    );
  }

  _gateMode(mode) {
    const m = mode ?? 'enforce';
    const cls = m === 'enforce' ? 'ok' : m === 'shadow' ? 'warn' : 'muted';
    return html`<span class="badge ${cls}">${m}</span>`;
  }

  _ruleText(r) {
    if (r.rule_type === 'direct')
      return html`<code>direct</code
        >${r.allow_object_wildcard ? html` <span class="badge muted">object *</span>` : nothing}`;
    if (r.rule_type === 'computed') return html`<code>${r.computed_relation}</code>`;
    return html`<code>${r.tupleset_computed}</code> ${t('from')} <code>${r.tupleset_relation}</code>`;
  }

  // Two rows: what a subject can do (permissions, derived) and what a
  // subject is (relations, assignable). An owner can move a name between the
  // rows; the engine refuses the move when tuples or direct rules are in the way.
  _relationRows() {
    const can = this._canEdit();
    const rels = byOrder(this.m.json.relations);
    const groups = {
      permission: rels.filter((r) => r.metadata?.kind === 'permission'),
      relation: rels.filter((r) => r.metadata?.kind !== 'permission'),
    };
    // Object types each relation is defined on, from the rules.
    const constraintsOf = (name) =>
      (this.m.json.relation_constraints ?? [])
        .filter((c) => c.relation === name)
        .sort((a, b) => a.object_type.localeCompare(b.object_type));
    const usedOn = (name) => [
      ...new Set(this.m.rules.filter((x) => x.relation === name).map((x) => x.object_type)),
    ];
    // The order shown: the unsaved draft when a row was dragged, else the saved one.
    const shown = (group) => {
      const saved = groups[group];
      const names = this.draft[group];
      return names ? names.map((n) => saved.find((r) => r.name === n)).filter(Boolean) : saved;
    };
    const dirty = (group) => {
      const d = this.draft[group];
      return !!d && d.join('\n') !== groups[group].map((r) => r.name).join('\n');
    };
    // Drag and drop: while a row is dragged over another, the draft moves it
    // there, so the table shows the result before anything is saved.
    const onDragStart = (group, name) => (e) => {
      this.dragging = { group, name };
      e.dataTransfer.effectAllowed = 'move';
      e.dataTransfer.setData('text/plain', name);
    };
    const onDragOver = (group, name) => (e) => {
      if (!this.dragging || this.dragging.group !== group || this.dragging.name === name) return;
      e.preventDefault();
      const order = shown(group).map((r) => r.name);
      const from = order.indexOf(this.dragging.name);
      const to = order.indexOf(name);
      if (from < 0 || to < 0 || from === to) return;
      order.splice(from, 1);
      order.splice(to, 0, this.dragging.name);
      this.draft = { ...this.draft, [group]: order };
    };
    const onDragEnd = () => (this.dragging = null);
    const save = async (group) => {
      const order = this.draft[group];
      const ok = await this._wrap(() =>
        api.modelBatch(
          this.store,
          order.map((name, n) => ({ op: 'set_relation_metadata', name, metadata: { ui_order: n + 1 } })),
        ),
      );
      if (ok) {
        this.draft = { ...this.draft, [group]: undefined };
        await this._load();
      }
    };
    const discard = (group) => (this.draft = { ...this.draft, [group]: undefined });

    const row = (group, label, helpText, otherKind, moveLabel) => {
      const filtering = !!(this.filters.relations ?? '').trim();
      const items = this._filtered('relations', shown(group), (r) => [
        r.name,
        r.description,
        this.m.rules
          .filter((x) => x.relation === r.name)
          .map((x) => x.object_type)
          .join(' '),
      ]);
      return html`<div class="rel-group">
        <div class="rel-row-head">
          <span class="badge ${group === 'permission' ? 'accent' : ''}">${t(label)}</span>
          ${help(helpText)}
          <span class="muted">${items.length}</span>
          ${can && items.length > 1 && !filtering ? html`<span class="help">${t('drag rows to reorder')}</span>` : nothing}
          ${filtering ? html`<span class="muted">${items.length} / ${shown(group).length}</span>` : nothing}
          ${
            dirty(group)
              ? html`<span class="actions order-save">
                  <button class="sm primary" ?disabled=${this.busy} @click=${() => save(group)}>
                    ${t('Save order')}
                  </button>
                  <button class="sm" @click=${() => discard(group)}>${t('Discard')}</button>
                </span>`
              : nothing
          }
        </div>
        ${
          items.length
            ? html`<div class="table-wrap">
                <table class="rel-table">
                  <colgroup>
                    <col class="c-grip" />
                    <col class="c-name" />
                    <col class="c-desc" />
                    <col class="c-on" />
                    <col class="c-constraints" />
                    <col class="c-payload" />
                    ${can ? html`<col class="c-actions" />` : nothing}
                  </colgroup>
                  <thead>
                    <tr>
                      <th class="num"></th>
                      <th>${t('Name')}</th>
                      <th>${t('Description')}</th>
                      <th>${t('Defined on')} ${help('The object types with a rule for this relation.')}</th>
                      <th>
                        ${t('Constraints')}
                        ${help('How many subjects may hold the relation on one object, per type: "direct" is enforced on every write (active tuples), "effective" is the advisory size of the resolved holder set. Declared on the Relation constraints tab; click one to edit it.')}
                      </th>
                      <th>
                        ${t('Payload')}
                        ${help('For actions recorded in the action log: the payload shape their events must have (record_event enforces it). Set with "Payload…".')}
                      </th>
                      ${can ? html`<th></th>` : nothing}
                    </tr>
                  </thead>
                  <tbody>
                    ${items.map(
                      (r) =>
                        html`<tr
                          class="${this.dragging?.name === r.name ? 'dragging' : ''} ${can && !filtering ? 'draggable' : ''}"
                          draggable=${can && !filtering ? 'true' : 'false'}
                          @dragstart=${onDragStart(group, r.name)}
                          @dragover=${onDragOver(group, r.name)}
                          @drop=${(e) => e.preventDefault()}
                          @dragend=${onDragEnd}
                        >
                          <td class="num muted">
                            ${can ? html`<span class="grip" title=${t('drag to reorder')}>⋮⋮</span>` : nothing}
                          </td>
                          <td class="mono">${r.name}</td>
                          <td class="muted">${r.description ?? ''}</td>
                          <td class="mono muted">${usedOn(r.name).join(', ')}</td>
                          <td class="constraints">
                            ${
                              constraintsOf(r.name).length
                                ? constraintsOf(r.name).map(
                                    (c) =>
                                      html`<button
                                        type="button"
                                        class="badge link"
                                        title=${t('relation constraint on {type}: click to edit', { type: c.object_type })}
                                        data-testid=${`model-relation-constraint-badge-${c.object_type}-${c.relation}`}
                                        ?disabled=${!can}
                                        @click=${() => this._openConstraint(c)}
                                      >
                                        ${usedOn(r.name).length > 1 ? `${c.object_type}: ` : ''}${[
                                          c.max_direct != null ? t('≤ {n} direct', { n: c.max_direct }) : '',
                                          c.max_effective != null
                                            ? t('≤ {n} effective', { n: c.max_effective })
                                            : '',
                                        ]
                                          .filter(Boolean)
                                          .join(' · ')}
                                      </button>`,
                                  )
                                : html`<span class="dim">—</span>`
                            }
                          </td>
                          <td>
                            ${
                              r.payload_schema
                                ? html`<span
                                    class="badge accent"
                                    title=${JSON.stringify(r.payload_schema)}
                                    data-testid=${`model-relation-payload-badge-${r.name}`}
                                    >${t('schema')}</span
                                  >`
                                : html`<span class="dim">—</span>`
                            }
                          </td>
                          ${
                            can
                              ? html`<td class="actions rel-actions">
                                  <button
                                    class="sm ghost"
                                    title=${t(moveLabel)}
                                    data-testid=${`model-relation-kind-${r.name}`}
                                    @click=${() => this._op('set_relation_kind', { name: r.name, kind: otherKind })}
                                  >
                                    ⇄
                                  </button>
                                  <button
                                    class="sm"
                                    title=${t('the payload shape events for this action must have')}
                                    data-testid=${`model-relation-payload-${r.name}`}
                                    @click=${() => this._editPayloadSchema(r)}
                                  >
                                    ${t('Payload…')}
                                  </button>
                                </td>`
                              : nothing
                          }
                        </tr>`,
                    )}
                  </tbody>
                </table>
              </div>`
            : html`<p class="muted">${t('none')}</p>`
        }
      </div>`;
    };
    return html`
      ${row('permission', 'What they can do (permissions)', 'What a subject can do: usually derived by computed and ttu rules (the engine refuses tuples on those), sometimes granted directly (a tool an agent may run). Check these when you want to know what a subject may do.', 'relation', 'make this a relation (what a subject is)')}
      ${row('relation', 'What they are (relations)', 'Relations are what a subject is: assignable by a tuple (viewer, owner, member) or a link (parent). They may also be inherited through rules.', 'permission', 'make this a permission (what a subject can do)')}
    `;
  }

  // The Structure card's sections, one tab each: id, label, the (?) text,
  // the add button (op, label) and the ops whose form belongs in it.
  static SECTIONS = [
    {
      id: 'types',
      label: 'Types',
      help: 'Object and subject types of this store. A type with tuples cannot be removed.',
      add: ['add_type', 'type'],
      ops: ['add_type', 'set_type_namespace', 'set_type_labels'],
    },
    {
      id: 'relations',
      label: 'Relations',
      help: 'Relation and permission names declared for this store; rules give them meaning per type. The order here (drag the rows, then Save order) is stored in the relation metadata as ui_order and used wherever the console lists them; it never affects evaluation.',
      add: ['add_relation', 'relation'],
      ops: ['add_relation', 'set_payload_schema'],
    },
    {
      id: 'rules',
      label: 'Rules',
      help: 'How each relation is defined on each type: direct (by tuple), computed (from another relation), ttu (from a related object). Rows with the same group form a union; other groups intersect or exclude.',
      add: ['add_rule', 'rule'],
      ops: ['add_rule'],
    },
    {
      id: 'restrictions',
      label: 'Type restrictions',
      help: 'Which subject types (or usersets like team#member) a direct relation accepts in tuples; the engine rejects other tuples.',
      add: ['add_restriction', 'type restriction'],
      ops: ['add_restriction'],
    },
    {
      id: 'conditions',
      label: 'Conditions',
      help: 'Named expressions evaluated at decision time against the request context; a tuple can carry one, and a type restriction can require one.',
      add: ['add_condition', 'condition'],
      ops: ['add_condition'],
    },
    {
      id: 'gates',
      label: 'Gates',
      help: 'History-dependent vetoes over the action log: quotas, prior approval, separation of duties. Evaluated after the graph allows, for the checked principal only; a gate never grants.',
      add: ['add_gate', 'gate'],
      ops: ['add_gate'],
    },
    {
      id: 'grant_rules',
      label: 'Grant rules',
      help: 'The sharing policy: which relation an actor needs on an object to grant — and to revoke — a relation on it through authz.grant / revoke, the path an application’s share dialog takes. Part of the model: versioned and rolled out with it.',
      add: ['add_grant_rule', 'grant rule'],
      ops: ['add_grant_rule'],
    },
    {
      id: 'relation_constraints',
      label: 'Relation constraints',
      help: 'How many subjects may hold a relation on one object: max_direct caps the active (unexpired) direct tuples per object and is enforced on every write — the one past the cap is refused; max_effective is the advisory size of the resolved holder set that relation_usage reports headroom against. Part of the model: versioned and rolled out with it.',
      add: ['set_relation_constraint', 'relation constraint'],
      ops: ['set_relation_constraint'],
    },
  ];

  // The active section: the URL's part (stores/<store>/model/<section>),
  // else the one last used in this browser, else types.
  _section() {
    const ids = PgcModel.SECTIONS.map((x) => x.id);
    if (ids.includes(this.section)) return this.section;
    try {
      const last = localStorage.getItem('pgc_model_section');
      if (ids.includes(last)) return last;
    } catch {
      /* storage unavailable */
    }
    return 'types';
  }

  _openForm(op) {
    this.edit = op;
    this.form = {};
    clearSelection(this);
  }

  _cells() {
    const can = this._canEdit();
    return {
      can,
      sel: (key) => (can ? selectionCell(this, key) : nothing),
      selAll: (keys) => (can ? selectAllCell(this, keys) : nothing),
    };
  }

  // A section's head line: its title with the (?) text, the filter, and —
  // for editors — the add button whose form opens right below, inside the
  // section, so nothing jumps.
  _panelHead(sec, shown, total) {
    return html`<div class="toolbar panel-head">
      <h3>${t(sec.label)} ${help(sec.help)}</h3>
      ${this._filterBox(sec.id, shown, total)}
      ${
        this._canEdit()
          ? html`<button
              class="sm"
              data-testid=${'model-' + sec.add[0].replaceAll('_', '-')}
              @click=${() => this._openForm(sec.add[0])}
            >
              + ${t(sec.add[1])}
            </button>`
          : nothing
      }
    </div>`;
  }

  _panelTypes(sec) {
    const m = this.m;
    const { can, sel, selAll } = this._cells();
    const vis = this._filtered('types', m.json.types, (x) => [
      x.name,
      x.namespace,
      x.description,
      (x.labels ?? []).join(' '),
    ]);
    return html`${this._panelHead(sec, vis.length, m.json.types.length)}
      ${sec.ops.includes(this.edit) ? this._forms() : nothing}
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              ${selAll(vis.map((x) => 'type:' + x.name))} ${this._sortTh('types', 'name', t('Type'))}
              ${this._sortTh('types', 'namespace', t('Namespace'), help('The application or team the type belongs to; namespace roles (Access tab) edit inside it. Changing it is a store-wide change.'))}
              ${this._sortTh('types', 'description', t('Description'), undefined, 'wide')}
              ${this._sortTh('types', 'labels', t('Labels'), help('Advisory key:value tags on a type (group:accounting, tier:core) for grouping and tooling; no access-control effect.'))}
              ${can ? html`<th></th>` : nothing}
            </tr>
          </thead>
          <tbody>
            ${vis.map(
              (x) =>
                html`<tr data-testid=${`model-type-row-${x.name}`}>
                  ${sel('type:' + x.name)}
                  <td class="mono">${x.name}</td>
                  <td>
                    ${x.namespace ? html`<span class="badge muted">${x.namespace}</span>` : html`<span class="dim">${t('store-wide')}</span>`}
                  </td>
                  <td class="muted">${x.description ?? ''}</td>
                  <td>
                    <div class="chips" data-testid=${`model-type-labels-${x.name}`}>
                      ${(x.labels ?? []).map((l) => html`<span class="chip">${l}</span>`)}
                    </div>
                  </td>
                  ${
                    can
                      ? html`<td class="actions">
                          ${
                            this.caps?.can_edit_model
                              ? html`<button
                                  class="sm"
                                  data-testid=${`model-type-namespace-${x.name}`}
                                  @click=${() => this._editTypeNamespace(x)}
                                >
                                  ${t('Namespace…')}
                                </button>`
                              : nothing
                          }
                          <button
                            class="sm"
                            data-testid=${`model-type-labels-edit-${x.name}`}
                            @click=${() => this._editTypeLabels(x)}
                          >
                            ${t('Labels…')}
                          </button>
                        </td>`
                      : nothing
                  }
                </tr>`,
            )}
          </tbody>
        </table>
      </div>
      ${
        this._namespaces().length
          ? html`<div class="ns-summary">
              <span class="muted">${t('Namespaces')}:</span>
              ${this._namespaces().map(
                (ns) =>
                  html`<span class="chip">
                    ${ns}
                    <span class="muted">(${m.json.types.filter((x) => x.namespace === ns).length})</span>
                    ${
                      this.caps?.can_edit_model && this.caps?.can_manage_access
                        ? html`<button
                            type="button"
                            class="link"
                            @click=${() => {
                              this.renaming = ns;
                              this.renameTo = ns;
                            }}
                          >
                            ${t('rename')}
                          </button>`
                        : nothing
                    }
                  </span>`,
              )}
              ${
                this.renaming
                  ? html`<form class="inline" @submit=${this._renameNamespace}>
                      <span class="mono">${this.renaming}</span> →
                      <input
                        class="mono"
                        required
                        pattern="[A-Za-z_][A-Za-z0-9_.-]*"
                        .value=${this.renameTo}
                        @input=${(e) => (this.renameTo = e.target.value)}
                      />
                      <button class="sm primary" ?disabled=${this.busy || this.renameTo === this.renaming}>
                        ${t('Rename')}
                      </button>
                      <button type="button" class="sm" @click=${() => (this.renaming = null)}>
                        ${t('Cancel')}
                      </button>
                      ${help('Moves every type of the namespace and the namespace role assignments to the new name, in one transaction.')}
                    </form>`
                  : nothing
              }
            </div>`
          : nothing
      }`;
  }

  _panelRelations(sec) {
    return html`${this._panelHead(sec, '', '')} ${sec.ops.includes(this.edit) ? this._forms() : nothing}
    ${this._relationRows()}`;
  }

  _panelRules(sec) {
    const m = this.m;
    const { sel, selAll } = this._cells();
    // searchable text = the raw fields plus the forms the rows render
    // (doc.viewer, "viewer from parent")
    const vis = this._filtered('rules', m.rules, (r) => [
      '#' + r.id,
      r.object_type,
      r.relation,
      `${r.object_type}.${r.relation}`,
      r.rule_type,
      r.computed_relation,
      r.tupleset_relation && `${r.tupleset_computed} from ${r.tupleset_relation}`,
      r.group_op,
    ]);
    return html`${this._panelHead(sec, vis.length, m.rules.length)}
      ${sec.ops.includes(this.edit) ? this._forms() : nothing}
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              ${selAll(vis.map((r) => 'rule:' + r.id))} ${this._sortTh('rules', 'id', 'ID')}
              ${this._sortTh('rules', 'object_type', t('Object type'))}
              ${this._sortTh('rules', 'relation', t('Relation'))}
              ${this._sortTh('rules', 'defined', t('Defined as'), undefined, 'wide')}
              ${this._sortTh('rules', 'group', t('Group'))}
            </tr>
          </thead>
          <tbody>
            ${vis.map(
              (r) =>
                html`<tr>
                  ${sel('rule:' + r.id)} ${this._idCell(r.id)}
                  <td class="mono">${r.object_type}</td>
                  <td class="mono">${r.relation}</td>
                  <td>
                    ${r.negated ? html`<span class="badge deny">${t('not')}</span> ` : nothing}${this._ruleText(r)}
                  </td>
                  <td>
                    ${r.group_id}${r.group_op !== 'or' ? html` <span class="badge warn">${r.group_op}</span>` : nothing}
                  </td>
                </tr>`,
            )}
          </tbody>
        </table>
      </div>`;
  }

  _panelRestrictions(sec) {
    const m = this.m;
    const { sel, selAll } = this._cells();
    const vis = this._filtered('restrictions', m.restrictions, (x) => [
      '#' + x.id,
      x.object_type,
      x.relation,
      `${x.object_type}.${x.relation}`,
      x.allowed_user_relation ? `${x.allowed_user_type}#${x.allowed_user_relation}` : x.allowed_user_type,
      x.allow_wildcard && `${x.allowed_user_type}:*`,
      x.condition,
    ]);
    return html`${this._panelHead(sec, vis.length, m.restrictions.length)}
      ${sec.ops.includes(this.edit) ? this._forms() : nothing}
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              ${selAll(vis.map((x) => 'restriction:' + x.id))} ${this._sortTh('restrictions', 'id', 'ID')}
              ${this._sortTh('restrictions', 'object_type', t('Object type'))}
              ${this._sortTh('restrictions', 'relation', t('Relation'))}
              ${this._sortTh('restrictions', 'accepts', t('Accepts'))}
              ${this._sortTh('restrictions', 'condition', t('Condition'))}
            </tr>
          </thead>
          <tbody>
            ${vis.map(
              (x) =>
                html`<tr>
                  ${sel('restriction:' + x.id)} ${this._idCell(x.id)}
                  <td class="mono">${x.object_type}</td>
                  <td class="mono">${x.relation}</td>
                  <td class="mono">
                    ${x.allowed_user_type}${x.allowed_user_relation ? '#' + x.allowed_user_relation : ''}${x.allow_wildcard ? ', *' : ''}
                  </td>
                  <td class="mono">${x.condition ?? ''}</td>
                </tr>`,
            )}
          </tbody>
        </table>
      </div>`;
  }

  _panelConditions(sec) {
    const m = this.m;
    const { can, sel, selAll } = this._cells();
    const vis = this._filtered('conditions', m.json.conditions, (c) => [
      c.name,
      c.description,
      c.lang,
      c.expression,
    ]);
    return html`${this._panelHead(sec, vis.length, m.json.conditions.length)}
    ${sec.ops.includes(this.edit) ? this._forms() : nothing}
    ${
      m.json.conditions.length
        ? html`<div class="table-wrap">
            <table>
              <thead>
                <tr>
                  ${selAll(vis.map((c) => 'condition:' + c.name))}
                  ${this._sortTh('conditions', 'name', t('Name'))}
                  ${this._sortTh('conditions', 'description', t('Description'), undefined, 'wide')}
                  ${this._sortTh('conditions', 'lang', t('Language'))}
                  ${this._sortTh('conditions', 'created', t('Created at'))}
                  ${this._sortTh('conditions', 'updated', t('Updated at'))}
                  <th></th>
                </tr>
              </thead>
              <tbody>
                ${vis.map((c) => {
                  const key = 'condition:' + c.name;
                  const tm = m.condition_times?.[c.name];
                  return html`<tr>
                      ${sel(key)}
                      <td class="mono">${c.name}</td>
                      <td class="muted">${c.description ?? ''}</td>
                      <td>${c.lang}</td>
                      <td class="muted nowrap" title=${tm?.created_at ?? ''}>
                        ${tm ? fmtTime(tm.created_at) : ''}
                      </td>
                      <td class="muted nowrap" title=${tm?.updated_at ?? ''}>
                        ${tm ? fmtRelative(tm.updated_at) : ''}
                      </td>
                      <td class="actions">
                        <button class="sm" @click=${() => this._toggleDetail(key)}>
                          ${this.detail.has(key) ? t('Hide') : t('Details')}
                        </button>
                        ${can ? html`<button class="sm" data-testid=${`model-condition-edit-${c.name}`} @click=${() => this._editCondition(c)}>${t('Edit')}</button>` : nothing}
                      </td>
                    </tr>
                    ${this.detail.has(key) ? this._detailRow(7, this._conditionSQL(c), c, this._tryPanel(c)) : nothing}`;
                })}
              </tbody>
            </table>
          </div>`
        : html`<p class="help">${t('No conditions in this model.')}</p>`
    }`;
  }

  _panelGates(sec) {
    const m = this.m;
    const { can, sel, selAll } = this._cells();
    const gates = m.json.gates ?? [];
    const vis = this._filtered('gates', gates, (g) => [
      `${g.object_type}.${g.relation}`,
      g.name,
      g.spec?.description,
      g.spec?.mode ?? 'enforce',
      JSON.stringify(g.spec?.all_of ?? []),
    ]);
    return html`${this._panelHead(sec, vis.length, gates.length)}
    ${sec.ops.includes(this.edit) ? this._forms() : nothing}
    ${
      gates.length
        ? html`<div class="table-wrap">
            <table>
              <thead>
                <tr>
                  ${selAll(vis.map((g) => this._gateKey(g)))} ${this._sortTh('gates', 'on', t('On'))}
                  ${this._sortTh('gates', 'name', t('Name'))} ${this._sortTh('gates', 'mode', t('Mode'))}
                  ${this._sortTh('gates', 'clauses', t('Clauses'))}
                  <th></th>
                </tr>
              </thead>
              <tbody>
                ${vis.map(
                  (g) =>
                    html`<tr data-testid=${`model-gate-${g.object_type}-${g.relation}-${g.name}`}>
                        ${sel(this._gateKey(g))}
                        <td class="mono">${g.object_type}.${g.relation}</td>
                        <td>
                          <span class="mono">${g.name}</span>
                          ${g.spec.description ? html`<div class="help">${g.spec.description}</div>` : nothing}
                        </td>
                        <td>${this._gateMode(g.spec.mode)}</td>
                        <td>
                          <ul class="clauses">
                            ${(g.spec.all_of ?? []).map((c) => html`<li>${this._clauseText(c)}</li>`)}
                          </ul>
                        </td>
                        <td class="actions">
                          <button class="sm" @click=${() => this._toggleDetail(this._gateKey(g))}>
                            ${this.detail.has(this._gateKey(g)) ? t('Hide') : t('Details')}
                          </button>
                          ${can ? html`<button class="sm" data-testid=${`model-gate-edit-${g.object_type}-${g.relation}-${g.name}`} @click=${() => this._editGate(g)}>${t('Edit')}</button>` : nothing}
                        </td>
                      </tr>
                      ${this.detail.has(this._gateKey(g)) ? this._detailRow(6, this._gateSQL(g), g.spec) : nothing}`,
                )}
              </tbody>
            </table>
          </div>`
        : html`<p class="help">${t('No temporal gates in this model.')}</p>`
    }`;
  }

  _panelGrantRules(sec) {
    const m = this.m;
    const { can, sel, selAll } = this._cells();
    const rules = m.json.grant_rules ?? [];
    const vis = this._filtered('grant_rules', rules, (g) => [
      `${g.object_type}.${g.relation}`,
      g.object_type,
      g.relation,
      g.requires,
      g.requires_revoke,
    ]);
    return html`${this._panelHead(sec, vis.length, rules.length)}
    ${sec.ops.includes(this.edit) ? this._forms() : nothing}
    ${
      rules.length
        ? html`<div class="table-wrap">
            <table data-testid="model-grant-rules">
              <thead>
                <tr>
                  ${selAll(vis.map((g) => this._grantKey(g)))}
                  ${this._sortTh('grant_rules', 'object_type', t('Object type'))}
                  ${this._sortTh('grant_rules', 'relation', t('Relation granted'))}
                  ${this._sortTh('grant_rules', 'requires', t('To grant, the actor needs'))}
                  ${this._sortTh('grant_rules', 'requires_revoke', t('To revoke, the actor needs'))}
                  <th></th>
                </tr>
              </thead>
              <tbody>
                ${vis.map(
                  (g) =>
                    html`<tr data-testid=${`model-grant-rule-${g.object_type}-${g.relation}`}>
                        ${sel(this._grantKey(g))}
                        <td class="mono">${g.object_type}</td>
                        <td class="mono">${g.relation}</td>
                        <td class="mono">${g.requires}</td>
                        <td class="mono">
                          ${g.requires_revoke ?? html`<span class="dim">${t('same as to grant')}</span>`}
                        </td>
                        <td class="actions">
                          <button class="sm" @click=${() => this._toggleDetail(this._grantKey(g))}>
                            ${this.detail.has(this._grantKey(g)) ? t('Hide') : t('Details')}
                          </button>
                          ${can ? html`<button class="sm" data-testid=${`model-grant-rule-edit-${g.object_type}-${g.relation}`} @click=${() => this._editGrantRule(g)}>${t('Edit')}</button>` : nothing}
                        </td>
                      </tr>
                      ${this.detail.has(this._grantKey(g)) ? this._detailRow(6, this._grantSQL(g), g) : nothing}`,
                )}
              </tbody>
            </table>
          </div>`
        : html`<p class="help">
            ${t('No grant rules in this model: nothing can be shared through authz.grant. Add one to let, say, anyone with can_share grant viewer.')}
          </p>`
    }`;
  }

  _panelRelationConstraints(sec) {
    const m = this.m;
    const { can, sel, selAll } = this._cells();
    const rows = m.json.relation_constraints ?? [];
    const vis = this._filtered('relation_constraints', rows, (c) => [
      `${c.object_type}.${c.relation}`,
      c.object_type,
      c.relation,
      c.max_direct,
      c.max_effective,
    ]);
    return html`${this._panelHead(sec, vis.length, rows.length)}
    ${sec.ops.includes(this.edit) ? this._forms() : nothing}
    ${
      rows.length
        ? html`<div class="table-wrap">
            <table data-testid="model-relation-constraints">
              <thead>
                <tr>
                  ${selAll(vis.map((c) => this._constraintKey(c)))}
                  ${this._sortTh('relation_constraints', 'object_type', t('Object type'))}
                  ${this._sortTh('relation_constraints', 'relation', t('Relation'))}
                  ${this._sortTh('relation_constraints', 'max_direct', t('Max direct (enforced)'))}
                  ${this._sortTh('relation_constraints', 'max_effective', t('Max effective (advisory)'))}
                  <th></th>
                </tr>
              </thead>
              <tbody>
                ${vis.map(
                  (c) =>
                    html`<tr data-testid=${`model-relation-constraint-${c.object_type}-${c.relation}`}>
                        ${sel(this._constraintKey(c))}
                        <td class="mono">${c.object_type}</td>
                        <td class="mono">${c.relation}</td>
                        <td class="mono">${c.max_direct ?? html`<span class="dim">${t('none')}</span>`}</td>
                        <td class="mono">
                          ${c.max_effective ?? html`<span class="dim">${t('none')}</span>`}
                        </td>
                        <td class="actions">
                          <button class="sm" @click=${() => this._toggleDetail(this._constraintKey(c))}>
                            ${this.detail.has(this._constraintKey(c)) ? t('Hide') : t('Details')}
                          </button>
                          ${can ? html`<button class="sm" data-testid=${`model-relation-constraint-edit-${c.object_type}-${c.relation}`} @click=${() => this._editConstraint(c)}>${t('Edit')}</button>` : nothing}
                        </td>
                      </tr>
                      ${this.detail.has(this._constraintKey(c)) ? this._detailRow(6, this._constraintSQL(c), c) : nothing}`,
                )}
              </tbody>
            </table>
          </div>`
        : html`<p class="help">
            ${t('No relation constraints in this model: a relation may hold any number of subjects on an object. Add one to cap, say, viewer on document at 50.')}
          </p>`
    }`;
  }

  // The Structure card: one tab per section (the URL carries it, so a
  // section can be linked and tested), the section's add button and form
  // inside its panel, and the selection bar above the tabs — a selection
  // spans sections (a type with its rules), so it stays in view on every tab.
  _editor() {
    const m = this.m;
    const can = this._canEdit();
    const active = this._section();
    const counts = {
      types: m.json.types.length,
      relations: m.json.relations.length,
      rules: m.rules.length,
      restrictions: m.restrictions.length,
      conditions: m.json.conditions.length,
      gates: (m.json.gates ?? []).length,
      grant_rules: (m.json.grant_rules ?? []).length,
      relation_constraints: (m.json.relation_constraints ?? []).length,
    };
    const sec = PgcModel.SECTIONS.find((x) => x.id === active);
    const panel = {
      types: () => this._panelTypes(sec),
      relations: () => this._panelRelations(sec),
      rules: () => this._panelRules(sec),
      restrictions: () => this._panelRestrictions(sec),
      conditions: () => this._panelConditions(sec),
      gates: () => this._panelGates(sec),
      grant_rules: () => this._panelGrantRules(sec),
      relation_constraints: () => this._panelRelationConstraints(sec),
    }[active];
    return html` <section class="card" data-testid="model-structure">
      <div class="toolbar">
        <h3>
          ${t('Structure')}
          ${help('The model as the engine stores it, one section per tab. Each change is one engine call, applied immediately and audited as you; adding and editing happens inside the section.')}
        </h3>
        ${can ? nothing : html`<span class="help">${t('read-only: editing needs "edit model" (author or owner)')}</span>`}
      </div>
      ${removeBar(this, {
        one: 'item',
        many: 'items',
        describe: (k) => this._describe(k),
        warning:
          'A type can only go when no tuples reference it; rules and type restrictions are removed before types.',
        onConfirm: () => this._removeSelected(),
      })}
      <nav class="tabs sub" aria-label=${t('Sections')} data-testid="model-sections">
        ${PgcModel.SECTIONS.map(
          (x) =>
            html`<a
              href="stores/${this.store}/model/${x.id}"
              class=${x.id === active ? 'active' : ''}
              data-testid=${'model-section-' + x.id}
              >${t(x.label)} <span class="count">${counts[x.id]}</span></a
            >`,
        )}
      </nav>
      <div class="panel" data-testid=${'model-panel-' + active}>${panel()}</div>
    </section>`;
  }

  render() {
    const m = this.m;
    if (!m) return html`${this.error ? errorBox(this.error) : loading()}`;
    const views = [
      ['dsl', 'DSL', 'OpenFGA-style; display only (conditions, gates, grant rules have no DSL form)'],
      ['json', 'JSON', 'the canonical export — what publish stores in the registry'],
      ['sql', 'SQL', 'the engine calls that rebuild this model; runnable in psql'],
    ];
    return html`
      ${this.error ? errorBox(this.error) : nothing}
      <div class="stats model-stats">
        <span
          >${statusBadge(this.info?.status)}
          ${help('Whether the store runs a registry version (name@version), and whether its live model still matches it.')}</span
        >
        <span><b>${m.json.types.length}</b> ${t('types')}</span>
        <span><b>${m.json.relations.length}</b> ${t('relations')}</span>
        <span><b>${m.rules.length}</b> ${t('rules')}</span>
        <span><b>${m.restrictions.length}</b> ${t('type restrictions')}</span>
        <span><b>${m.json.conditions.length}</b> ${t('conditions')}</span>
        ${m.json.gates?.length ? html`<span><b>${m.json.gates.length}</b> ${t('gates')}</span>` : nothing}
        ${m.json.grant_rules?.length ? html`<span><b>${m.json.grant_rules.length}</b> ${t('grant rules')}</span>` : nothing}
        ${m.json.relation_constraints?.length ? html`<span><b>${m.json.relation_constraints.length}</b> ${t('relation constraints')}</span>` : nothing}
      </div>
      ${
        this.dslReport
          ? html`<p class="notice">
              ${t(
                'Model applied: {types} types, {relations} relations, {rules} rules, {restrictions} type restrictions.',
                {
                  types: this.dslReport.types?.length ?? 0,
                  relations: this.dslReport.relations?.length ?? 0,
                  rules: this.dslReport.rules_imported ?? 0,
                  restrictions: this.dslReport.type_restrictions_imported ?? 0,
                },
              )}
              ${(this.dslReport.warnings ?? []).map((w) => html`<div class="help">${w}</div>`)}
            </p>`
          : nothing
      }
      ${
        this.dslEdit
          ? html`<section class="card">
              <div class="code-head">
                <h3>
                  ${t('Edit the model as DSL')}
                  ${help('Write the model in the OpenFGA-style DSL shown in the DSL view. Applying ADDS types and relations, REPLACES all rules and type restrictions with what the text says, and infers relation kinds (no direct rule = permission). Conditions, temporal gates and grant rules are not expressed here and stay as they are.')}
                </h3>
                <span class="help">${t('types, relations, rules and type restrictions')}</span>
              </div>
              <div class="editor">
                <pre class="gutter" aria-hidden="true">
${Array.from({ length: Math.max(1, this.dslText.split('\n').length) }, (_, i) => i + 1).join('\n')}</pre>
                <textarea
                  class="mono dsl-editor"
                  spellcheck="false"
                  rows="18"
                  .value=${this.dslText}
                  @input=${(e) => (this.dslText = e.target.value)}
                  @scroll=${(e) => (e.target.previousElementSibling.scrollTop = e.target.scrollTop)}
                ></textarea>
              </div>
              <div class="actions" style="margin-top:var(--s-3)">
                <button class="primary" ?disabled=${this.busy} @click=${this._applyDSL}>
                  ${t('Apply model')}
                </button>
                <button @click=${() => (this.dslEdit = false)}>${t('Cancel')}</button>
                <span class="help"
                  >${t('Replaces the rules and type restrictions of this store; runs as you and is recorded.')}</span
                >
              </div>
            </section>`
          : nothing
      }
      <details
        class="card definition"
        ?hidden=${this.dslEdit}
        ?open=${this.defOpen}
        @toggle=${this._toggleDef}
      >
        <summary>
          <span class="caps-label">${t('Model definition')}</span>
          <span class="help"
            >${t('the whole model as text — DSL, JSON or SQL; collapsed by default, the Structure below is where you work')}</span
          >
        </summary>
        <div class="code-head">
          <div class="seg">
            ${views.map(([v, l, tip]) => html`<button class=${this.view === v ? 'active' : ''} title=${t(tip)} @click=${() => (this.view = v)}>${l}</button>`)}
          </div>
          <span class="help">${t(views.find(([v]) => v === this.view)[2])}</span>
          ${this.caps?.can_edit_model ? html`<button class="sm" @click=${this._openDSL}>${t('Edit as DSL')}</button>` : nothing}
          <button class="sm" @click=${this._copy}>${this.copied ? t('Copied') : t('Copy')}</button>
        </div>
        <pre class="code">
${this.view === 'json' ? highlightJSON(JSON.stringify(m.json, null, 2)) : this.view === 'sql' ? highlightSQL(m.sql) : highlightDSL(m.dsl)}</pre>
      </details>
      ${this._editor()}
    `;
  }
}
customElements.define('pgc-model', PgcModel);
