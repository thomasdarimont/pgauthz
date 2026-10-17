import { html, nothing } from 'lit';
import { PgcElement, help } from '../base.js';
import { api } from '../api.js';
import { t } from '../i18n.js';
import { run, copyText, forbiddenText, byOrder, statusBadge, fmtTime, fmtRelative } from '../util.js';
import { selectionCell, selectAllCell, removeBar, clearSelection } from './pgc-select.js';
import { highlightDSL, highlightSQL, highlightJSON } from '../highlight.js';

// Model tab. Three read views of the SAME live model — DSL (OpenFGA-style,
// lossy), JSON (the registry's canonical export) and SQL (the engine calls
// that rebuild it; copy-and-run) — plus the structured editor, whose
// vocabulary is exactly the engine's model_* API. Edits are live: each one
// is a call as you, audited and recorded. Removal goes through selection and
// a confirmation, one transaction for all selected items.
export class PgcModel extends PgcElement {
  static properties = {
    store: { type: String },
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
    tryCond: { state: true }, // per-condition try-it state (contexts, result)
    renaming: { state: true }, // namespace being renamed
    renameTo: { state: true },
  };

  constructor() {
    super();
    this.m = null;
    this.view = 'dsl';
    this.busy = false;
    this.error = '';
    this.copied = false;
    this.edit = null; // which add-form is open
    this.form = {};
    this.selected = new Set(); // keys: type:<name> | rule:<id> | restriction:<id> | condition:<name>
    this.confirming = false;
    this.dslEdit = false; // the DSL view as an editor
    this.dslText = '';
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
    this.tryCond = {};
    this.draft = {}; // unsaved drag order per group: { permission: [names], relation: [names] }
    this.dragging = null; // { group, name } while a row is being dragged
  }

  willUpdate(changed) {
    if (changed.has('store') && this.store) this._load();
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
    const order = { gate: 0, rule: 1, restriction: 2, condition: 3, type: 4 };
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
                : { op: 'remove_type', name: id },
      );
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
      if (f.required_context) {
        try {
          f.required_context = JSON.parse(f.required_context);
        } catch {
          this.error = t('required context must be JSON');
          return;
        }
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
      <button class="primary" ?disabled=${this.busy}>${t(label)}</button>
      <button type="button" @click=${() => (this.edit = null)}>${t('Cancel')}</button>
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
            ><input class="mono" list="dl-namespaces" placeholder="billing" @input=${this._set('namespace')}
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
                  ><input
                    class="mono"
                    list="dl-rels"
                    placeholder="viewer, owner"
                    @input=${this._set('derived_from')}
                /></label>`
              : html`<label class="field wide"
                  ><span
                    >${t('Accepts subject types')}
                    ${help('Type restrictions for the tuples of this relation on each selected type: "user" a user; "team#member" the members of a team (userset); "user:*" also the wildcard for everyone of that type. Empty = no restriction (any subject).')}</span
                  ><input
                    class="mono"
                    list="dl-types"
                    placeholder="user, team#member, user:*"
                    @input=${this._set('accepts')}
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
              ${help('SQL: $1 is the request context, $2 the tuple context (jsonb). CEL: request and tuple variables.')}</span
            ><textarea
              class="mono"
              rows="2"
              required
              placeholder="($1->>'ip')::inet << '10.0.0.0/8'::inet"
              .value=${f.expression ?? ''}
              @input=${this._set('expression')}
            ></textarea>
          </label>
          <label class="field wide"
            ><span
              >${t('Required context (JSON, optional)')}
              ${help('Keys the request must supply; a decision without them is "conditional", not a silent deny.')}</span
            ><input
              class="mono"
              placeholder='{"request": ["ip"]}'
              .value=${f.required_context ?? ''}
              @input=${this._set('required_context')}
          /></label>
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
              placeholder=${t('empty = store-wide')}
              .value=${f.namespace ?? ''}
              @input=${this._set('namespace')}
          /></label>
          <datalist id="dl-namespaces">
            ${this._namespaces().map((n) => html`<option value=${n}></option>`)}
          </datalist>
          ${this._formActions('Save namespace')}
        </form>`;
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
            <textarea
              class="mono"
              rows="8"
              required
              placeholder='[{"count_within": {"window": "1h", "max": 5, "plus": 1}}]'
              .value=${f.all_of ?? ''}
              @input=${this._set('all_of')}
            ></textarea>
            ${
              clauses
                ? html`<ul class="clauses">
                    ${clauses.map((c) => html`<li>${this._clauseText(c)}</li>`)}
                  </ul>`
                : html`<span class="error">${t('not valid JSON')}</span>`
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
  _filtered(section, items, fields) {
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
          placeholder=${t('filter… (#id for one item)')}
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
        ><textarea
          class="mono ${reqP.error ? 'invalid' : ''}"
          rows="4"
          spellcheck="false"
          .value=${req}
          @input=${(e) => this._trySet(c.name, { request: e.target.value })}
        ></textarea>
        ${warn(reqP)}
      </label>
      <label class="field"
        ><span>${t('Stored context (mocked tuple)')} <span class="mono muted">$2</span></span
        ><textarea
          class="mono ${stoP.error ? 'invalid' : ''}"
          rows="4"
          spellcheck="false"
          .value=${stored}
          @input=${(e) => this._trySet(c.name, { stored: e.target.value })}
        ></textarea>
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
                  <thead>
                    <tr>
                      <th class="num"></th>
                      <th>${t('Name')}</th>
                      <th>${t('Description')}</th>
                      <th>${t('Defined on')} ${help('The object types with a rule for this relation.')}</th>
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
                          ${
                            can
                              ? html`<td class="actions rel-actions">
                                  <button
                                    class="sm ghost"
                                    title=${t(moveLabel)}
                                    @click=${() => this._op('set_relation_kind', { name: r.name, kind: otherKind })}
                                  >
                                    ⇄
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

  _editor() {
    const m = this.m;
    const can = this._canEdit();
    const sel = (key) => (can ? selectionCell(this, key) : nothing);
    const selAll = (keys) => (can ? selectAllCell(this, keys) : nothing);
    const vis = {
      types: this._filtered('types', m.json.types, (x) => [x.name, x.namespace, x.description]),
      // searchable text = the raw fields plus the forms the rows render
      // (team#member, user:*, doc.viewer, "viewer from parent")
      rules: this._filtered('rules', m.rules, (r) => [
        '#' + r.id,
        r.object_type,
        r.relation,
        `${r.object_type}.${r.relation}`,
        r.rule_type,
        r.computed_relation,
        r.tupleset_relation && `${r.tupleset_computed} from ${r.tupleset_relation}`,
        r.group_op,
      ]),
      restrictions: this._filtered('restrictions', m.restrictions, (x) => [
        '#' + x.id,
        x.object_type,
        x.relation,
        `${x.object_type}.${x.relation}`,
        x.allowed_user_relation ? `${x.allowed_user_type}#${x.allowed_user_relation}` : x.allowed_user_type,
        x.allow_wildcard && `${x.allowed_user_type}:*`,
        x.condition,
      ]),
      conditions: this._filtered('conditions', m.json.conditions, (c) => [
        c.name,
        c.description,
        c.lang,
        c.expression,
      ]),
      gates: this._filtered('gates', m.json.gates ?? [], (g) => [
        `${g.object_type}.${g.relation}`,
        g.name,
        g.spec?.description,
        g.spec?.mode ?? 'enforce',
        JSON.stringify(g.spec?.all_of ?? []),
      ]),
    };
    const addButtons = [
      ['add_type', 'type'],
      ['add_relation', 'relation'],
      ['add_rule', 'rule'],
      ['add_restriction', 'type restriction'],
      ['add_condition', 'condition'],
      ['add_gate', 'gate'],
    ];
    return html` <section class="card">
      <div class="toolbar">
        <h3>
          ${t('Structure')}
          ${help('The model as the engine stores it. Each change below is one engine call, applied immediately and audited as you.')}
        </h3>
        ${
          can
            ? html`<div class="actions">
                ${addButtons.map(([op, label]) => html`<button class="sm" @click=${() => ((this.edit = op), (this.form = {}), clearSelection(this))}>+ ${t(label)}</button>`)}
              </div>`
            : html`<span class="help">${t('read-only: editing needs "edit model" (author or owner)')}</span>`
        }
      </div>
      <nav class="jump" aria-label=${t('Sections')}>
        ${[
          ['types', 'Types'],
          ['relations', 'Relations'],
          ['rules', 'Rules'],
          ['restrictions', 'Type restrictions'],
          ['conditions', 'Conditions'],
          ['gates', 'Gates'],
        ].map(
          ([id, label]) =>
            html`<a
              href="#"
              @click=${(e) => {
                e.preventDefault();
                this.querySelector('#sec-' + id)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
              }}
              >${t(label)}</a
            >`,
        )}
      </nav>
      ${this._forms()}
      ${removeBar(this, {
        one: 'item',
        many: 'items',
        describe: (k) => this._describe(k),
        warning:
          'A type can only go when no tuples reference it; rules and type restrictions are removed before types.',
        onConfirm: () => this._removeSelected(),
      })}
      ${this._filterBox('types', vis.types.length, m.json.types.length)}
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              ${selAll(vis.types.map((x) => 'type:' + x.name))}
              <th id="sec-types">
                ${t('Type')}
                ${help('Object and subject types of this store. A type with tuples cannot be removed.')}
              </th>
              <th>
                ${t('Namespace')}
                ${help('The application or team the type belongs to; namespace roles (Access tab) edit inside it. Changing it is a store-wide change.')}
              </th>
              <th>${t('Description')}</th>
              ${this.caps?.can_edit_model ? html`<th></th>` : nothing}
            </tr>
          </thead>
          <tbody>
            ${vis.types.map(
              (x) =>
                html`<tr>
                  ${sel('type:' + x.name)}
                  <td class="mono">${x.name}</td>
                  <td>
                    ${x.namespace ? html`<span class="badge muted">${x.namespace}</span>` : html`<span class="dim">${t('store-wide')}</span>`}
                  </td>
                  <td class="muted">${x.description ?? ''}</td>
                  ${
                    this.caps?.can_edit_model
                      ? html`<td class="actions">
                          <button class="sm" @click=${() => this._editTypeNamespace(x)}>
                            ${t('Namespace…')}
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
                            @click=${() => ((this.renaming = ns), (this.renameTo = ns))}
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
      }
      <h3 id="sec-relations" style="margin-top:var(--s-4)">
        ${t('Relations')}
        ${help('Relation and permission names declared for this store; rules give them meaning per type. The order here (drag the rows, then Save order) is stored in the relation metadata as ui_order and used wherever the console lists them; it never affects evaluation.')}
      </h3>
      ${this._filterBox('relations', '', '')} ${this._relationRows()}
      <h3 id="sec-rules" style="margin-top:var(--s-4)">
        ${t('Rules')}
        ${help('How each relation is defined on each type: direct (by tuple), computed (from another relation), ttu (from a related object). Rows with the same group form a union; other groups intersect or exclude.')}
      </h3>
      ${this._filterBox('rules', vis.rules.length, m.rules.length)}
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              ${selAll(vis.rules.map((r) => 'rule:' + r.id))}
              <th class="num">ID</th>
              <th>${t('Object type')}</th>
              <th>${t('Relation')}</th>
              <th>${t('Defined as')}</th>
              <th>${t('Group')}</th>
            </tr>
          </thead>
          <tbody>
            ${vis.rules.map(
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
      </div>
      <h3 id="sec-restrictions" style="margin-top:var(--s-4)">
        ${t('Type restrictions')}
        ${help('Which subject types (or usersets like team#member) a direct relation accepts in tuples; the engine rejects other tuples.')}
      </h3>
      ${this._filterBox('restrictions', vis.restrictions.length, m.restrictions.length)}
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              ${selAll(vis.restrictions.map((x) => 'restriction:' + x.id))}
              <th class="num">ID</th>
              <th>${t('Object type')}</th>
              <th>${t('Relation')}</th>
              <th>${t('Accepts')}</th>
              <th>${t('Condition')}</th>
            </tr>
          </thead>
          <tbody>
            ${vis.restrictions.map(
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
      </div>
      ${
        m.json.conditions.length
          ? html`<h3 id="sec-conditions" style="margin-top:var(--s-4)">
                ${t('Conditions')}
                ${help('Named expressions evaluated at decision time against the request context; a tuple can carry one, and a type restriction can require one.')}
              </h3>
              ${this._filterBox('conditions', vis.conditions.length, m.json.conditions.length)}
              <div class="table-wrap">
                <table>
                  <thead>
                    <tr>
                      ${selAll(vis.conditions.map((c) => 'condition:' + c.name))}
                      <th>${t('Name')}</th>
                      <th>${t('Description')}</th>
                      <th>${t('Language')}</th>
                      <th>${t('Created at')}</th>
                      <th>${t('Updated at')}</th>
                      <th></th>
                    </tr>
                  </thead>
                  <tbody>
                    ${vis.conditions.map((c) => {
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
                            ${can ? html`<button class="sm" @click=${() => this._editCondition(c)}>${t('Edit')}</button>` : nothing}
                          </td>
                        </tr>
                        ${this.detail.has(key) ? this._detailRow(7, this._conditionSQL(c), c, this._tryPanel(c)) : nothing}`;
                    })}
                  </tbody>
                </table>
              </div>`
          : html`<h3 id="sec-conditions" style="margin-top:var(--s-4)">${t('Conditions')}</h3>
              <p class="help">${t('No conditions in this model.')}</p>`
      }
      ${
        m.json.gates?.length
          ? html`<h3 id="sec-gates" style="margin-top:var(--s-4)">
                ${t('Temporal gates')}
                ${help('History-dependent vetoes over the action log: quotas, prior approval, separation of duties. Evaluated after the graph allows, for the checked principal only; a gate never grants.')}
              </h3>
              ${this._filterBox('gates', vis.gates.length, m.json.gates.length)}
              <div class="table-wrap">
                <table>
                  <thead>
                    <tr>
                      ${selAll(vis.gates.map((g) => this._gateKey(g)))}
                      <th>${t('On')}</th>
                      <th>${t('Name')}</th>
                      <th>${t('Mode')}</th>
                      <th>${t('Clauses')}</th>
                      <th></th>
                    </tr>
                  </thead>
                  <tbody>
                    ${vis.gates.map(
                      (g) =>
                        html`<tr>
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
                              ${can ? html`<button class="sm" @click=${() => this._editGate(g)}>${t('Edit')}</button>` : nothing}
                            </td>
                          </tr>
                          ${this.detail.has(this._gateKey(g)) ? this._detailRow(6, this._gateSQL(g), g.spec) : nothing}`,
                    )}
                  </tbody>
                </table>
              </div>`
          : html`<h3 id="sec-gates" style="margin-top:var(--s-4)">${t('Temporal gates')}</h3>
              <p class="help">${t('No temporal gates in this model.')}</p>`
      }
      ${
        m.json.grant_rules?.length
          ? html`<p class="help">
              ${t('This model also has {rules} grant rules — see the SQL view; the console does not edit those yet.', { rules: m.json.grant_rules.length })}
            </p>`
          : nothing
      }
    </section>`;
  }

  render() {
    const m = this.m;
    if (!m)
      return html`${this.error ? html`<p class="error">${this.error}</p>` : html`<p class="muted">${t('Loading…')}</p>`}`;
    const views = [
      ['dsl', 'DSL', 'OpenFGA-style; display only (conditions, gates, grant rules have no DSL form)'],
      ['json', 'JSON', 'the canonical export — what publish stores in the registry'],
      ['sql', 'SQL', 'the engine calls that rebuild this model; runnable in psql'],
    ];
    return html`
      ${this.error ? html`<p class="error">${this.error}</p>` : nothing}
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
