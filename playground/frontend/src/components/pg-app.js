import { LitElement, html, css } from 'lit';
import { api } from '../api.js';
import './pg-explain-tree.js';
import './pg-access-graph.js';
import './pg-types-graph.js';
import './pg-model.js';
import './pg-tuples.js';
import './pg-conditions.js';
import './pg-json-editor.js';
import './pg-combo.js';

export class PgApp extends LitElement {
  static properties = {
    me: { state: true }, meta: { state: true }, mode: { state: true },
    store: { state: true }, model: { state: true }, tuples: { state: true }, conditions: { state: true },
    typeLabels: { state: true }, clusterHidden: { state: true },
    subjectType: { state: true }, subjectId: { state: true },
    action: { state: true }, objType: { state: true }, objId: { state: true },
    context: { state: true }, decision: { state: true }, tree: { state: true },
    error: { state: true }, busy: { state: true },
    queryTab: { state: true }, dataTab: { state: true }, allowedOnly: { state: true },
    leftOpen: { state: true }, leftWidth: { state: true },
    typesOpen: { state: true }, contextOpen: { state: true },
    typeHidden: { state: true }, relHidden: { state: true },
    modelOpen: { state: true }, modelH: { state: true }, queryOpen: { state: true }, typesH: { state: true },
  };

  constructor() {
    super();
    const url = new URL(location.href);
    this.me = null; this.meta = null; this.mode = 'explore';
    this.store = url.searchParams.get('store') || 'demo';
    this.model = ''; this.tuples = []; this.conditions = []; this.typeLabels = []; this.clusterHidden = [];
    this.subjectType = 'internal_user'; this.subjectId = 'alice';
    this.action = 'can_read'; this.objType = 'document'; this.objId = 'doc_payroll_001';
    this.context = ''; this.decision = null; this.tree = null; this.error = ''; this.busy = false;
    this.queryTab = 'structured'; this.dataTab = 'tuples'; this.allowedOnly = true;
    this.leftOpen = true; this.leftWidth = 520; this.typesOpen = false; this.contextOpen = false;
    this.typeHidden = []; this.relHidden = [];
    this.modelOpen = true; this.modelH = 300; this.queryOpen = true; this.typesH = 340;
  }

  // Declared type names parsed from the model DSL ("type <name>" lines), so the
  // type graph can show types even before any tuple references them. Memoized by
  // model text so the array reference stays stable across re-renders (e.g. while
  // dragging the divider) — otherwise the type graph would re-layout every frame.
  _typeNames() {
    if (this._tnModel !== this.model) {
      this._tnModel = this.model;
      this._tnCache = [...(this.model || '').matchAll(/^type\s+(\S+)/gm)].map((m) => m[1]);
    }
    return this._tnCache;
  }

  // All type / relation names in the store (for the type-graph filter chips).
  _allTypes() {
    return [...new Set([...(this._typeNames() || []), ...(this.tuples || []).flatMap((t) => [t.object_type, t.user_type])])].filter(Boolean).sort();
  }
  _allRelations() { return [...new Set((this.tuples || []).map((t) => t.relation))].filter(Boolean).sort(); }
  // Toggle a value in a reactive array property (reassign so Lit re-renders).
  _toggle(prop, v) {
    const s = new Set(this[prop]);
    s.has(v) ? s.delete(v) : s.add(v);
    this[prop] = [...s];
  }

  createRenderRoot() { return this; } // light DOM so /styles.css applies
  connectedCallback() { super.connectedCallback(); this._run(() => this._loadMe()); }

  async _loadMe() {
    const { body } = await api.me();
    this.me = body;
    // Await so a metadata/store load failure propagates to the wrapping _run.
    if (body?.authenticated) { await Promise.all([this._loadMeta(), this._loadStore()]); }
  }
  async _loadMeta() {
    const [s, r, o] = await Promise.all([api.metaStores(), api.metaRelations(this.store), api.metaObjects(this.store)]);
    this.meta = { stores: s.body ?? [], relations: r.body ?? [], objects: o.body ?? [] };
  }
  async _loadStore() {
    const [m, t, c, ty] = await Promise.all([api.model(this.store), api.tuples(this.store), api.conditions(this.store), api.metaTypes(this.store)]);
    this.model = m.body?.dsl ?? ''; this.tuples = t.body ?? []; this.conditions = c.body ?? []; this.typeLabels = ty.body ?? [];
    this.clusterHidden = [];
  }

  // Distinct labels (clusters) across the store's types.
  _clusters() { return [...new Set((this.typeLabels || []).flatMap((t) => t.labels || []))].filter(Boolean).sort(); }

  // Types to hide in the graph: explicitly hidden (typeHidden) PLUS any type whose
  // every cluster is hidden — a type stays visible as long as ANY cluster it
  // belongs to is still shown (untagged types are never hidden by clusters).
  _effectiveHidden() {
    const hidden = new Set(this.typeHidden);
    const ch = new Set(this.clusterHidden);
    if (ch.size) {
      for (const t of this.typeLabels || []) {
        const labels = t.labels || [];
        if (labels.length && labels.every((l) => ch.has(l))) hidden.add(t.name);
      }
    }
    return [...hidden];
  }
  _setStore(v) {
    this.store = v;
    const u = new URL(location.href); u.searchParams.set('store', v); history.replaceState(null, '', u);
    this._run(() => Promise.all([this._loadMeta(), this._loadStore()]));
  }

  async _run(fn) { this.busy = true; this.error = ''; try { await fn(); } catch (e) { this.error = String(e.message || e); } finally { this.busy = false; } }

  // Parse the request-context editor into an object (undefined when empty).
  _contextObj() {
    const s = (this.context || '').trim();
    if (!s) return undefined;
    try { return JSON.parse(s); } catch { throw new Error('Request context is not valid JSON'); }
  }

  _check() {
    return this._run(async () => {
      this.decision = null; this.tree = null;
      const ctx = this._contextObj();
      let raw = null;
      if (this.mode === 'explore') {
        const body = { store: this.store, subject: { type: this.subjectType, id: this.subjectId }, action: this.action, resource: { type: this.objType, id: this.objId } };
        if (ctx !== undefined) body.context = ctx;
        this.decision = (await api.exploreCheck(body)).body?.allowed;
        const e = await api.exploreExplain(body);
        raw = e.body?.tree ?? e.body ?? null;
      } else {
        const input = { store: this.store, action: this.action, resource: { type: this.objType, id: this.objId } };
        if (ctx !== undefined) input.context = ctx;
        this.decision = (await api.q('allow', input)).body?.result;
        raw = (await api.q('explain', input)).body?.result?.tree ?? null;
      }
      this.tree = this._annotateTree(raw);
    });
  }

  // The engine only reports condition_name on a node when the condition *fails*
  // (condition_denied). For a *satisfied* grant it reports a plain direct_tuple,
  // so we cross-reference the loaded tuples and tag granting nodes whose
  // underlying tuple carries a condition — letting the graph show conditional
  // grants either way.
  _annotateTree(tree) {
    if (!tree) return tree;
    const byKey = new Map();
    for (const t of this.tuples || []) {
      if (!t.condition_name) continue;
      // Userset subjects are `type:id#relation`; include user_relation so a userset
      // tuple matches the right node and doesn't collide with the plain-subject one.
      const subj = t.user_relation ? `${t.user_type}:${t.user_id}#${t.user_relation}` : `${t.user_type}:${t.user_id}`;
      byKey.set(`${subj}|${t.relation}|${t.object_type}:${t.object_id}`, t.condition_name);
    }
    const walk = (n) => {
      if (!n.condition_name && n.subject && n.relation && n.object) {
        const c = byKey.get(`${n.subject}|${n.relation}|${n.object}`);
        if (c) n.condition_name = c;
      }
      (n.children || []).forEach(walk);
    };
    walk(tree);
    return tree;
  }

  // Drop a User/Relation/Object picked in the tuples table into the Structured query.
  _pick(d) {
    if (d.user) { this.subjectType = d.user.type; this.subjectId = d.user.id; }
    if (d.relation) this.action = d.relation;
    if (d.object) { this.objType = d.object.type; this.objId = d.object.id; }
    if (d.condition) this._fillContext(d.condition);
  }

  // Build an example request-context object from a condition's required request
  // keys, drop it into the editor, and open it.
  _fillContext(name) {
    const c = (this.conditions || []).find((x) => x.name === name);
    if (!c) return;
    let req = [];
    try { req = JSON.parse(c.required_context || '{}').request || []; } catch { /* ignore */ }
    const ex = {};
    for (const k of req) ex[k] = this._exampleValue(k);
    this.context = JSON.stringify(ex, null, 2);
    this.contextOpen = true;
  }

  _exampleValue(k) {
    if (/time|date|expires|now/i.test(k)) return '2026-03-11T10:00:00Z';
    if (/cidr|range/i.test(k)) return '203.0.113.0/24';
    if (/ip|addr/i.test(k)) return '203.0.113.10';
    return '';
  }

  // The structured sentence always queries an arbitrary subject → Explore mode.
  _runStructured() {
    if (this.mode !== 'explore') this.mode = 'explore';
    this._check();
  }

  // Drag a horizontal divider to resize a section's height (the `prop` state).
  _startVResize(e, prop = 'modelH', min = 80, max = 700) {
    e.preventDefault();
    const startY = e.clientY, startH = this[prop];
    this._vMove = (ev) => { this[prop] = Math.max(min, Math.min(max, startH + ev.clientY - startY)); };
    this._vUp = () => {
      window.removeEventListener('mousemove', this._vMove);
      window.removeEventListener('mouseup', this._vUp);
      document.body.style.userSelect = '';
    };
    window.addEventListener('mousemove', this._vMove);
    window.addEventListener('mouseup', this._vUp);
    document.body.style.userSelect = 'none';
  }

  // ── Left/right resizable divider ──────────────────────────────────────────
  _toggleLeft() { this.leftOpen = !this.leftOpen; }
  _startResize(e) {
    if (!this.leftOpen) return;
    e.preventDefault();
    const startX = e.clientX, startW = this.leftWidth;
    this._moveH = (ev) => { this.leftWidth = Math.max(300, Math.min(900, startW + ev.clientX - startX)); };
    this._upH = () => {
      window.removeEventListener('mousemove', this._moveH);
      window.removeEventListener('mouseup', this._upH);
      document.body.style.userSelect = '';
    };
    window.addEventListener('mousemove', this._moveH);
    window.addEventListener('mouseup', this._upH);
    document.body.style.userSelect = 'none';
  }

  // Completion candidates derived from the loaded tuples (+ model relations).
  _uniq(a) { return [...new Set(a.filter(Boolean))].sort(); }
  _subjectTypes() { return this._uniq((this.tuples || []).map((t) => t.user_type)); }
  _subjectIds(type) { return this._uniq((this.tuples || []).filter((t) => !type || t.user_type === type).map((t) => t.user_id)); }
  _objectTypes() { return this._uniq([...(this.meta?.objects ?? []), ...(this.tuples || []).map((t) => t.object_type)]); }
  _objectIds(type) { return this._uniq((this.tuples || []).filter((t) => !type || t.object_type === type).map((t) => t.object_id)); }

  // One editable token of the sentence: a content-sized input with a datalist.
  _tok(prop, suggestions, placeholder) {
    return html`<pg-combo class="tok" data-testid="query-${prop}" .value=${this[prop] || ''} .options=${suggestions ?? []}
      placeholder=${placeholder ?? prop}
      @value-changed=${(e) => (this[prop] = e.detail.value)}
      @submit=${() => this._runStructured()}></pg-combo>`;
  }

  render() {
    if (!this.me) return html`<main><p>Loading…</p></main>`;
    if (!this.me.authenticated) {
      return html`<main class="login"><h1>pgauthz Playground</h1>
        <p>Sign in to explore the authorization model.</p>
        <button @click=${() => api.login()}>Sign in with Keycloak</button></main>`;
    }
    const cols = `${this.leftOpen ? this.leftWidth : 0}px 18px minmax(0, 1fr)`;
    return html`
      ${this._header()}
      <div class="panes" style="grid-template-columns:${cols}">
        ${this.leftOpen ? this._leftPane() : html`<div></div>`}
        <div class="divider" @mousedown=${(e) => this._startResize(e)} title="drag to resize">
          <button class="div-toggle" @mousedown=${(e) => e.stopPropagation()} @click=${() => this._toggleLeft()}
            title=${this.leftOpen ? 'collapse panel' : 'expand panel'}>${this.leftOpen ? '‹' : '›'}</button>
        </div>
        <section class="right">
          <details class="graph-section" data-testid="section-types" @toggle=${(e) => (this.typesOpen = e.target.open)}>
            <summary><h2>Types</h2><span class="chev"></span></summary>
            ${this.typesOpen ? html`
              ${this._typeFilters()}
              <pg-types-graph data-testid="types-graph" style="height:${this.typesH}px" .tuples=${this.tuples} .types=${this._typeNames()}
                .hiddenTypes=${this._effectiveHidden()} .hiddenRelations=${this.relHidden}
                @node-hidden=${(e) => this._toggle('typeHidden', e.detail)}></pg-types-graph>
            ` : ''}
          </details>
          ${this.typesOpen
            ? html`<div class="hdivider" title="drag to resize" @mousedown=${(e) => this._startVResize(e, 'typesH', 160, 800)}></div>`
            : ''}
          ${this._evaluate()}
        </section>
      </div>`;
  }

  _leftPane() {
    return html`<section class="left">
      <details class="graph-section model-section" data-testid="section-model" open
        style=${this.modelOpen ? `height:${this.modelH}px` : ''}
        @toggle=${(e) => (this.modelOpen = e.target.open)}>
        <summary><h2>Model</h2><span class="chev"></span></summary>
        <pg-model data-testid="model" .dsl=${this.model} .types=${this.typeLabels}></pg-model>
      </details>
      ${this.modelOpen
        ? html`<div class="hdivider" title="drag to resize" @mousedown=${(e) => this._startVResize(e)}></div>`
        : ''}
      <details class="graph-section data-section" data-testid="section-data" open>
        <summary><h2>Data</h2><span class="chev"></span></summary>
        <div class="data-body">
          <div class="tabs data-tabs">
            <button data-testid="tab-tuples" class=${this.dataTab === 'tuples' ? 'active' : ''} @click=${() => (this.dataTab = 'tuples')}>Tuples (${this.tuples.length})</button>
            <button data-testid="tab-conditions" class=${this.dataTab === 'conditions' ? 'active' : ''} @click=${() => (this.dataTab = 'conditions')}>Conditions (${this.conditions.length})</button>
          </div>
          ${this.dataTab === 'tuples'
            ? html`<pg-tuples data-testid="tuples" .tuples=${this.tuples} @pick=${(e) => this._pick(e.detail)}></pg-tuples>`
            : html`<pg-conditions data-testid="conditions" .conditions=${this.conditions}></pg-conditions>`}
        </div>
      </details>
    </section>`;
  }

  _typeFilters() {
    const clusters = this._clusters();
    const anyHidden = this.typeHidden.length + this.relHidden.length + this.clusterHidden.length;
    const chips = (all, prop) => all.map((v) => html`<button
      class="chip ${this[prop].includes(v) ? 'off' : ''}" @click=${() => this._toggle(prop, v)}>${v}</button>`);
    return html`<div class="type-filters">
      ${clusters.length ? html`<span class="clusters" data-testid="clusters">clusters
        ${clusters.map((c) => html`<button class="chip ${this.clusterHidden.includes(c) ? 'off' : ''}" data-testid="cluster-${c}"
          @click=${() => this._toggle('clusterHidden', c)} title="show / hide this cluster">${c}</button>`)}
      </span>` : ''}
      <details class="filter">
        <summary>Types${this.typeHidden.length ? html` <span class="fcount">${this.typeHidden.length} hidden</span>` : ''}</summary>
        <div class="chips">${chips(this._allTypes(), 'typeHidden')}</div>
      </details>
      <details class="filter">
        <summary>Relations${this.relHidden.length ? html` <span class="fcount">${this.relHidden.length} hidden</span>` : ''}</summary>
        <div class="chips">${chips(this._allRelations(), 'relHidden')}</div>
      </details>
      ${anyHidden ? html`<button class="link reset" data-testid="filters-show-all" @click=${() => { this.typeHidden = []; this.relHidden = []; this.clusterHidden = []; }}>Show all</button>` : ''}
      <span class="hint muted">tip: click a node to hide it</span>
    </div>`;
  }

  _accessGraph() {
    return html`<details class="graph-section access-section" data-testid="section-access-graph" open>
      <summary><h2>Access graph</h2><span class="chev"></span></summary>
      <div class="graph-toolbar">
        <span class="seg">
          <button data-testid="mode-access-path" class=${this.allowedOnly ? 'active' : ''} @click=${() => (this.allowedOnly = true)}
            title="only the relations that grant access">Access path</button>
          <button data-testid="mode-full-tree" class=${!this.allowedOnly ? 'active' : ''} @click=${() => (this.allowedOnly = false)}
            title="every relation explored, including those that did not grant access">Full tree</button>
        </span>
        <span class="legend">
          <span class="lg query">requested</span>
          <span class="lg grant">granting tuple</span>
          <span class="lg allow">grants</span>
          <span class="lg deny">dead end</span>
          <span class="lg cond">conditional</span>
        </span>
      </div>
      <pg-access-graph data-testid="access-graph" .node=${this.tree} .allowedOnly=${this.allowedOnly}></pg-access-graph>
    </details>
    <details class="aux rule-legend"><summary class="muted">what the edge labels mean</summary>
      <dl>
        <dt>direct</dt><dd>a stored tuple grants it directly</dd>
        <dt>wildcard</dt><dd>matched a wildcard tuple — <code>object:*</code> (any object) or <code>subject:*</code> (any subject of that type)</dd>
        <dt>rewrite</dt><dd>the relation is defined as another relation on the <em>same</em> object (e.g. <code>can_read: viewer</code>)</dd>
        <dt>via <em>&lt;relation&gt;</em></dt><dd>inherited from a <em>related</em> object reached through that relation (tuple-to-userset)</dd>
        <dt>userset</dt><dd>granted to a group/userset — resolution continues into its members</dd>
        <dt>intersection / exclusion</dt><dd>AND / BUT&nbsp;NOT rule groups</dd>
      </dl></details>
    <details class="aux"><summary class="muted">resolution path (text)</summary>
      <pg-explain-tree .node=${this.tree}></pg-explain-tree></details>`;
  }

  _header() {
    return html`<header>
      <div class="brand"><strong>pgauthz Playground</strong>
        ${this._field('Store', 'store', this.meta?.stores, (v) => this._setStore(v))}</div>
      <div class="who">
        <span class="mode">
          <button data-testid="mode-explore" class=${this.mode === 'explore' ? 'active' : ''} @click=${() => (this.mode = 'explore')}>Explore</button>
          <button data-testid="mode-opa" class=${this.mode === 'opa' ? 'active' : ''} @click=${() => (this.mode = 'opa')}>As me (OPA)</button>
        </span>
        <span class="muted" data-testid="username">${this.me.username}</span>
        <button class="link" data-testid="logout" @click=${() => api.logout()}>logout</button>
      </div>
    </header>`;
  }

  _evaluate() {
    return html`<details class="graph-section evaluate" data-testid="section-query" ?open=${this.queryOpen} @toggle=${(e) => (this.queryOpen = e.target.open)}>
      <summary><h2>Query</h2><span class="chev"></span></summary>
      <div class="sentence">
            <span>is</span>
            ${this._tok('subjectType', this._subjectTypes(), 'subject type')}<span class="colon">:</span>${this._tok('subjectId', this._subjectIds(this.subjectType), 'id')}
            <span>related to</span>
            ${this._tok('objType', this._objectTypes(), 'object type')}<span class="colon">:</span>${this._tok('objId', this._objectIds(this.objType), 'id')}
            <span>as</span>
            ${this._tok('action', this.meta?.relations, 'relation')}<span class="colon">?</span>
            <button class="run" data-testid="query-run" ?disabled=${this.busy} @click=${() => this._runStructured()}>Run</button>
            ${this.decision != null ? html`<span class="decision ${this.decision ? 'allow' : 'deny'}"
              data-testid="decision" data-result=${this.decision ? 'allow' : 'deny'}>${this.decision ? 'ALLOW' : 'DENY'}</span>` : ''}
          </div>
      <details class="context-row" ?open=${this.contextOpen} @toggle=${(e) => (this.contextOpen = e.target.open)}>
        <summary class="muted">request context (JSON) — evaluates conditional tuples</summary>
        <pg-json-editor .value=${this.context} placeholder=${'{\n  "current_time": "2026-03-11T10:00:00Z"\n}'}
          @value-changed=${(e) => (this.context = e.detail.value)}></pg-json-editor>
        <p class="muted ctx-hint">e.g. the time-boxed share needs <code>{"current_time": "…"}</code>. Empty context → conditions fail closed (deny).</p>
      </details>
      ${this.error ? html`<p class="error">${this.error}</p>` : ''}
      ${this.tree ? this._accessGraph() : ''}
    </details>`;
  }

  _field(label, prop, suggestions, onChange) {
    const listId = suggestions ? `dl-${prop}` : undefined;
    return html`<label>${label}
      <input list=${listId ?? ''} .value=${this[prop]} @input=${(e) => {
        this[prop] = e.target.value;
        if (onChange) onChange(e.target.value);
      }}>
      ${suggestions ? html`<datalist id=${listId}>
        ${suggestions.map((v) => html`<option value=${v}></option>`)}</datalist>` : ''}
    </label>`;
  }
}
customElements.define('pg-app', PgApp);
