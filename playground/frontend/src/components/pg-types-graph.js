import { LitElement, html, css } from 'lit';
import cytoscape from 'cytoscape';
import elk from 'cytoscape-elk';
import { cyToDot } from '../dot.js';

cytoscape.use(elk);

// Model overview: a type-level graph of the whole store, in one of two modes:
//   • declared (default): edges are the model's type restrictions — every direct
//     relation `object ──relation──▶ allowed_type`, parsed from the DSL. This is
//     the full declared schema (matches the DSL / OpenFGA), including relations no
//     tuple uses. Relations declared as `[any]` (no restriction) have no edge.
//   • observed: edges aggregated from the tuples — the type→type relationships that
//     actually occur in the data. Declared-but-unused relations don't appear.
// Declared types with no edges still appear as isolated nodes.
const TYPE_FILL = '#3d5a73';

export class PgTypesGraph extends LitElement {
  static properties = {
    tuples: { attribute: false }, types: { attribute: false }, model: { attribute: false },
    hiddenTypes: { attribute: false }, hiddenRelations: { attribute: false },
    mode: { state: true }, zoomLevel: { state: true }, copied: { state: true },
  };
  static styles = css`
    :host { display: block; position: relative; height: 42vh; min-height: 280px;
      border: 1px solid var(--pg-border, #d0d7de); border-radius: var(--pg-radius-md, 6px); }
    #graph { width: 100%; height: 100%; background: var(--pg-surface, #f6f8fa); }
    .controls { position: absolute; top: var(--pg-space-2, .5rem); right: var(--pg-space-2, .5rem);
      z-index: 2; display: flex; gap: 2px; }
    .controls button { width: 30px; height: 30px; padding: 0; font-size: 17px; line-height: 1;
      border: 1px solid var(--pg-border, #d0d7de); background: var(--pg-bg, #fff);
      color: var(--pg-fg, #1f2328); border-radius: var(--pg-radius-sm, 4px); cursor: pointer; }
    .controls button:hover { background: var(--pg-surface, #f6f8fa); }
    .controls .zoomlvl { display: inline-flex; align-items: center; height: 30px; padding: 0 7px;
      font-size: 12px; color: var(--pg-muted, #6e7781); background: var(--pg-bg, #fff); white-space: nowrap;
      border: 1px solid var(--pg-border, #d0d7de); border-radius: var(--pg-radius-sm, 4px); }
    /* Segmented model/data view selector. */
    .controls .modeseg { display: inline-flex; }
    .controls .modeseg button { width: auto; padding: 0 9px; font-size: 12px; font-weight: 600; border-radius: 0; }
    .controls .modeseg button:first-child { border-radius: var(--pg-radius-sm, 4px) 0 0 var(--pg-radius-sm, 4px); }
    .controls .modeseg button:last-child { border-radius: 0 var(--pg-radius-sm, 4px) var(--pg-radius-sm, 4px) 0; border-left: none; }
    .controls .modeseg button.active { background: var(--pg-primary, #0969da); color: #fff; border-color: var(--pg-primary, #0969da); }
    .legend { position: absolute; left: var(--pg-space-2, .5rem); bottom: var(--pg-space-2, .5rem);
      z-index: 2; display: flex; flex-direction: column; gap: 3px; padding: 6px 9px;
      font-size: 11px; color: var(--pg-muted, #57606a);
      background: color-mix(in srgb, var(--pg-bg, #fff) 88%, transparent);
      border: 1px solid var(--pg-border, #d0d7de); border-radius: var(--pg-radius-sm, 4px); }
    .legend .key { display: inline-flex; align-items: center; gap: 6px; white-space: nowrap; }
    .legend code { font-size: 10px; }
    .legend .line { width: 22px; height: 0; flex: 0 0 auto; }
    .legend .line.solid  { border-top: 2px solid #b1b8c0; }
    .legend .line.dashed { border-top: 2px dashed #9aa4b0; }
  `;

  constructor() {
    super();
    this.mode = 'declared';
    this.zoomLevel = 90;
    this.copied = false;
  }

  // Parse the DSL's type restrictions into type→type edges. Each direct relation
  // renders as `define <rel>: [<type>, <type>#<rel>, …]`; computed/TTU relations
  // have no `[...]` and are skipped. A `type#relation` (userset) or `type:*`
  // (wildcard) still targets the base type node.
  #declaredElements() {
    const types = new Set();
    const edges = new Map();
    let cur = null;
    for (const raw of (this.model || '').split('\n')) {
      const th = raw.match(/^type\s+(\S+)/);
      if (th) { cur = th[1]; types.add(cur); continue; }
      if (!cur) continue;
      const dm = raw.match(/^\s*define\s+(\S+):\s*\[([^\]]*)\]/);
      if (!dm) continue;
      const rel = dm[1];
      for (const item of dm[2].split(',')) {
        const s = item.trim();
        if (!s) continue;
        const userset = s.includes('#') ? s.split('#')[1] : null;
        const target = s.split('#')[0].replace(/:\*$/, '');
        types.add(target);
        const label = userset ? `${rel} #${userset}` : rel;
        edges.set(`${cur} ${label} ${target}`, { source: cur, target, label, userset: !!userset });
      }
    }
    return { types, edges: [...edges.values()] };
  }

  // Copy the current (visible) graph as Graphviz DOT to the clipboard.
  async #copyDot() {
    const dot = cyToDot(this.#cy, { name: 'types' });
    if (!dot) return;
    try {
      await navigator.clipboard.writeText(dot);
      this.copied = true;
      setTimeout(() => (this.copied = false), 1200);
    } catch { /* clipboard unavailable (insecure context) */ }
  }

  #cy;
  #ro;
  #fit100; // the fitted zoom that counts as 100%

  // Nodes = distinct types (declared ∪ referenced). Edges come from the model's
  // type restrictions (declared mode) or from the tuples (observed mode).
  #elements() {
    const types = new Set((this.types || []).filter(Boolean));
    let edgeList;
    if (this.mode === 'observed') {
      const edges = new Map();
      for (const t of this.tuples || []) {
        types.add(t.object_type); types.add(t.user_type);
        const userset = t.user_relation || null; // e.g. team:x#member → userset "member"
        const label = userset ? `${t.relation} #${userset}` : t.relation;
        const key = `${t.object_type} ${label} ${t.user_type}`;
        if (!edges.has(key)) edges.set(key, { source: t.object_type, target: t.user_type, label, userset: !!userset });
      }
      edgeList = [...edges.values()];
    } else {
      const d = this.#declaredElements();
      d.types.forEach((t) => types.add(t));
      edgeList = d.edges;
    }
    const nodes = [...types].filter(Boolean).map((id) => ({ data: { id, label: id } }));
    const edgeEls = edgeList.map((e, i) => ({ data: { id: 'te' + i, ...e } }));
    return [...nodes, ...edgeEls];
  }

  // ELK 'layered' (Sugiyama): a deterministic layered layout with thorough
  // crossing minimization — far fewer edge crossings than a force-directed layout
  // for a structured type graph.
  #layout() {
    return {
      name: 'elk', fit: false, padding: 20,
      elk: {
        algorithm: 'layered',
        'elk.direction': 'DOWN',
        'elk.layered.thoroughness': 40,
        'elk.layered.crossingMinimization.strategy': 'LAYER_SWEEP',
        'elk.layered.nodePlacement.strategy': 'NETWORK_SIMPLEX',
        'elk.spacing.nodeNode': 45,
        'elk.layered.spacing.nodeNodeBetweenLayers': 80,
        'elk.spacing.edgeNode': 25,
        'elk.layered.spacing.edgeEdgeBetweenLayers': 15,
      },
    };
  }

  // fcose is async — fit + apply filters once positions are final.
  #runLayout() {
    const l = this.#cy.layout(this.#layout());
    l.one('layoutstop', () => { this.#fitReadable(); this.#applyFilter(); });
    l.run();
  }

  // Show/hide elements by toggling display only — keeps positions stable so
  // hiding never reshuffles the layout. Hidden types hide their edges too.
  #applyFilter() {
    if (!this.#cy) return;
    const ht = new Set(this.hiddenTypes || []);
    const hr = new Set(this.hiddenRelations || []);
    this.#cy.batch(() => {
      this.#cy.nodes().forEach((n) => n.style('display', ht.has(n.id()) ? 'none' : 'element'));
      this.#cy.edges().forEach((e) => {
        const hide = hr.has(e.data('label')) || ht.has(e.source().id()) || ht.has(e.target().id());
        e.style('display', hide ? 'none' : 'element');
      });
    });
  }

  #fitReadable() {
    if (!this.#cy || this.#cy.elements().length === 0) return;
    this.#cy.fit(undefined, 30);
    let z = this.#cy.zoom();
    if (z < 0.8) z = 0.8; else if (z > 2) z = 2;
    this.#fit100 = z;          // this fitted zoom is "100%"
    this.#cy.zoom(z * 0.9);    // start zoomed out to 90%
    this.#cy.center();
    this.#updateZoom();
  }

  #updateZoom() {
    if (this.#cy && this.#fit100) this.zoomLevel = Math.round((this.#cy.zoom() / this.#fit100) * 100);
  }

  // Step the zoom by ±N percentage points (relative to the fitted 100%).
  #zoom(deltaPct) {
    if (!this.#cy || !this.#fit100) return;
    const cur = Math.round((this.#cy.zoom() / this.#fit100) * 100);
    const next = Math.max(10, cur + deltaPct);
    const w = this.#cy.width(), h = this.#cy.height();
    this.#cy.zoom({ level: this.#fit100 * (next / 100), renderedPosition: { x: w / 2, y: h / 2 } });
  }

  firstUpdated() {
    this.#cy = cytoscape({
      container: this.renderRoot.querySelector('#graph'),
      elements: this.#elements(),
      layout: { name: 'preset' },
      minZoom: 0.3, maxZoom: 3,
      userZoomingEnabled: false, // don't hijack page scroll; zoom via the buttons
      style: [
        { selector: 'node', style: {
          label: 'data(label)', 'font-size': 14, 'text-valign': 'center', 'text-halign': 'center',
          color: '#fff', 'background-color': TYPE_FILL, shape: 'round-rectangle',
          width: 'label', height: 'label', padding: '10px',
        } },
        { selector: 'edge', style: {
          'curve-style': 'bezier', 'target-arrow-shape': 'triangle',
          'line-color': '#b1b8c0', 'target-arrow-color': '#b1b8c0', width: 1.5,
          label: 'data(label)', 'font-size': 11, 'text-rotation': 'none',
          color: '#57606a', 'text-background-color': '#ffffff', 'text-background-opacity': 0.9,
          'text-background-shape': 'round-rectangle', 'text-background-padding': '2px',
        } },
        // Userset restrictions (e.g. team#member) drawn dashed to distinguish them
        // from a direct assignment of the same type.
        { selector: 'edge[?userset]', style: { 'line-style': 'dashed', 'line-color': '#9aa4b0', 'target-arrow-color': '#9aa4b0' } },
      ],
    });
    this.#cy.on('zoom', () => this.#updateZoom());
    // Click a node to hide it (parent records it in hiddenTypes).
    this.#cy.on('tap', 'node', (e) => this.dispatchEvent(
      new CustomEvent('node-hidden', { detail: e.target.id(), bubbles: true, composed: true })));
    this.#runLayout();
    // Re-fit the renderer (NOT the layout) when the container resizes.
    this.#ro = new ResizeObserver(() => this.#cy?.resize());
    this.#ro.observe(this);
  }

  updated(changed) {
    if (!this.#cy) return;
    if (changed.has('tuples') || changed.has('types') || changed.has('model') || changed.has('mode')) {
      this.#cy.elements().remove();
      this.#cy.add(this.#elements());
      this.#runLayout();
    } else if (changed.has('hiddenTypes') || changed.has('hiddenRelations')) {
      // Toggle visibility only — no relayout, so nothing moves.
      this.#applyFilter();
    }
  }

  disconnectedCallback() {
    this.#ro?.disconnect();
    this.#cy?.destroy();
    this.#cy = undefined;
    super.disconnectedCallback();
  }

  render() {
    return html`
      <div class="controls">
        <span class="modeseg" data-testid="types-mode">
          <button class=${this.mode === 'declared' ? 'active' : ''} data-testid="types-mode-model"
            title="edges from the model's type restrictions (the declared schema)"
            @click=${() => (this.mode = 'declared')}>model</button>
          <button class=${this.mode === 'observed' ? 'active' : ''} data-testid="types-mode-data"
            title="edges from the tuples (relationships observed in the data)"
            @click=${() => (this.mode = 'observed')}>data</button>
        </span>
        <span class="zoomlvl" title="zoom level (100% = fit)">${this.zoomLevel}%</span>
        <button title="re-arrange nodes" @click=${() => this.#runLayout()}>↻</button>
        <button title="zoom in (+10%)" @click=${() => this.#zoom(10)}>+</button>
        <button title="zoom out (−10%)" @click=${() => this.#zoom(-10)}>−</button>
        <button title="center & fit" @click=${() => this.#fitReadable()}>⊙</button>
        <button title="copy as Graphviz DOT" data-testid="copy-dot" @click=${() => this.#copyDot()}>${this.copied ? '✓' : '⧉'}</button>
      </div>
      <div class="legend" data-testid="types-legend">
        <span class="key"><span class="line solid"></span>direct type</span>
        <span class="key"><span class="line dashed"></span>userset (<code>type#relation</code>)</span>
      </div>
      <div id="graph"></div>`;
  }
}
customElements.define('pg-types-graph', PgTypesGraph);
