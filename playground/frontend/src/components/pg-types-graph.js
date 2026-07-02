import { html, css } from 'lit';
import cytoscape from 'cytoscape';
import elk from 'cytoscape-elk';
import { PgGraph } from './pg-graph.js';

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

export class PgTypesGraph extends PgGraph {
  static properties = {
    tuples: { attribute: false }, types: { attribute: false }, model: { attribute: false },
    hiddenTypes: { attribute: false }, hiddenRelations: { attribute: false },
    mode: { state: true },
  };

  static styles = [PgGraph.styles, css`
    :host { height: 42vh; min-height: 280px; }
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
  `];

  constructor() {
    super();
    this.mode = 'declared';
  }

  graphName() { return 'types'; }

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

  // Nodes = distinct types (declared ∪ referenced). Edges come from the model's
  // type restrictions (declared mode) or from the tuples (observed mode).
  buildElements() {
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

  // ELK 'layered' (Sugiyama): a deterministic layered layout with thorough crossing
  // minimization and generous spacing so fanned parallel edges and their labels read.
  layoutOptions() {
    return {
      name: 'elk', fit: false, padding: 20,
      elk: {
        algorithm: 'layered',
        'elk.direction': 'DOWN',
        'elk.layered.thoroughness': 100,
        'elk.layered.crossingMinimization.strategy': 'LAYER_SWEEP',
        'elk.layered.nodePlacement.strategy': 'NETWORK_SIMPLEX',
        'elk.layered.nodePlacement.favorStraightEdges': true,
        'elk.layered.considerModelOrder.strategy': 'NODES_AND_EDGES',
        'elk.spacing.nodeNode': 60,
        'elk.layered.spacing.nodeNodeBetweenLayers': 150,
        'elk.spacing.edgeNode': 40,
        'elk.spacing.edgeEdge': 28,
        'elk.layered.spacing.edgeNodeBetweenLayers': 35,
        'elk.layered.spacing.edgeEdgeBetweenLayers': 28,
      },
    };
  }

  cyStyle() {
    return [
      { selector: 'node', style: {
        label: 'data(label)', 'font-size': 14, 'text-valign': 'center', 'text-halign': 'center',
        color: '#fff', 'background-color': TYPE_FILL, shape: 'round-rectangle',
        width: 'label', height: 'label', padding: '10px',
      } },
      { selector: 'edge', style: {
        // bezier fans multiple edges between the same node pair into distinct arcs;
        // a large step-size spreads them (and their labels) far enough to read.
        'curve-style': 'bezier', 'control-point-step-size': 60,
        'target-arrow-shape': 'triangle', 'arrow-scale': 0.9,
        'line-color': '#b1b8c0', 'target-arrow-color': '#b1b8c0', width: 1.5,
        label: 'data(label)', 'font-size': 10, 'text-rotation': 'none', 'text-wrap': 'none',
        // Each label is an opaque bordered chip so it stays legible where it crosses a line.
        color: '#3d4653', 'text-background-color': '#ffffff', 'text-background-opacity': 1,
        'text-background-shape': 'round-rectangle', 'text-background-padding': '3px',
        'text-border-opacity': 1, 'text-border-color': '#d0d7de', 'text-border-width': 1,
      } },
      // Userset restrictions (e.g. team#member) drawn dashed to distinguish them
      // from a direct assignment of the same type.
      { selector: 'edge[?userset]', style: { 'line-style': 'dashed', 'line-color': '#9aa4b0', 'target-arrow-color': '#9aa4b0' } },
    ];
  }

  // Click a node to hide it (parent records it in hiddenTypes).
  onNodeTap(e) {
    this.dispatchEvent(new CustomEvent('node-hidden', { detail: e.target.id(), bubbles: true, composed: true }));
  }

  // Apply the type/relation filter *before* layout so the layout ignores hidden
  // nodes (they don't reserve space); the base then lays out only visible elements.
  _prepare() { this.#applyFilter(); }

  // Hide elements by toggling display. Hidden types hide their incident edges too.
  #applyFilter() {
    if (!this._cy) return;
    const ht = new Set(this.hiddenTypes || []);
    const hr = new Set(this.hiddenRelations || []);
    this._cy.batch(() => {
      this._cy.nodes().forEach((n) => n.style('display', ht.has(n.id()) ? 'none' : 'element'));
      this._cy.edges().forEach((e) => {
        const hide = hr.has(e.data('label')) || ht.has(e.source().id()) || ht.has(e.target().id());
        e.style('display', hide ? 'none' : 'element');
      });
    });
  }

  updated(changed) {
    if (!this._cy) return;
    if (changed.has('tuples') || changed.has('types') || changed.has('model') || changed.has('mode')) {
      this._rebuild();
    } else if (changed.has('hiddenTypes') || changed.has('hiddenRelations')) {
      // Toggle visibility only — positions stay put (no reflow). The next layout
      // (↻ button or a data change) lays out just the visible subset, ignoring the
      // hidden nodes.
      this.#applyFilter();
    }
  }

  extraControls() {
    return html`<span class="modeseg" data-testid="types-mode">
      <button class=${this.mode === 'declared' ? 'active' : ''} data-testid="types-mode-model"
        title="edges from the model's type restrictions (the declared schema)"
        @click=${() => (this.mode = 'declared')}>model</button>
      <button class=${this.mode === 'observed' ? 'active' : ''} data-testid="types-mode-data"
        title="edges from the tuples (relationships observed in the data)"
        @click=${() => (this.mode = 'observed')}>data</button>
    </span>`;
  }

  legend() {
    return html`<div class="legend" data-testid="types-legend">
      <span class="key"><span class="line solid"></span>direct type</span>
      <span class="key"><span class="line dashed"></span>userset (<code>type#relation</code>)</span>
    </div>`;
  }
}
customElements.define('pg-types-graph', PgTypesGraph);
