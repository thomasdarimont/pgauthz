import { LitElement, html, css } from 'lit';
import cytoscape from 'cytoscape';
import elk from 'cytoscape-elk';

cytoscape.use(elk);

// Model overview: a type-level graph of the whole store. The demo's type
// restrictions are all `[any]`, so the model text alone has no type→type edges;
// instead we aggregate the tuples into distinct `objectType ──relation──▶ userType`
// edges, which is the structural skeleton the store actually uses. Declared types
// with no tuples still appear as isolated nodes.
const TYPE_FILL = '#3d5a73';

export class PgTypesGraph extends LitElement {
  static properties = {
    tuples: { attribute: false }, types: { attribute: false },
    hiddenTypes: { attribute: false }, hiddenRelations: { attribute: false },
    zoomLevel: { state: true },
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
  `;

  constructor() {
    super();
    this.zoomLevel = 90;
  }

  #cy;
  #ro;
  #fit100; // the fitted zoom that counts as 100%

  // Nodes = distinct types (declared ∪ referenced); edges = distinct
  // (object_type, relation, user_type) triples drawn from the tuples.
  #elements() {
    const types = new Set((this.types || []).filter(Boolean));
    const edges = new Map();
    for (const t of this.tuples || []) {
      types.add(t.object_type); types.add(t.user_type);
      const key = `${t.object_type} ${t.relation} ${t.user_type}`;
      if (!edges.has(key)) edges.set(key, { source: t.object_type, target: t.user_type, label: t.relation });
    }
    const nodes = [...types].filter(Boolean).map((id) => ({ data: { id, label: id } }));
    const edgeEls = [...edges.values()].map((e, i) => ({ data: { id: 'te' + i, ...e } }));
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
    if (changed.has('tuples') || changed.has('types')) {
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
        <span class="zoomlvl" title="zoom level (100% = fit)">${this.zoomLevel}%</span>
        <button title="re-arrange nodes" @click=${() => this.#runLayout()}>↻</button>
        <button title="zoom in (+10%)" @click=${() => this.#zoom(10)}>+</button>
        <button title="zoom out (−10%)" @click=${() => this.#zoom(-10)}>−</button>
        <button title="center & fit" @click=${() => this.#fitReadable()}>⊙</button>
      </div>
      <div id="graph"></div>`;
  }
}
customElements.define('pg-types-graph', PgTypesGraph);
