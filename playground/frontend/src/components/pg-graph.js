import { LitElement, html, css } from 'lit';
import cytoscape from 'cytoscape';
import { cyToDot } from '../dot.js';

// Shared base for the playground's Cytoscape graph views (pg-types-graph,
// pg-access-graph). Owns the boilerplate — Cytoscape lifecycle, zoom (buttons +
// Ctrl/⌘ or trackpad-pinch wheel-zoom about the cursor), fit, DOT export, resize
// observer — and delegates the graph-specific parts to hooks a subclass overrides:
//   buildElements() → cytoscape elements   cyStyle() → style array
//   layoutOptions() → layout config        graphName() → DOT export name
//   onNodeTap(evt), afterLayout(), extraControls(), legend(),
//   fitPadding(), minReadableZoom()  (all optional)
// Subclasses use this._cy (the Cytoscape instance) and this._rebuild() from updated().
export class PgGraph extends LitElement {
  static properties = { zoomLevel: { state: true }, copied: { state: true } };

  static styles = css`
    :host { display: block; position: relative;
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
    this.copied = false;
  }

  // ── Hooks (override in subclasses) ─────────────────────────────────
  graphName() { return 'graph'; }         // DOT export name
  buildElements() { return []; }          // → cytoscape elements
  cyStyle() { return []; }                // → cytoscape style array
  layoutOptions() { return { name: 'grid', fit: false }; }
  onNodeTap(/* evt */) {}                 // node click handler
  _prepare() {}                           // runs before layout (e.g. apply a visibility filter)
  afterLayout() { this._fitReadable(); }  // runs on layoutstop
  extraControls() { return ''; }          // extra toolbar html (left of the zoom level)
  legend() { return ''; }                 // legend html (rendered outside .controls)
  fitPadding() { return 30; }
  minReadableZoom() { return 0.8; }

  // ── Cytoscape lifecycle ────────────────────────────────────────────
  _cy;       // protected: the Cytoscape instance
  #fit100;   // the fitted zoom that counts as 100%
  #ro;

  firstUpdated() {
    const graphEl = this.renderRoot.querySelector('#graph');
    this._cy = cytoscape({
      container: graphEl,
      elements: this.buildElements(),
      layout: { name: 'preset' },
      minZoom: 0.3, maxZoom: 3,
      userZoomingEnabled: false, // a plain wheel scrolls the page; zoom is gated below
      style: this.cyStyle(),
    });
    this._cy.on('zoom', () => this._updateZoom());
    this._cy.on('tap', 'node', (e) => this.onNodeTap(e));
    this._prepare();
    this._runLayout();
    // Ctrl/⌘ + wheel (and trackpad pinch, delivered as a ctrlKey wheel) zooms about
    // the cursor; a plain wheel is left alone so the page/pane scrolls as normal.
    graphEl.addEventListener('wheel', (e) => {
      if (!(e.ctrlKey || e.metaKey)) return;
      e.preventDefault();
      const rect = graphEl.getBoundingClientRect();
      this._zoomBy(Math.exp(-e.deltaY * 0.002), { x: e.clientX - rect.left, y: e.clientY - rect.top });
    }, { passive: false });
    this.#ro = new ResizeObserver(() => this._cy?.resize());
    this.#ro.observe(this);
  }

  disconnectedCallback() {
    this.#ro?.disconnect();
    this._cy?.destroy();
    this._cy = undefined;
    super.disconnectedCallback();
  }

  // Rebuild the elements from current state and re-run the layout. Subclasses call
  // this from updated() when their inputs change.
  _rebuild() {
    if (!this._cy) return;
    this._cy.elements().remove();
    this._cy.add(this.buildElements());
    this._prepare();
    this._runLayout();
  }

  // Lay out only the *visible* elements, so hidden nodes don't reserve space or
  // pull the layout around. _prepare() must have set visibility first.
  _runLayout() {
    if (!this._cy) return;
    const vis = this._cy.elements(':visible');
    const l = (vis.length ? vis : this._cy.elements()).layout(this.layoutOptions());
    l.one('layoutstop', () => this.afterLayout());
    l.run();
  }

  // ── Zoom / fit ─────────────────────────────────────────────────────
  _fitReadable() {
    if (!this._cy || this._cy.elements().length === 0) return;
    this._cy.fit(undefined, this.fitPadding());
    let z = this._cy.zoom();
    const min = this.minReadableZoom();
    if (z < min) z = min; else if (z > 2) z = 2;
    this.#fit100 = z;         // this fitted zoom is "100%"
    this._cy.zoom(z * 0.9);   // start zoomed out to 90%
    this._cy.center();
    this._updateZoom();
  }

  _updateZoom() {
    if (this._cy && this.#fit100) this.zoomLevel = Math.round((this._cy.zoom() / this.#fit100) * 100);
  }

  // Multiply the zoom by `factor` (>1 in, <1 out), clamped, about `pos` (rendered
  // coords) or the viewport centre. Multiplicative so a few clicks/notches go far.
  _zoomBy(factor, pos) {
    if (!this._cy) return;
    const level = Math.max(this._cy.minZoom(), Math.min(this._cy.maxZoom(), this._cy.zoom() * factor));
    this._cy.zoom({ level, renderedPosition: pos || { x: this._cy.width() / 2, y: this._cy.height() / 2 } });
  }

  async #copyDot() {
    const dot = cyToDot(this._cy, { name: this.graphName() });
    if (!dot) return;
    try {
      await navigator.clipboard.writeText(dot);
      this.copied = true;
      setTimeout(() => (this.copied = false), 1200);
    } catch { /* clipboard unavailable (insecure context) */ }
  }

  render() {
    return html`
      <div class="controls">
        ${this.extraControls()}
        <span class="zoomlvl" title="Ctrl/⌘ + scroll (or pinch) to zoom · buttons to step">${this.zoomLevel}%</span>
        <button title="re-arrange nodes" @click=${() => this._runLayout()}>↻</button>
        <button title="zoom in" @click=${() => this._zoomBy(1.35)}>+</button>
        <button title="zoom out" @click=${() => this._zoomBy(1 / 1.35)}>−</button>
        <button title="center & fit" @click=${() => this._fitReadable()}>⊙</button>
        <button title="copy as Graphviz DOT" data-testid="copy-dot" @click=${() => this.#copyDot()}>${this.copied ? '✓' : '⧉'}</button>
      </div>
      ${this.legend()}
      <div id="graph"></div>`;
  }
}
