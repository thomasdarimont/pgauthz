import { LitElement, html, css } from 'lit';

// Renders one node of the explain_access resolution tree, recursively. Green =
// the step contributed an allow, red = denied. Collapsible.
export class PgExplainTree extends LitElement {
  static properties = { node: { type: Object }, open: { state: true } };
  constructor() { super(); this.open = true; }

  // Reads the shared design tokens (inherited from :root into shadow DOM);
  // each var() has a fallback so the component still renders standalone.
  static styles = css`
    :host { display: block; font: var(--pg-text-code, 13px)/1.5 var(--pg-font-mono, ui-monospace, monospace); }
    .node { display: flex; align-items: baseline; gap: var(--pg-space-2, .5rem); padding: 1px 0; }
    .toggle { cursor: pointer; width: 1rem; color: var(--pg-muted, #888); user-select: none; }
    .badge { width: 1rem; text-align: center; font-weight: 700; }
    .allow > .badge { color: var(--pg-allow-fg, #1a7f37); }
    .deny  > .badge { color: var(--pg-deny-fg, #cf222e); }
    .children { margin-left: 1.1rem; border-left: 1px dotted var(--pg-tree-guide, #ccc); padding-left: var(--pg-space-2, .4rem); }
    .label .reason { color: var(--pg-reason-fg, #6639ba); }
    .label .muted { color: var(--pg-muted, #888); }
  `;

  _allowed(n) { return n.allowed === true || n.result === true; }

  _label(n) {
    const main = n.detail || [n.relation, n.object && `on ${n.object}`].filter(Boolean).join(' ') ||
      [n.subject, n.relation, n.object].filter(Boolean).join(' ');
    return html`<span class="label">${main || JSON.stringify(n)}
      ${n.reason ? html`<span class="reason">[${n.reason}]</span>` : ''}</span>`;
  }

  render() {
    const n = this.node;
    if (!n) return html``;
    const kids = n.children || [];
    return html`
      <div class="node ${this._allowed(n) ? 'allow' : 'deny'}">
        <span class="toggle" @click=${() => (this.open = !this.open)}>
          ${kids.length ? (this.open ? '▾' : '▸') : '•'}</span>
        <span class="badge">${this._allowed(n) ? '✔' : '✘'}</span>
        ${this._label(n)}
      </div>
      ${this.open && kids.length
        ? html`<div class="children">${kids.map(
            (c) => html`<pg-explain-tree .node=${c}></pg-explain-tree>`)}</div>`
        : ''}
    `;
  }
}
customElements.define('pg-explain-tree', PgExplainTree);
