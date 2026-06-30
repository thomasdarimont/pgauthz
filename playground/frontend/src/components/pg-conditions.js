import { LitElement, html, css } from 'lit';

// Lists the store's named conditions (ABAC expressions). Each shows its language
// (sql/cel), the required request/stored context keys, and the expression. These
// are what conditional tuples reference by name.
export class PgConditions extends LitElement {
  static properties = { conditions: { attribute: false } };

  static styles = css`
    :host { display: flex; flex-direction: column; min-height: 0; }
    .scroll { flex: 1 1 auto; min-height: 120px; overflow: auto;
      border: 1px solid var(--pg-border, #d0d7de); border-radius: var(--pg-radius-md, 6px);
      padding: var(--pg-space-2, .5rem); }
    .cond { padding: var(--pg-space-2, .5rem) 0; border-bottom: 1px solid var(--pg-border, #d0d7de); }
    .cond:last-child { border-bottom: none; }
    .head { display: flex; align-items: center; gap: var(--pg-space-2, .5rem); }
    .name { font-family: var(--pg-font-mono, monospace); font-weight: 600; color: var(--pg-accent, #6639ba); }
    .lang { font-size: .68rem; text-transform: uppercase; letter-spacing: .03em;
      padding: 1px 6px; border-radius: 999px; background: var(--pg-surface, #eee); color: var(--pg-muted, #666);
      border: 1px solid var(--pg-border, #d0d7de); }
    .keys { font-size: var(--pg-text-sm, .8rem); color: var(--pg-muted, #888); margin: .25rem 0; }
    .keys code { color: var(--pg-fg, #1f2328); }
    pre { margin: .25rem 0 0; padding: var(--pg-space-2, .5rem); overflow: auto;
      background: var(--pg-surface, #f6f8fa); border-radius: var(--pg-radius-sm, 4px);
      font: var(--pg-text-code, 12px)/1.5 var(--pg-font-mono, monospace); color: var(--pg-fg, #1f2328); }
    .muted { color: var(--pg-muted, #888); }
  `;

  // The stored expression is heavily indented (it comes from a $cond$ … $cond$
  // block); strip surrounding blank lines and the common leading indent.
  #expr(s) {
    const body = (s || '').replace(/^\s*\n/, '').replace(/\s+$/, '');
    const lines = body.split('\n');
    const indents = lines.filter((l) => l.trim()).map((l) => l.match(/^\s*/)[0].length);
    const min = indents.length ? Math.min(...indents) : 0;
    return lines.map((l) => l.slice(min)).join('\n');
  }

  // required_context arrives as a JSON string like {"request":[...],"stored":[...]}.
  #keys(raw) {
    try {
      const o = JSON.parse(raw || '{}');
      const fmt = (a) => (a || []).join(', ');
      return { request: fmt(o.request), stored: fmt(o.stored) };
    } catch { return { request: '', stored: '' }; }
  }

  render() {
    const conds = this.conditions || [];
    if (!conds.length) return html`<div class="scroll"><p class="muted">(no conditions defined in this store)</p></div>`;
    return html`<div class="scroll">
      ${conds.map((c) => {
        const k = this.#keys(c.required_context);
        return html`<div class="cond">
          <div class="head"><span class="name">${c.name}</span><span class="lang">${c.lang}</span></div>
          ${k.request || k.stored ? html`<div class="keys">
            ${k.request ? html`request: <code>${k.request}</code>&nbsp;&nbsp;` : ''}
            ${k.stored ? html`stored: <code>${k.stored}</code>` : ''}
          </div>` : ''}
          <pre>${this.#expr(c.expression)}</pre>
        </div>`;
      })}
    </div>`;
  }
}
customElements.define('pg-conditions', PgConditions);
