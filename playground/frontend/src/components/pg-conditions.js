import { LitElement, html, css } from 'lit';
import './pg-grid.js';

// Named conditions (ABAC expressions) as a grid: Name · Lang · Request keys ·
// Stored keys · Expression. Thin wrapper over pg-grid.
export class PgConditions extends LitElement {
  static properties = { conditions: { attribute: false } };

  static styles = css`
    :host { display: flex; flex-direction: column; min-height: 0; }
    pg-grid { flex: 1 1 auto; min-height: 0; }
  `;

  // The stored expression is heavily indented (from a $cond$ … $cond$ block);
  // strip surrounding blank lines and the common leading indent.
  #expr(s) {
    const body = (s || '').replace(/^\s*\n/, '').replace(/\s+$/, '');
    const lines = body.split('\n');
    const indents = lines.filter((l) => l.trim()).map((l) => l.match(/^\s*/)[0].length);
    const min = indents.length ? Math.min(...indents) : 0;
    return lines.map((l) => l.slice(min)).join('\n');
  }

  // required_context arrives as JSON like {"request":[...],"stored":[...]}.
  #keys(raw) {
    try {
      const o = JSON.parse(raw || '{}');
      const fmt = (a) => (a || []).join(', ');
      return { request: fmt(o.request), stored: fmt(o.stored) };
    } catch { return { request: '', stored: '' }; }
  }

  #columns() {
    return [
      { header: 'Name', cellClass: 'name', get: (c) => c.name },
      { header: 'Lang', get: (c) => c.lang, render: (c) => html`<span class="lang">${c.lang}</span>` },
      { header: 'Request keys', get: (c) => this.#keys(c.required_context).request || '—' },
      { header: 'Stored keys', get: (c) => this.#keys(c.required_context).stored || '—' },
      { header: 'Expression', cellClass: 'expr', get: (c) => this.#expr(c.expression) },
    ];
  }

  #filter(c, q) {
    return String(c.name).toLowerCase().includes(q)
      || String(c.lang).toLowerCase().includes(q)
      || String(c.expression).toLowerCase().includes(q);
  }

  #rowText(c) {
    const k = this.#keys(c.required_context);
    return [c.name, c.lang, k.request, k.stored, this.#expr(c.expression)].join('\t');
  }

  render() {
    return html`<pg-grid data-testid="conditions-grid"
      .rows=${this.conditions || []} .columns=${this.#columns()}
      .filter=${(c, q) => this.#filter(c, q)} .rowText=${(c) => this.#rowText(c)}
      searchPlaceholder="filter conditions — name, lang, or expression"></pg-grid>`;
  }
}
customElements.define('pg-conditions', PgConditions);
