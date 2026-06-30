import { LitElement, html, css } from 'lit';

// Read-only code view of the model (authz.describe_model DSL): line numbers,
// keyword highlighting, scrollable, half-screen tall by default.
export class PgModel extends LitElement {
  static properties = { dsl: { type: String }, types: { attribute: false } };

  static styles = css`
    :host { display: block; height: 100%; min-height: 0; }
    .editor {
      height: 100%; overflow: auto; display: flex;
      border: 1px solid var(--pg-border, #d0d7de); border-radius: var(--pg-radius-md, 6px);
      background: var(--pg-surface, #f6f8fa);
      font: var(--pg-text-code, 13px)/1.55 var(--pg-font-mono, ui-monospace, monospace);
    }
    .gutter {
      position: sticky; left: 0; z-index: 2; text-align: right; padding: .5rem .5rem .5rem .6rem;
      user-select: none; color: var(--pg-muted, #888);
      background: color-mix(in srgb, var(--pg-surface, #f6f8fa) 70%, var(--pg-border, #d0d7de));
      box-shadow: 1px 0 0 var(--pg-border, #d0d7de), 3px 0 5px -2px rgba(0, 0, 0, .15);
    }
    .code { padding: .5rem .8rem; }
    /* Pin every row in both columns to the same integer height so the line
       numbers line up exactly with the code (no sub-pixel line-height drift). */
    .gutter > div, .code .ln { height: 20px; line-height: 20px; }
    .code .ln { white-space: pre; }
    .code .ln.cmt { color: var(--pg-green, #1a7f37); font-style: italic; opacity: .85; }
    .kw  { color: var(--pg-primary, #0969da); font-weight: 600; }
    .neg { color: var(--pg-deny-fg, #cf222e); font-weight: 600; }
    .muted { color: var(--pg-muted, #888); padding: .5rem; }
  `;

  // Tokenize a line, highlighting DSL keywords (and "but not").
  _line(line) {
    const re = /(\bbut not\b)|(\b(?:store|model|schema|type|relations|define|or|and|from)\b)/g;
    const parts = [];
    let last = 0, m;
    while ((m = re.exec(line)) !== null) {
      if (m.index > last) parts.push(line.slice(last, m.index));
      parts.push(m[1] ? html`<span class="neg">${m[1]}</span>` : html`<span class="kw">${m[2]}</span>`);
      last = m.index + m[0].length;
    }
    if (last < line.length) parts.push(line.slice(last));
    return parts;
  }

  render() {
    if (!this.dsl) return html`<div class="editor"><span class="muted">(no model loaded)</span></div>`;
    const raw = this.dsl.replace(/\n+$/, '').split('\n');
    // Build rows, inserting an un-numbered spacer line before each "type …" (but
    // not the first). Only real model lines get a line number.
    const meta = new Map((this.types || []).map((t) => [t.name, t]));
    const rows = [];
    let n = 0;
    raw.forEach((line, i) => {
      const m = line.match(/^type\s+(\S+)/);
      if (m && i > 0 && raw[i - 1].trim() !== '') rows.push({ num: ++n, text: '' });
      if (m) {
        const t = meta.get(m[1]);
        if (t?.description) rows.push({ num: ++n, text: '# ' + t.description, comment: true });
        if (t?.labels?.length) rows.push({ num: ++n, text: '# labels: ' + t.labels.join(', '), comment: true });
      }
      rows.push({ num: ++n, text: line });
    });
    return html`<div class="editor">
      <div class="gutter">${rows.map((r) => html`<div>${r.num ?? ' '}</div>`)}</div>
      <div class="code">${rows.map((r) => html`<div class="ln ${r.comment ? 'cmt' : ''}">${r.comment ? r.text : r.text ? this._line(r.text) : ' '}</div>`)}</div>
    </div>`;
  }
}
customElements.define('pg-model', PgModel);
