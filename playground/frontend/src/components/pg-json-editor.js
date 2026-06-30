import { LitElement, html, css } from 'lit';

// A small editable JSON code editor: line-number gutter + syntax highlighting.
// Highlighting is a classic overlay — a coloured <pre> sits behind a transparent
// <textarea>; the textarea owns editing/caret, the <pre> shows colour, and the
// two are kept in sync (same font/padding, scroll mirrored). No external lib.
export class PgJsonEditor extends LitElement {
  static properties = { value: { type: String }, placeholder: { type: String }, invalid: { state: true } };

  constructor() { super(); this.value = ''; this.placeholder = ''; this.invalid = false; }

  static styles = css`
    :host { display: block; }
    .editor { display: flex; height: 9rem; overflow: hidden;
      border: 1px solid var(--pg-border, #d0d7de); border-radius: var(--pg-radius-md, 6px);
      background: var(--pg-surface, #f6f8fa);
      font: var(--pg-text-code, 13px)/1.55 var(--pg-font-mono, ui-monospace, monospace); }
    .editor.invalid { border-color: var(--pg-deny-fg, #cf222e); }
    .gutter { flex: 0 0 auto; overflow: hidden; text-align: right; padding: .5rem .5rem .5rem .6rem;
      user-select: none; color: var(--pg-muted, #888);
      background: color-mix(in srgb, var(--pg-surface, #f6f8fa) 70%, var(--pg-border, #d0d7de)); }
    .gutter div { white-space: pre; height: 20px; line-height: 20px; }
    .wrap { position: relative; flex: 1 1 auto; overflow: hidden; }
    .hl, textarea { margin: 0; border: 0; padding: .5rem .6rem; font: inherit; line-height: 20px;
      white-space: pre; tab-size: 2; position: absolute; inset: 0; overflow: auto; }
    .hl { pointer-events: none; color: var(--pg-fg, #1f2328); }
    textarea { background: transparent; color: transparent; caret-color: var(--pg-fg, #1f2328);
      resize: none; outline: none; }
    .hl .k { color: var(--pg-primary, #0969da); }              /* key */
    .hl .s { color: var(--pg-green, #1a7f37); }                /* string value */
    .hl .b { color: var(--pg-accent, #6639ba); font-weight: 600; } /* bool/null */
    .hl .n { color: var(--pg-deny-fg, #cf222e); }              /* number */
    .hl .p { color: var(--pg-muted, #888); }                   /* punctuation */
  `;

  _tokens(text) {
    const re = /("(?:[^"\\]|\\.)*"\s*:)|("(?:[^"\\]|\\.)*")|(\b(?:true|false|null)\b)|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)|([{}[\],:])/g;
    const parts = []; let last = 0, m;
    while ((m = re.exec(text)) !== null) {
      if (m.index > last) parts.push(text.slice(last, m.index));
      const cls = m[1] ? 'k' : m[2] ? 's' : m[3] ? 'b' : m[4] ? 'n' : 'p';
      parts.push(html`<span class=${cls}>${m[0]}</span>`);
      last = m.index + m[0].length;
    }
    if (last < text.length) parts.push(text.slice(last));
    return parts;
  }

  _onInput(e) {
    this.value = e.target.value;
    this.dispatchEvent(new CustomEvent('value-changed', { detail: { value: this.value }, bubbles: true, composed: true }));
  }

  // Mirror the textarea's scroll onto the highlight layer and gutter.
  _onScroll(e) {
    const ta = e.target;
    const hl = this.renderRoot.querySelector('.hl');
    const gutter = this.renderRoot.querySelector('.gutter');
    if (hl) { hl.scrollTop = ta.scrollTop; hl.scrollLeft = ta.scrollLeft; }
    if (gutter) gutter.scrollTop = ta.scrollTop;
  }

  render() {
    const text = this.value || '';
    // Always show at least 5 line numbers (so an empty/placeholder editor still
    // reads as a code area), and grow with the content.
    const lines = Math.max(5, text.split('\n').length);
    return html`<div class="editor ${this.invalid ? 'invalid' : ''}">
      <div class="gutter">${Array.from({ length: lines }, (_, i) => html`<div>${i + 1}</div>`)}</div>
      <div class="wrap">
        <pre class="hl" aria-hidden="true">${this._tokens(text)}${'\n'}</pre>
        <textarea spellcheck="false" autocapitalize="off" autocomplete="off" placeholder=${this.placeholder}
          .value=${text} @input=${this._onInput} @scroll=${this._onScroll}></textarea>
      </div>
    </div>`;
  }
}
customElements.define('pg-json-editor', PgJsonEditor);
