import { LitElement, html, css } from 'lit';

// A small editable JSON code editor: line-number gutter + syntax highlighting.
// Highlighting is a classic overlay — a coloured <pre> sits behind a transparent
// <textarea>; the textarea owns editing/caret, the <pre> shows colour, and the
// two are kept in sync (same font/padding, scroll mirrored). No external lib.
export class PgJsonEditor extends LitElement {
  static properties = { value: { type: String }, placeholder: { type: String },
    readonly: { type: Boolean }, invalid: { state: true } };

  constructor() { super(); this.value = ''; this.placeholder = ''; this.readonly = false; this.invalid = false; }

  static styles = css`
    :host { display: flex; flex-direction: column; }
    /* Fill the host when it's stretched (e.g. the AuthZEN request pane); otherwise
       fall back to a comfortable 9rem minimum (e.g. the inline request-context box). */
    .editor { display: flex; flex: 1 1 auto; min-height: 9rem; overflow: hidden;
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
    textarea[readonly] { caret-color: transparent; cursor: default; }
    .hl .k { color: var(--pg-primary, #0969da); }              /* key */
    .hl .s { color: var(--pg-green, #1a7f37); }                /* string value */
    .hl .b { color: var(--pg-accent, #6639ba); font-weight: 600; } /* bool/null */
    .hl .n { color: var(--pg-deny-fg, #cf222e); }              /* number */
    .hl .p { color: var(--pg-muted, #888); }                   /* punctuation */
    /* Pretty-print button, floated top-right; dimmed until the editor is hovered. */
    .fmt { position: absolute; top: 4px; right: 4px; z-index: 2; cursor: pointer;
      font: var(--pg-text-sm, 11px)/1 var(--pg-font-sans, system-ui, sans-serif);
      padding: 3px 8px; border: 1px solid var(--pg-border, #d0d7de); border-radius: var(--pg-radius-sm, 4px);
      background: var(--pg-bg, #fff); color: var(--pg-muted, #6e7781);
      opacity: .35; transition: opacity .12s; }
    .editor:hover .fmt { opacity: 1; }
    .fmt:hover { color: var(--pg-fg, #1f2328); border-color: var(--pg-muted, #6e7781); }
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
    this.invalid = false;
    this.dispatchEvent(new CustomEvent('value-changed', { detail: { value: this.value }, bubbles: true, composed: true }));
  }

  // Pretty-print the JSON (2-space indent). On invalid JSON, flag it (red border)
  // and leave the text untouched so nothing is lost.
  _format() {
    const text = (this.value || '').trim();
    if (!text) return;
    let parsed;
    try { parsed = JSON.parse(text); } catch { this.invalid = true; return; }
    this.invalid = false;
    this.value = JSON.stringify(parsed, null, 2);
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
          ?readonly=${this.readonly} .value=${text} @input=${this._onInput} @scroll=${this._onScroll}></textarea>
        ${this.readonly ? '' : html`<button class="fmt" type="button" title="format JSON (pretty-print)"
          data-testid="json-format" @click=${() => this._format()}>Format</button>`}
      </div>
    </div>`;
  }
}
customElements.define('pg-json-editor', PgJsonEditor);
