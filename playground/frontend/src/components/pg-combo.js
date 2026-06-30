import { LitElement, html, css } from 'lit';

// A tiny editable combobox: a free-text input with a dropdown of suggestions.
// Unlike a <datalist>, clicking shows the *full* option list even when the field
// already holds a value (a full value just shows everything so you can pick
// another); typing filters by substring. Free text is always allowed.
export class PgCombo extends LitElement {
  static properties = {
    value: { type: String }, options: { attribute: false }, placeholder: { type: String },
    open: { state: true }, active: { state: true },
  };

  constructor() { super(); this.value = ''; this.options = []; this.placeholder = ''; this.open = false; this.active = -1; }

  static styles = css`
    :host { display: inline-block; position: relative; }
    input {
      padding: .25rem .45rem; border: 1px solid var(--pg-border, #d0d7de); border-radius: var(--pg-radius-sm, 4px);
      background: var(--pg-bg, #fff); color: var(--pg-accent, #6639ba);
      font: var(--pg-text-code, 13px)/1.4 var(--pg-font-mono, ui-monospace, monospace);
    }
    input:focus { outline: 2px solid var(--pg-primary, #0969da); outline-offset: -1px; border-color: var(--pg-primary, #0969da); }
    input.unknown { border-color: var(--pg-deny-fg, #cf222e); color: var(--pg-deny-fg, #cf222e); }
    input.unknown:focus { outline-color: var(--pg-deny-fg, #cf222e); border-color: var(--pg-deny-fg, #cf222e); }
    .opts {
      position: absolute; z-index: 10; top: 100%; left: 0; min-width: 100%; max-height: 220px; overflow: auto;
      margin: 2px 0 0; padding: 2px; list-style: none; box-sizing: border-box;
      background: var(--pg-bg, #fff); border: 1px solid var(--pg-border, #d0d7de);
      border-radius: var(--pg-radius-md, 6px); box-shadow: 0 6px 20px rgba(0, 0, 0, .14);
    }
    .opts li {
      padding: 2px 8px; cursor: pointer; white-space: nowrap; border-radius: var(--pg-radius-sm, 4px);
      font: var(--pg-text-code, 13px)/1.6 var(--pg-font-mono, ui-monospace, monospace); color: var(--pg-fg, #1f2328);
    }
    .opts li.active, .opts li:hover { background: var(--pg-primary, #0969da); color: #fff; }
  `;

  #filtered() {
    const v = (this.value || '').toLowerCase();
    const opts = this.options || [];
    const exact = opts.some((o) => String(o).toLowerCase() === v);
    // Empty or a full match → show everything (so you can pick a different value).
    if (!v || exact) return opts;
    return opts.filter((o) => String(o).toLowerCase().includes(v));
  }

  #emit() {
    this.dispatchEvent(new CustomEvent('value-changed', { detail: { value: this.value }, bubbles: true, composed: true }));
  }

  #pick(o) { this.value = o; this.open = false; this.active = -1; this.#emit(); }

  #key(e, opts) {
    if (e.key === 'ArrowDown') { e.preventDefault(); this.open = true; this.active = Math.min(this.active + 1, opts.length - 1); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); this.active = Math.max(this.active - 1, 0); }
    else if (e.key === 'Enter') {
      if (this.open && this.active >= 0 && opts[this.active]) { e.preventDefault(); this.#pick(opts[this.active]); }
      else { this.open = false; this.dispatchEvent(new CustomEvent('submit', { bubbles: true, composed: true })); }
    } else if (e.key === 'Escape') { this.open = false; }
  }

  // A non-empty value that isn't one of the known options (when there are any).
  #unknown() {
    const v = this.value || '';
    return v !== '' && (this.options || []).length > 0 && !this.options.includes(v);
  }

  render() {
    const opts = this.#filtered();
    const v = this.value || '';
    const ph = this.placeholder || '';
    const size = Math.max(v.length + 2, ph.length, 8);
    return html`
      <input class=${this.#unknown() ? 'unknown' : ''} title=${this.#unknown() ? 'not found in this store' : ''}
        .value=${v} placeholder=${ph} size=${size} spellcheck="false" autocomplete="off"
        @focus=${() => { this.open = true; this.active = -1; }}
        @click=${() => { this.open = true; }}
        @input=${(e) => { this.value = e.target.value; this.open = true; this.active = -1; this.#emit(); }}
        @blur=${() => setTimeout(() => { this.open = false; }, 130)}
        @keydown=${(e) => this.#key(e, opts)}>
      ${this.open && opts.length ? html`<ul class="opts">
        ${opts.map((o, i) => html`<li class=${i === this.active ? 'active' : ''}
          @mousedown=${(e) => { e.preventDefault(); this.#pick(o); }}>${o}</li>`)}
      </ul>` : ''}
    `;
  }
}
customElements.define('pg-combo', PgCombo);
