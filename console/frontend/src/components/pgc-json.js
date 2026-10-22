import { html, nothing } from 'lit';
import { PgcElement } from '../base.js';
import { t } from '../i18n.js';
import { highlightJSON } from '../highlight.js';

// A JSON field: a textarea laid over a highlighted copy of its text, parsed
// on every keystroke. Invalid text marks the field, names the line and
// column, and sets the textarea's custom validity so the surrounding form's
// submit is refused by the browser until it is fixed; valid text can be
// re-indented with Format. The parent keeps the raw text (json-input event,
// detail {text, value, error}) and parses it again on submit as before.
export class PgcJson extends PgcElement {
  static properties = {
    value: { type: String }, // the text
    rows: { type: Number },
    required: { type: Boolean },
    testid: { type: String },
  };

  constructor() {
    super();
    this.value = '';
    this.rows = 4;
    this.required = false;
    this.testid = '';
  }

  // {value} for valid text (null when empty and not required), else {error:
  // {msg, line, col}}: the parser's message without its position suffix, the
  // position as line and column when it gives one.
  static check(text, required) {
    const s = String(text ?? '').trim();
    if (!s) return required ? { error: { msg: t('a value is required') } } : { value: null };
    try {
      return { value: JSON.parse(s) };
    } catch (e) {
      const msg = String(e.message ?? e);
      let line, col;
      let m = /line (\d+) column (\d+)/.exec(msg);
      if (m) [line, col] = [Number(m[1]), Number(m[2])];
      else if ((m = /position (\d+)/.exec(msg))) {
        const pos = Math.min(Number(m[1]), s.length);
        const before = s.slice(0, pos);
        line = before.split('\n').length;
        col = pos - before.lastIndexOf('\n');
      }
      const clean = msg
        .replace(/^JSON\.parse:\s*/, '')
        .replace(/,?\s*(?:\.\.\.)?".*" is not valid JSON$/s, '')
        .replace(/\s*in JSON at position \d+.*$/, '')
        .replace(/\s*\(line \d+ column \d+\)\s*$/, '')
        .replace(/\s+at line \d+ column \d+ of the JSON data$/, '');
      return { error: { msg: clean, line, col } };
    }
  }

  // Bring the first invalid JSON field under root to the person: open the
  // collapsed section it may sit in, focus it, and show the browser's
  // validity message next to it. True when there was one.
  static report(root) {
    const ta = root.querySelector('pgc-json textarea:invalid');
    if (!ta) return false;
    for (let d = ta.closest('details'); d; d = d.parentElement?.closest('details')) d.open = true;
    ta.focus();
    ta.reportValidity();
    return true;
  }

  _emit(text) {
    this.value = text;
    const c = PgcJson.check(text, this.required);
    this.dispatchEvent(
      new CustomEvent('json-input', {
        detail: { text, value: c.value ?? null, error: c.error ?? null },
        bubbles: true,
      }),
    );
  }

  _format() {
    const c = PgcJson.check(this.value, this.required);
    if (c.error || c.value === null) return;
    this._emit(JSON.stringify(c.value, null, 2));
  }

  // The browser's own form validation refused a submit because of this
  // field: open the collapsed section it may sit in, then let the browser
  // show its message (it skips controls it cannot focus).
  _onInvalid(e) {
    let opened = false;
    for (let d = e.target.closest('details'); d; d = d.parentElement?.closest('details'))
      if (!d.open) ((d.open = true), (opened = true));
    if (opened && !this._reporting) {
      this._reporting = true;
      requestAnimationFrame(() => {
        e.target.reportValidity();
        this._reporting = false;
      });
    }
  }

  _sync(e) {
    const pre = e.target.previousElementSibling;
    pre.scrollTop = e.target.scrollTop;
    pre.scrollLeft = e.target.scrollLeft;
  }

  updated() {
    const ta = this.querySelector('textarea');
    const c = PgcJson.check(this.value, this.required);
    ta?.setCustomValidity(c.error ? `${t('Invalid JSON')}: ${c.error.msg}` : '');
  }

  render() {
    const text = this.value ?? '';
    const c = PgcJson.check(text, this.required);
    const lines = highlightJSON(text + '\n');
    if (c.error?.line && lines[c.error.line - 1])
      lines[c.error.line - 1] = html`<span class="errline">${lines[c.error.line - 1]}</span>`;
    return html`<div class="json-editor ${c.error ? 'invalid' : ''}">
        <pre class="json-hl" aria-hidden="true">${lines}</pre>
        <textarea
          class="mono"
          rows=${this.rows}
          wrap="off"
          spellcheck="false"
          autocomplete="off"
          ?required=${this.required}
          data-testid=${this.testid || nothing}
          .value=${text}
          @input=${(e) => this._emit(e.target.value)}
          @invalid=${this._onInvalid}
          @scroll=${this._sync}
        ></textarea>
      </div>
      <div class="json-status">
        ${
          c.error
            ? html`<span class="json-warn" data-testid=${this.testid ? this.testid + '-error' : nothing}
                >⚠
                ${t('Invalid JSON')}${c.error.line ? ` (${t('line {line}, column {col}', { line: c.error.line, col: c.error.col })})` : ''}:
                ${c.error.msg}</span
              >`
            : html`<span class="json-ok">${text.trim() ? '✓ ' + t('valid JSON') : nothing}</span> ${
                  text.trim()
                    ? html`<button type="button" class="link" @click=${this._format}>${t('Format')}</button>`
                    : nothing
                }`
        }
      </div>`;
  }
}
customElements.define('pgc-json', PgcJson);
