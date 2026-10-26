import { html, nothing } from 'lit';
import { PgcElement } from '../base.js';
import { api } from '../api.js';

// A store-group picker that scales to a tenant per group: a text input over
// a datalist of the groups the person may see that match what was typed,
// fetched as they type (api/platform/groups/names) — never the whole list.
// A pick is taken when the value is a known name (or empty, when allowed);
// an unknown name is marked. Fires `pick` with the name.
//
//   <pgc-group-pick .value=${v} placeholder="…" allow-empty .exclude=${[...]}
//                   data-testid="…" @pick=${(e) => use(e.detail)}></pgc-group-pick>
let seq = 0;
export class PgcGroupPick extends PgcElement {
  static properties = {
    value: { type: String },
    placeholder: { type: String },
    title: { type: String },
    allowEmpty: { type: Boolean, attribute: 'allow-empty' },
    exclude: { type: Array }, // names not offered (a group's own name, groups already chosen)
    testid: { type: String },
    names: { state: true },
    invalid: { state: true },
  };

  constructor() {
    super();
    this.value = '';
    this.placeholder = '';
    this.title = '';
    this.allowEmpty = false;
    this.exclude = [];
    this.testid = '';
    this.names = [];
    this.invalid = false;
    this._id = `dl-group-pick-${++seq}`;
    this._timer = 0;
  }

  _known(v) {
    return (v === '' && this.allowEmpty) || (this.names.includes(v) && !(this.exclude ?? []).includes(v));
  }

  async _fetch(q) {
    try {
      const r = await api.groupNames(q);
      this.names = (r.names ?? []).filter((n) => !(this.exclude ?? []).includes(n));
    } catch {
      this.names = [];
    }
  }

  _onInput(e) {
    const v = e.target.value.trim();
    this.value = v;
    this.invalid = !this._known(v) && v !== '';
    clearTimeout(this._timer);
    this._timer = setTimeout(() => this._fetch(v), 150);
  }

  async _onChange(e) {
    const v = e.target.value.trim();
    if (!this._known(v)) {
      // the fetch may not have answered yet: ask for this name exactly
      await this._fetch(v);
      if (!this._known(v)) {
        this.invalid = v !== '';
        return;
      }
    }
    this.invalid = false;
    this.dispatchEvent(new CustomEvent('pick', { detail: v, bubbles: true }));
  }

  render() {
    return html`<input
        class="mono group-pick ${this.invalid ? 'invalid' : ''}"
        list=${this._id}
        .value=${this.value ?? ''}
        placeholder=${this.placeholder}
        title=${this.title || nothing}
        autocomplete="off"
        data-testid=${this.testid || nothing}
        @focus=${() => this.names.length || this._fetch(this.value ?? '')}
        @input=${this._onInput}
        @change=${this._onChange}
      />
      <datalist id=${this._id}>${this.names.map((n) => html`<option value=${n}></option>`)}</datalist>`;
  }
}
customElements.define('pgc-group-pick', PgcGroupPick);
