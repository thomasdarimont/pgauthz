import { LitElement, html, css } from 'lit';
import './pg-grid.js';

// Tuple table (OpenFGA order: User · Relation · Object · Condition). Thin wrapper
// over pg-grid: supplies the columns, a prefix filter, and per-row copy text, and
// forwards cell clicks as `pick` events for the query builder.
export class PgTuples extends LitElement {
  static properties = { tuples: { type: Array } };

  static styles = css`
    :host { display: flex; flex-direction: column; min-height: 0; }
    pg-grid { flex: 1 1 auto; min-height: 0; }
  `;

  #pick(detail) {
    this.dispatchEvent(new CustomEvent('pick', { detail, bubbles: true, composed: true }));
  }

  #subj(x) { return `${x.user_type}:${x.user_id}${x.user_relation ? '#' + x.user_relation : ''}`; }
  #obj(x) { return `${x.object_type}:${x.object_id}`; }

  #columns() {
    return [
      { header: 'User', title: 'use as query subject',
        get: (x) => this.#subj(x),
        onClick: (x) => this.#pick({ user: { type: x.user_type, id: x.user_id } }) },
      { header: 'Relation', cellClass: 'rel', title: 'use as query relation',
        get: (x) => `#${x.relation}`,
        onClick: (x) => this.#pick({ relation: x.relation }) },
      { header: 'Object', title: 'use as query object',
        get: (x) => this.#obj(x),
        onClick: (x) => this.#pick({ object: { type: x.object_type, id: x.object_id } }) },
      { header: 'Condition',
        get: (x) => x.condition_name || '',
        render: (x) => x.condition_name
          ? html`<span class="cond" title=${'stored: ' + (x.condition_context || '(none)')}
              @click=${() => this.#pick({ condition: x.condition_name })}>⚖ ${x.condition_name}</span>`
          : '' },
    ];
  }

  // Prefix match against the subject, relation (with/without leading #), or object.
  #filter(x, q) {
    const rel = String(x.relation).toLowerCase();
    return this.#subj(x).toLowerCase().startsWith(q)
      || this.#obj(x).toLowerCase().startsWith(q)
      || rel.startsWith(q) || ('#' + rel).startsWith(q);
  }

  #rowText(x) {
    return [this.#subj(x), `#${x.relation}`, this.#obj(x), x.condition_name || ''].join('\t');
  }

  render() {
    return html`<pg-grid data-testid="tuples-grid"
      .rows=${this.tuples || []} .columns=${this.#columns()}
      .filter=${(x, q) => this.#filter(x, q)} .rowText=${(x) => this.#rowText(x)}
      searchPlaceholder="filter by prefix — internal_user:eva   #can_read   document:"></pg-grid>`;
  }
}
customElements.define('pg-tuples', PgTuples);
