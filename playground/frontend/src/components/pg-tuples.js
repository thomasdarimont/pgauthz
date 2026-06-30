import { LitElement, html, css } from 'lit';

// Searchable, paginated tuple table with resizable columns. Tuples are shown in
// OpenFGA order — User · Relation · Object · Condition. The filter is a PREFIX
// expression matched (case-insensitively) against the subject (`internal_user:eva`),
// the relation (`#can_read`), or the object (`document:`). The first three columns
// have draggable borders (table-layout: fixed + a <colgroup>); Condition flexes.
export class PgTuples extends LitElement {
  static properties = {
    tuples: { type: Array },
    filter: { state: true }, widths: { state: true },
    page: { state: true }, pageSize: { state: true },
  };

  constructor() {
    super();
    this.filter = '';
    this.widths = null; // null → measure content, then lock in resizable widths
    this.page = 0;
    this.pageSize = 25;
  }

  // When the data changes (e.g. switching store), re-fit columns and reset paging.
  willUpdate(changed) {
    if (changed.has('tuples')) { this.widths = null; this.page = 0; }
  }

  // After an auto-layout render, capture the content-fit column widths so the
  // columns start sized to their contents and become resizable from there.
  updated() {
    if (this.widths) return;
    const ths = this.renderRoot.querySelectorAll('thead th');
    if (ths.length >= 4) {
      this.widths = [0, 1, 2, 3].map((i) => Math.max(56, Math.min(300, ths[i].offsetWidth)));
    }
  }

  static styles = css`
    :host { display: flex; flex-direction: column; min-height: 0; }
    .search {
      box-sizing: border-box;
      width: 100%; padding: var(--pg-space-2, .5rem); margin-bottom: var(--pg-space-2, .5rem);
      border: 1px solid var(--pg-border, #d0d7de); border-radius: var(--pg-radius-md, 6px);
      background: var(--pg-bg, #fff); color: var(--pg-fg, #1f2328); font: inherit;
    }
    .scroll {
      flex: 1 1 auto; min-height: 120px; overflow: auto;
      border: 1px solid var(--pg-border, #d0d7de); border-radius: var(--pg-radius-md, 6px);
      padding: var(--pg-space-2, .5rem);
    }
    table { border-collapse: collapse;
      font: var(--pg-text-code, 12px)/1.5 var(--pg-font-mono, ui-monospace, monospace); }
    th { text-align: left; font-weight: 600; color: var(--pg-muted, #888); white-space: nowrap;
      padding: var(--pg-space-1, .25rem) var(--pg-space-2, .5rem);
      position: sticky; top: 0; z-index: 1; background: var(--pg-bg, #fff);
      border-bottom: 1px solid var(--pg-border, #d0d7de); }
    /* Thin gridlines (every cell, including the Condition column) */
    th, td { border-right: 1px solid var(--pg-border, #d0d7de); border-bottom: 1px solid var(--pg-border, #d0d7de); }
    table { empty-cells: show; }
    /* Draggable column border */
    .resizer { position: absolute; top: 0; right: 0; width: 9px; height: 100%; cursor: col-resize;
      user-select: none; touch-action: none; }
    .resizer::after { content: ""; position: absolute; right: 3px; top: 3px; bottom: 3px; width: 2px;
      border-radius: 2px; background: transparent; }
    .resizer:hover::after, .resizer.active::after { background: var(--pg-primary, #0969da); }
    td { padding: var(--pg-space-1, .25rem) var(--pg-space-2, .5rem); vertical-align: top;
      overflow-wrap: anywhere; word-break: break-word; }
    .rel { color: var(--pg-reason-fg, #6639ba); }
    .pick { cursor: pointer; }
    .pick:hover { text-decoration: underline; text-underline-offset: 2px; }
    tr:hover td { background: color-mix(in srgb, var(--pg-primary, #0969da) 6%, transparent); }
    .cond { display: inline-flex; align-items: center; gap: .2rem; white-space: nowrap; cursor: pointer;
      padding: 0 6px; border-radius: 999px; font-size: .68rem;
      background: color-mix(in srgb, var(--pg-accent, #6639ba) 14%, transparent);
      color: var(--pg-accent, #6639ba); border: 1px solid color-mix(in srgb, var(--pg-accent, #6639ba) 40%, transparent); }
    .muted { color: var(--pg-muted, #888); }
    /* Pager */
    .pager { display: flex; align-items: center; gap: var(--pg-space-3, .75rem); flex-wrap: wrap;
      margin-top: var(--pg-space-2, .5rem); font-size: var(--pg-text-sm, .8rem); color: var(--pg-muted, #888); }
    .pager .psize { display: inline-flex; align-items: center; gap: 4px; }
    .pager select, .pager .nav button { font: inherit; background: var(--pg-bg, #fff); color: var(--pg-fg, #1f2328);
      border: 1px solid var(--pg-border, #d0d7de); border-radius: var(--pg-radius-sm, 4px); }
    .pager select { padding: 1px 4px; }
    .pager .info { margin-left: auto; }
    .pager .nav { display: inline-flex; gap: 2px; }
    .pager .nav button { padding: 1px 9px; cursor: pointer; }
    .pager .nav button:disabled { opacity: .4; cursor: default; }
  `;

  // Emit the picked field(s) so the app can drop them into the Structured query.
  #pick(detail) {
    this.dispatchEvent(new CustomEvent('pick', { detail, bubbles: true, composed: true }));
  }

  #obj(x) { return `${x.object_type}:${x.object_id}`; }
  #subj(x) { return `${x.user_type}:${x.user_id}${x.user_relation ? '#' + x.user_relation : ''}`; }

  #rows() {
    const q = this.filter.trim().toLowerCase();
    const all = this.tuples || [];
    if (!q) return all;
    return all.filter((x) => {
      const rel = String(x.relation).toLowerCase();
      return this.#obj(x).toLowerCase().startsWith(q)
        || this.#subj(x).toLowerCase().startsWith(q)
        || rel.startsWith(q) || ('#' + rel).startsWith(q);
    });
  }

  // Drag a column border: adjust widths[i] live.
  #startResize(e, i) {
    e.preventDefault(); e.stopPropagation();
    e.target.classList.add('active');
    const startX = e.clientX, startW = this.widths[i];
    const move = (ev) => {
      const next = [...this.widths];
      next[i] = Math.max(56, startW + ev.clientX - startX);
      this.widths = next;
    };
    const up = () => {
      window.removeEventListener('mousemove', move);
      window.removeEventListener('mouseup', up);
      document.body.style.userSelect = '';
      e.target.classList.remove('active');
    };
    window.addEventListener('mousemove', move);
    window.addEventListener('mouseup', up);
    document.body.style.userSelect = 'none';
  }

  render() {
    const rows = this.#rows();
    const total = rows.length;
    const size = this.pageSize;
    const maxPage = Math.max(0, Math.ceil(total / size) - 1);
    const page = Math.min(this.page, maxPage);
    const start = page * size;
    const end = Math.min(start + size, total);
    const paged = rows.slice(start, end);
    const cols = ['User', 'Relation', 'Object', 'Condition'];
    return html`
      <input class="search" .value=${this.filter}
        @input=${(e) => { this.filter = e.target.value; this.page = 0; }}
        placeholder="filter by prefix — internal_user:eva   #can_read   document:">
      <div class="scroll">
        ${total
          ? html`<table style=${this.widths ? 'table-layout:fixed;width:max-content' : 'table-layout:auto;width:max-content'}>
              ${this.widths ? html`<colgroup>
                ${this.widths.map((w) => html`<col style="width:${w}px">`)}
              </colgroup>` : ''}
              <thead><tr>${cols.map((c, i) => html`<th>${c}${i < 3
                ? html`<span class="resizer" @mousedown=${(e) => this.#startResize(e, i)}></span>` : ''}</th>`)}</tr></thead>
              <tbody>${paged.map((x) => html`<tr>
                <td class="pick" title="use as query subject"
                  @click=${() => this.#pick({ user: { type: x.user_type, id: x.user_id } })}>${x.user_type}:${x.user_id}${x.user_relation ? html`#${x.user_relation}` : ''}</td>
                <td class="rel pick" title="use as query relation"
                  @click=${() => this.#pick({ relation: x.relation })}>#${x.relation}</td>
                <td class="pick" title="use as query object"
                  @click=${() => this.#pick({ object: { type: x.object_type, id: x.object_id } })}>${x.object_type}:${x.object_id}</td>
                <td>${x.condition_name
                  ? html`<span class="cond" title=${'stored: ' + (x.condition_context || '(none)')}
                      @click=${() => this.#pick({ condition: x.condition_name })}>⚖ ${x.condition_name}</span>`
                  : ' '}</td>
              </tr>`)}</tbody></table>`
          : html`<p class="muted">(no matching tuples)</p>`}
      </div>
      <div class="pager">
        <label class="psize">rows
          <select @change=${(e) => { this.pageSize = +e.target.value; this.page = 0; }}>
            ${[25, 50, 100].map((n) => html`<option value=${n} ?selected=${this.pageSize === n}>${n}</option>`)}
          </select>
        </label>
        <span class="info">${total ? `${start + 1}–${end} of ${total}` : '0 tuples'}</span>
        <span class="nav">
          <button ?disabled=${page <= 0} @click=${() => (this.page = page - 1)} title="previous page">‹</button>
          <button ?disabled=${end >= total} @click=${() => (this.page = page + 1)} title="next page">›</button>
        </span>
      </div>
    `;
  }
}
customElements.define('pg-tuples', PgTuples);
