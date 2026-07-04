import { LitElement, html, css } from 'lit';

// Generic data grid — config-driven columns, resizable, searchable, paginated,
// with a per-row copy button. Used by pg-tuples and pg-conditions.
//
//   columns: [{
//     header,                 // column title
//     get?(row)  -> string,   // text cell (used for measuring + copy)
//     render?(row) -> html,   // rich cell (falls back to get())
//     cellClass?,             // class on the <td> (e.g. 'rel', 'cond', 'expr')
//     onClick?(row),          // makes the cell a clickable "pick"
//     title?,                 // cell tooltip
//   }]
//   rows:    array of row objects
//   filter?: (row, queryLower) -> boolean   // shows a search box when set
//   rowText?:(row) -> string                 // shows a copy-row column when set
export class PgGrid extends LitElement {
  static properties = {
    columns: { attribute: false }, rows: { attribute: false },
    filter: { attribute: false }, rowText: { attribute: false },
    searchPlaceholder: { type: String },
    query: { state: true }, widths: { state: true },
    page: { state: true }, pageSize: { state: true }, copiedRow: { state: true },
  };

  constructor() {
    super();
    this.columns = []; this.rows = [];
    this.filter = null; this.rowText = null; this.searchPlaceholder = 'filter…';
    this.query = ''; this.widths = null; this.page = 0; this.pageSize = 25; this.copiedRow = null;
  }

  // Re-fit columns + reset paging when the data changes. NOT on `columns` — the
  // parent rebuilds that array each render, which would thrash the resized widths.
  willUpdate(changed) {
    if (changed.has('rows')) { this.widths = null; this.page = 0; }
  }

  // Capture content-fit widths once, then columns become resizable from there.
  updated() {
    if (this.widths) return;
    const ths = this.renderRoot.querySelectorAll('thead th.col');
    if (ths.length === this.columns.length && ths.length) {
      this.widths = [...ths].map((th) => Math.max(56, Math.min(340, th.offsetWidth)));
    }
  }

  static styles = css`
    :host { display: flex; flex-direction: column; min-height: 0; }
    .search { box-sizing: border-box; width: 100%; padding: var(--pg-space-2, .5rem);
      margin-bottom: var(--pg-space-2, .5rem); border: 1px solid var(--pg-border, #d0d7de);
      border-radius: var(--pg-radius-md, 6px); background: var(--pg-bg, #fff); color: var(--pg-fg, #1f2328); font: inherit; }
    .scroll { flex: 1 1 auto; min-height: 120px; overflow: auto;
      border: 1px solid var(--pg-border, #d0d7de); border-radius: var(--pg-radius-md, 6px); padding: var(--pg-space-2, .5rem); }
    table { border-collapse: collapse; empty-cells: show;
      font: var(--pg-text-code, 12px)/1.5 var(--pg-font-mono, ui-monospace, monospace); }
    th { text-align: left; font-weight: 600; color: var(--pg-muted, #888); white-space: nowrap;
      padding: var(--pg-space-1, .25rem) var(--pg-space-2, .5rem); position: sticky; top: 0; z-index: 1;
      background: var(--pg-bg, #fff); border-bottom: 1px solid var(--pg-border, #d0d7de); }
    th, td { border-right: 1px solid var(--pg-border, #d0d7de); border-bottom: 1px solid var(--pg-border, #d0d7de); }
    td { padding: var(--pg-space-1, .25rem) var(--pg-space-2, .5rem); vertical-align: top;
      overflow-wrap: anywhere; word-break: break-word; }
    tr:hover td { background: color-mix(in srgb, var(--pg-primary, #0969da) 6%, transparent); }
    /* Draggable column border */
    th.col { position: relative; }
    .resizer { position: absolute; top: 0; right: 0; width: 9px; height: 100%; cursor: col-resize;
      user-select: none; touch-action: none; }
    .resizer::after { content: ""; position: absolute; right: 3px; top: 3px; bottom: 3px; width: 2px;
      border-radius: 2px; background: transparent; }
    .resizer:hover::after, .resizer.active::after { background: var(--pg-primary, #0969da); }
    /* Shared cell vocabulary (referenced via column.cellClass) */
    .pick { cursor: pointer; }
    .pick:hover { text-decoration: underline; text-underline-offset: 2px; }
    .rel { color: var(--pg-reason-fg, #6639ba); }
    .cond { display: inline-flex; align-items: center; gap: .2rem; white-space: nowrap; cursor: pointer;
      padding: 0 6px; border-radius: 999px; font-size: .68rem;
      background: color-mix(in srgb, var(--pg-accent, #6639ba) 14%, transparent);
      color: var(--pg-accent, #6639ba); border: 1px solid color-mix(in srgb, var(--pg-accent, #6639ba) 40%, transparent); }
    .lang { font-size: .68rem; text-transform: uppercase; letter-spacing: .03em; padding: 1px 6px;
      border-radius: 999px; background: var(--pg-surface, #eee); color: var(--pg-muted, #666);
      border: 1px solid var(--pg-border, #d0d7de); }
    .name { font-weight: 600; color: var(--pg-accent, #6639ba); }
    .expr { display: block; max-height: 7em; overflow: auto; white-space: pre; } /* keep formatting; scroll tall exprs */
    .muted { color: var(--pg-muted, #888); }
    /* Per-row copy button */
    .copycell { text-align: center; padding: 0 2px; }
    .rowcopy { font: inherit; line-height: 1.5; padding: 0 5px; cursor: pointer; color: var(--pg-muted, #888);
      background: var(--pg-bg, #fff); border: 1px solid var(--pg-border, #d0d7de); border-radius: var(--pg-radius-sm, 4px); }
    .rowcopy:hover { border-color: var(--pg-primary, #0969da); color: var(--pg-primary, #0969da); }
    /* Trailing "more rows" indicator: an in-flow row after the last visible
       row, so a page that happens to fit the viewport doesn't read as "that's
       all" (the 1–25 of 42 pager info is easy to overlook). */
    tr.more td { text-align: center; cursor: pointer; font-style: italic;
      color: var(--pg-muted, #6e7781); background: var(--pg-surface, #f6f8fa);
      border-top: 1px dashed var(--pg-border, #d0d7de); }
    tr.more:hover td { color: var(--pg-fg, #1f2328); background: var(--pg-hover, #eaeef2); }

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

  #filtered() {
    const q = this.query.trim().toLowerCase();
    if (!q || !this.filter) return this.rows || [];
    return (this.rows || []).filter((r) => this.filter(r, q));
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

  async #copyRow(r) {
    try {
      await navigator.clipboard.writeText(this.rowText(r));
      this.copiedRow = r;
      setTimeout(() => (this.copiedRow = null), 1000);
    } catch { /* clipboard unavailable */ }
  }

  #cell(col, r) {
    const content = col.render ? col.render(r) : (col.get ? col.get(r) : '');
    const cls = [col.cellClass, col.onClick ? 'pick' : ''].filter(Boolean).join(' ');
    return html`<td class=${cls} title=${col.title ?? ''}
      @click=${() => col.onClick && col.onClick(r)}>${content}</td>`;
  }

  render() {
    const rows = this.#filtered();
    const total = rows.length;
    const size = this.pageSize;
    const maxPage = Math.max(0, Math.ceil(total / size) - 1);
    const page = Math.min(this.page, maxPage);
    const start = page * size;
    const end = Math.min(start + size, total);
    const paged = rows.slice(start, end);
    const w = this.widths;
    return html`
      ${this.filter ? html`<input class="search" .value=${this.query}
        @input=${(e) => { this.query = e.target.value; this.page = 0; }}
        placeholder=${this.searchPlaceholder}>` : ''}
      <div class="scroll">
        ${total
          ? html`<table style=${w ? 'table-layout:fixed;width:max-content' : 'table-layout:auto;width:max-content'}>
              ${w ? html`<colgroup>
                ${w.map((cw) => html`<col style="width:${cw}px">`)}
                ${this.rowText ? html`<col style="width:34px">` : ''}
              </colgroup>` : ''}
              <thead><tr>
                ${this.columns.map((col, i) => html`<th class="col">${col.header}<span class="resizer"
                  @mousedown=${(e) => this.#startResize(e, i)}></span></th>`)}
                ${this.rowText ? html`<th class="copyhead" title="copy row"></th>` : ''}
              </tr></thead>
              <tbody>${paged.map((r) => html`<tr>
                ${this.columns.map((col) => this.#cell(col, r))}
                ${this.rowText ? html`<td class="copycell"><button class="rowcopy" title="copy row (tab-separated)"
                  @click=${() => this.#copyRow(r)}>${this.copiedRow === r ? '✓' : '⧉'}</button></td>` : ''}
              </tr>`)}
              ${end < total ? html`<tr class="more" data-testid="grid-more"
                @click=${() => (this.page = page + 1)}>
                <td colspan=${this.columns.length + (this.rowText ? 1 : 0)}
                  title="show the next page">⋯ ${total - end} more row${total - end === 1 ? '' : 's'} — click for the next page ›</td>
              </tr>` : ''}</tbody></table>`
          : html`<p class="muted">(no matching rows)</p>`}
      </div>
      <div class="pager">
        <label class="psize">rows
          <select @change=${(e) => { this.pageSize = +e.target.value; this.page = 0; }}>
            ${[25, 50, 100].map((n) => html`<option value=${n} ?selected=${this.pageSize === n}>${n}</option>`)}
          </select>
        </label>
        <span class="info">${total ? `${start + 1}–${end} of ${total}` : '0 rows'}</span>
        <span class="nav">
          <button ?disabled=${page <= 0} @click=${() => (this.page = page - 1)} title="previous page">‹</button>
          <button ?disabled=${end >= total} @click=${() => (this.page = page + 1)} title="next page">›</button>
        </span>
      </div>
    `;
  }
}
customElements.define('pg-grid', PgGrid);
