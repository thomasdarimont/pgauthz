import { LitElement, html } from 'lit';
import { t } from './i18n.js';

// Base class of the page components: light DOM (styled by styles.css) and a
// re-render when the language changes.
export class PgcElement extends LitElement {
  createRenderRoot() {
    return this;
  }
  connectedCallback() {
    super.connectedCallback();
    this._onLang = () => this.requestUpdate();
    window.addEventListener('pgc-lang', this._onLang);
  }
  disconnectedCallback() {
    window.removeEventListener('pgc-lang', this._onLang);
    super.disconnectedCallback();
  }
}

// The page-level error box: what went wrong, said as an error so it is not
// mistaken for a notice. Field-level mistakes (a JSON syntax error) are
// reported next to their field instead; this is for what the server said.
export function errorBox(text) {
  return html`<p class="error" role="alert"><b>${t('Error')}:</b> ${text}</p>`;
}

// The loading state of a page or card before its data arrived: a skeleton
// in the shape of what will appear (a heading line and table rows), so the
// layout does not jump when the content lands. Announced to assistive
// technology as busy; the shimmer stops under prefers-reduced-motion.
export function loading(rows = 5) {
  return html`<div class="skeleton" role="status" aria-busy="true" aria-label=${t('Loading…')}>
    <div class="sk-line sk-title"></div>
    ${Array.from({ length: rows }, () => html`<div class="sk-row"><span class="sk-line"></span><span class="sk-line"></span><span class="sk-line"></span></div>`)}
  </div>`;
}

// A (?) that explains a column or section on hover and focus. `text` is
// English, translated like everything else.
export function help(text) {
  const s = t(text);
  return html`<span class="help-icon" tabindex="0" role="note" data-tip=${s} aria-label=${s}>?</span>`;
}

// Tooltips for the (?) icons: one fixed element shown 500 ms after the
// pointer rests on an icon (or the icon takes focus), placed below it and
// kept inside the viewport. Native title tooltips are not used: their delay
// is the browser's (about a second) and cannot be changed.
const TIP_DELAY = 500;
let tipEl = null;
let tipTimer = 0;
let tipFor = null;
function tipElement() {
  if (!tipEl) {
    tipEl = document.createElement('div');
    tipEl.className = 'pgc-tip';
    tipEl.setAttribute('role', 'tooltip');
    tipEl.hidden = true;
    document.body.appendChild(tipEl);
  }
  return tipEl;
}
function showTip(icon) {
  const el = tipElement();
  el.textContent = icon.dataset.tip ?? '';
  el.hidden = false;
  const r = icon.getBoundingClientRect();
  const margin = 8;
  el.style.left = '0px';
  el.style.top = '0px';
  const w = el.offsetWidth;
  const h = el.offsetHeight;
  let left = r.left + r.width / 2 - w / 2;
  left = Math.max(margin, Math.min(left, window.innerWidth - w - margin));
  let top = r.bottom + 6;
  if (top + h > window.innerHeight - margin) top = r.top - h - 6;
  el.style.left = `${left}px`;
  el.style.top = `${top}px`;
  tipFor = icon;
}
function hideTip() {
  clearTimeout(tipTimer);
  tipTimer = 0;
  tipFor = null;
  if (tipEl) tipEl.hidden = true;
}
function armTip(icon) {
  if (tipFor === icon) return;
  hideTip();
  tipTimer = setTimeout(() => showTip(icon), TIP_DELAY);
}
document.addEventListener('mouseover', (e) => {
  const icon = e.target.closest?.('.help-icon[data-tip]');
  if (icon) armTip(icon);
  else if (!e.target.closest?.('.pgc-tip')) hideTip();
});
document.addEventListener('focusin', (e) => {
  const icon = e.target.closest?.('.help-icon[data-tip]');
  if (icon) armTip(icon);
});
document.addEventListener('focusout', (e) => {
  if (e.target.closest?.('.help-icon[data-tip]')) hideTip();
});
document.addEventListener('keydown', (e) => e.key === 'Escape' && hideTip());
window.addEventListener('scroll', hideTip, true);

// Resizable table columns, for every table in the console: drag the right
// edge of a header cell. Widths live on the <th> elements, which Lit keeps
// across re-renders of the same table, so a resize survives a refresh of
// the rows. Double-click the edge to reset the column.
const RESIZE_EDGE = 10;
// The header cell whose right edge is under the pointer: the cell itself
// near its right edge, or the previous cell when the pointer is just inside
// the left edge of the next one — so every column boundary is a handle.
function headerEdge(e) {
  const th = e.target.closest?.('th');
  if (!th || !th.closest('table')) return null;
  const r = th.getBoundingClientRect();
  if (e.clientX >= r.right - RESIZE_EDGE && e.clientX <= r.right + 1) return th;
  const prev = th.previousElementSibling;
  if (prev?.tagName === 'TH' && e.clientX - r.left <= RESIZE_EDGE) return prev;
  return null;
}
document.addEventListener('pointermove', (e) => {
  if (document.body.classList.contains('col-resizing')) return;
  const th = headerEdge(e);
  for (const x of document.querySelectorAll('th.col-edge')) if (x !== th) x.classList.remove('col-edge');
  th?.classList.add('col-edge');
});
let justResized = false; // a drag just ended: swallow the click it produces
document.addEventListener('pointerdown', (e) => {
  const th = headerEdge(e);
  if (!th || e.button !== 0) return;
  e.preventDefault();
  const table = th.closest('table');
  const startX = e.clientX;
  const startW = th.getBoundingClientRect().width;
  table.style.tableLayout = 'fixed';
  for (const h of table.querySelectorAll('thead th'))
    if (!h.style.width) h.style.width = h.getBoundingClientRect().width + 'px';
  document.body.classList.add('col-resizing');
  const move = (ev) => {
    th.style.width = Math.max(40, startW + ev.clientX - startX) + 'px';
    justResized = true;
  };
  const up = () => {
    document.body.classList.remove('col-resizing');
    setTimeout(() => (justResized = false), 0);
    window.removeEventListener('pointermove', move);
    window.removeEventListener('pointerup', up);
  };
  window.addEventListener('pointermove', move);
  window.addEventListener('pointerup', up);
});
document.addEventListener('dblclick', (e) => {
  const th = headerEdge(e);
  if (!th) return;
  const table = th.closest('table');
  for (const h of table.querySelectorAll('thead th')) h.style.width = '';
  table.style.tableLayout = '';
});
// The click at the end of a drag is not a sort — but a plain click on a
// header edge (or a synthetic click with no coordinates) still is.
document.addEventListener('click', (e) => justResized && e.stopPropagation(), true);
