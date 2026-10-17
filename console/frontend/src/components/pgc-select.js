import { html, nothing } from 'lit';
import { t } from '../i18n.js';

// Shared selection + confirmation for the tables that remove things (model
// parts, tuples, role assignments). A page component keeps `selected` (a Set
// of row keys) and `confirming`; this module renders the checkbox cells, the
// "Remove selected" bar and the inline confirmation that lists what goes —
// nothing is removed on a single click, and one confirmation removes one or
// many in one transaction.

export function selectionCell(el, key) {
  return html`<td class="sel">
    <input
      type="checkbox"
      aria-label=${t('select')}
      .checked=${el.selected.has(key)}
      @change=${() => toggle(el, key)}
    />
  </td>`;
}

export function selectAllCell(el, keys) {
  const all = keys.length > 0 && keys.every((k) => el.selected.has(k));
  return html`<th class="sel">
    <input
      type="checkbox"
      aria-label=${t('select all')}
      .checked=${all}
      @change=${(e) => {
        el.selected = new Set(e.target.checked ? keys : []);
        el.confirming = false;
      }}
    />
  </th>`;
}

export function toggle(el, key) {
  const next = new Set(el.selected);
  if (next.has(key)) next.delete(key);
  else next.add(key);
  el.selected = next;
  el.confirming = false;
}

export function clearSelection(el) {
  el.selected = new Set();
  el.confirming = false;
}

// The bar above a table: how many are selected, the remove button, and when
// confirming, the list of what will be removed plus the warning the caller
// supplies. `one`/`many` are the English nouns ('tuple', 'tuples').
export function removeBar(el, { one, many, describe, warning, onConfirm }) {
  const n = el.selected.size;
  if (!n) return nothing;
  return html`<div class="remove-bar ${el.confirming ? 'confirming' : ''}">
    <div class="actions">
      <span>${t('{n} {what} selected', { n, what: t(n === 1 ? one : many) })}</span>
      ${el.confirming ? nothing : html`<button class="danger sm" @click=${() => (el.confirming = true)}>${t('Remove selected…')}</button>`}
      <button class="sm" @click=${() => clearSelection(el)}>${t('Clear')}</button>
    </div>
    ${
      el.confirming
        ? html`<div class="confirm">
            <p>
              <b>${t('Remove {n} {what}?', { n, what: t(n === 1 ? one : many) })}</b>
              ${warning ? t(warning) : ''} ${t('This runs as you, in one transaction, and is recorded.')}
            </p>
            <ul class="mono">
              ${[...el.selected].map((k) => html`<li>${describe(k)}</li>`)}
            </ul>
            <div class="actions">
              <button class="danger" ?disabled=${el.busy} @click=${onConfirm}>${t('Yes, remove')}</button>
              <button @click=${() => (el.confirming = false)}>${t('Keep')}</button>
            </div>
          </div>`
        : nothing
    }
  </div>`;
}
