import { html, nothing } from 'lit';
import { help } from '../base.js';
import { t } from '../i18n.js';
import { fmtTime, fmtRelative } from '../util.js';

// Shared pieces of the two Operations screens (a store's, the platform's).

export function fmtBytes(n) {
  if (n == null) return '';
  const units = ['B', 'kB', 'MB', 'GB', 'TB'];
  let i = 0;
  let v = Number(n);
  while (v >= 1024 && i < units.length - 1) ((v /= 1024), i++);
  return `${v < 10 && i > 0 ? v.toFixed(1) : Math.round(v)} ${units[i]}`;
}

// "events_2026_10" → "2026-10"; the default partition has no month.
export function partitionMonth(p) {
  const m = /_(\d{4})_(\d{2})$/.exec(p.name);
  return m ? `${m[1]}-${m[2]}` : null;
}

// Months of coverage ahead of now for one log, from its partition names.
export function monthsAhead(parts) {
  const now = new Date();
  const cur = now.getUTCFullYear() * 12 + now.getUTCMonth();
  let max = null;
  for (const p of parts) {
    const m = partitionMonth(p);
    if (!m) continue;
    const [y, mo] = m.split('-').map(Number);
    const idx = y * 12 + (mo - 1);
    if (max === null || idx > max) max = idx;
  }
  return max === null ? null : max - cur;
}

// The partitions of both logs, grouped, with the coverage ahead.
export function partitionsCard(parts, { actions, help: helpText } = {}) {
  const groups = [
    [
      'tuples_audit',
      'Audit trail',
      'authz.tuples_audit: every relationship change, monthly partitions; ensure_audit_partitions creates them ahead of time.',
    ],
    [
      'events',
      'Action log',
      'authz.events: what principals did, monthly partitions; ensure_event_partitions creates them ahead, drop_event_partitions_before is the fleet-wide retention.',
    ],
  ];
  return html`<section class="card" data-testid="ops-partitions">
    <h3>
      ${t('Partitions')}
      ${help(helpText ?? 'Both logs are partitioned by month. Rows for a month without its own partition land in the default partition, which is a fail-safe, not a plan: keep at least one month ahead.')}
    </h3>
    ${actions ?? nothing}
    <div class="ops-grid">
      ${groups.map(([parent, label, tip]) => {
        const mine = parts.filter((p) => p.parent === parent);
        const ahead = monthsAhead(mine);
        return html`<div>
          <h4>
            ${t(label)} ${help(tip)}
            ${
              ahead === null
                ? html`<span class="badge warn">${t('no monthly partitions')}</span>`
                : ahead >= 1
                  ? html`<span class="badge ok">${t('{n} month(s) ahead', { n: ahead })}</span>`
                  : html`<span class="badge warn">${t('nothing ahead')}</span>`
            }
          </h4>
          <div class="table-wrap">
            <table class="compact">
              <thead>
                <tr>
                  <th>${t('Partition')}</th>
                  <th>${t('Month')}</th>
                  <th class="num">${t('Size')}</th>
                </tr>
              </thead>
              <tbody>
                ${mine.map(
                  (p) =>
                    html`<tr data-testid=${`ops-partition-${p.name}`}>
                      <td class="mono">${p.name}</td>
                      <td>
                        ${p.default ? html`<span class="badge muted">${t('default')}</span>` : partitionMonth(p)}
                      </td>
                      <td class="num muted">${fmtBytes(p.bytes)}</td>
                    </tr>`,
                )}
              </tbody>
            </table>
          </div>
        </div>`;
      })}
    </div>
  </section>`;
}

// One readiness row as a row of facts (store screen: without the store name).
export function readinessFacts(r) {
  if (!r) return nothing;
  return html`<dl class="kv">
    <dt>${t('Gates')}</dt>
    <dd>
      ${r.gates}
      <span class="muted"
        >(${r.gates_enforce} ${t('enforce')}, ${r.gates_shadow} ${t('shadow')}, ${r.gates_off}
        ${t('off')})</span
      >
    </dd>
    <dt>
      ${t('Longest window')}
      ${help('The longest look-back of any gate clause (a calendar day counts as 25 h, a month as 31 d). Retention must keep at least this much history.')}
    </dt>
    <dd class="mono">${r.max_gate_window ?? html`<span class="muted">${t('none')}</span>`}</dd>
    <dt>
      ${t('History since')}
      ${help('The earliest retained partition, or the oldest event: how far back the gates can see.')}
    </dt>
    <dd>
      ${r.history_since ? html`<span title=${r.history_since}>${fmtTime(r.history_since)}</span>` : html`<span class="muted">${t('no events')}</span>`}
    </dd>
    <dt>${t('Covers the gates')}</dt>
    <dd>
      ${
        r.gates === 0
          ? html`<span class="muted">${t('no gates')}</span>`
          : r.history_covers_gates
            ? html`<span class="badge ok">${t('yes')}</span>`
            : html`<span class="badge deny">${t('no')}</span>
                <span class="muted">${t('short by')} <span class="mono">${r.history_deficit}</span></span>`
      }
    </dd>
    <dt>${t('Last recorded')}</dt>
    <dd>
      ${r.last_recorded_at ? html`<span title=${r.last_recorded_at}>${fmtRelative(r.last_recorded_at)}</span>` : html`<span class="muted">${t('never')}</span>`}
    </dd>
    <dt>${t('Events, last hour')}</dt>
    <dd>
      ${r.events_1h}
      ${r.max_recording_delay_1h ? html`<span class="muted">· ${t('max recording delay')} <span class="mono">${r.max_recording_delay_1h}</span></span>` : nothing}
    </dd>
    <dt>${t('Recorders, 24 h')} ${help('The database roles that recorded events in the last day.')}</dt>
    <dd class="mono">
      ${(r.recorders_24h ?? []).join(', ') || html`<span class="muted">${t('none')}</span>`}
    </dd>
  </dl>`;
}
