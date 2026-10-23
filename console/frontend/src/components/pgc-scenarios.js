import { html, nothing } from 'lit';
import { PgcElement, help, errorBox } from '../base.js';
import { api } from '../api.js';
import { t } from '../i18n.js';
import { run, copyText, fmtTime, fmtRelative } from '../util.js';

const seedLimit = 500;

// Saved scenarios: the store's tests.authz.yaml, edited here, run through
// the engine in an ephemeral store (pgauthzadm's runner, the one behind
// `pgauthzctl model test`) against the store's current model, saved for the
// team, exported for the CLI and CI. The parent (the Test tab) owns the
// YAML text so a result there can be appended as a case; this component
// loads it once, edits it and reports every change back (yaml-change).
export class PgcScenarios extends PgcElement {
  static properties = {
    store: { type: String },
    caps: { attribute: false },
    yaml: { attribute: false }, // null until loaded
    info: { state: true }, // saved: updated_at, updated_by, cases, can_edit
    savedYaml: { state: true },
    report: { state: true },
    exported: { state: true },
    seeded: { state: true },
    busy: { state: true },
    error: { state: true },
    copied: { state: true },
  };

  constructor() {
    super();
    this.store = '';
    this.caps = null;
    this.yaml = null;
    this.info = null;
    this.savedYaml = '';
    this.report = null;
    this.exported = null;
    this.seeded = null;
    this.busy = false;
    this.error = '';
    this.copied = '';
  }

  willUpdate(changed) {
    if (changed.has('store') && this.store) void this._load();
  }

  _emit(yaml) {
    this.dispatchEvent(new CustomEvent('yaml-change', { detail: yaml, bubbles: true, composed: true }));
  }

  async _load() {
    const d = await run(this, () => api.scenarios(this.store));
    if (!d) return;
    this.info = d;
    this.savedYaml = d.yaml;
    if (this.yaml === null) this._emit(d.yaml);
  }

  async _run() {
    this.report = null;
    const r = await run(this, () => api.scenariosRun(this.store, this.yaml ?? ''));
    if (r) this.report = r;
  }

  async _save() {
    const r = await run(this, () => api.scenariosSave(this.store, this.yaml ?? ''));
    if (r) await this._load();
  }

  async _export() {
    const r = await run(this, () => api.scenariosExport(this.store));
    if (r) this.exported = r;
  }

  // The store's tuples as fixture tuples: a scenario runs in an empty
  // ephemeral store, so the facts the checks rely on must be listed —
  // seeding from the live data is how the current state becomes a fixture.
  // Real data leaving the store is an EXPORT: the same gate (can_export)
  // and the same action-log record as Data → Export, capped at seedLimit
  // tuples (a fixture is a sample, not a dump).
  async _seed() {
    const d = await run(this, () => api.tuplesExportJSON(this.store));
    if (!d) return;
    const all = d.tuples ?? [];
    const subject = (x) => `${x.user_type}:${x.user_id}${x.user_relation ? '#' + x.user_relation : ''}`;
    const lines = ['tuples:'];
    for (const x of all.slice(0, seedLimit)) {
      lines.push(`  - user: ${yamlScalar(subject(x))}`);
      lines.push(`    relation: ${yamlScalar(x.relation)}`);
      lines.push(`    object: ${yamlScalar(x.object_type + ':' + x.object_id)}`);
      if (x.condition) lines.push(`    condition: ${yamlScalar(x.condition)}`);
      if (x.condition_context != null && x.condition_context !== 'null')
        lines.push(`    context: ${JSON.stringify(x.condition_context)}`);
      if (x.expires_at) lines.push(`    expires_at: ${yamlScalar(x.expires_at)}`);
    }
    this._emit(lines.join('\n') + '\n' + stripTuples(this.yaml ?? ''));
    this.seeded = { n: Math.min(all.length, seedLimit), total: all.length };
  }

  async _copy(key, text) {
    await copyText(text);
    this.copied = key;
    setTimeout(() => (this.copied = ''), 1500);
  }

  render() {
    const yaml = this.yaml ?? '';
    const dirty = yaml !== this.savedYaml;
    const canEdit = !!(this.info?.can_edit ?? this.caps?.can_edit_model);
    const rep = this.report;
    return html`<section class="card" data-testid="test-scenarios">
        <h3>
          ${t('Scenarios')}
          ${help("The store's saved checks as a tests.authz.yaml fixture — the format pgauthzctl model test runs (a superset of OpenFGA's store tests). Hermetic: every run creates an ephemeral store, rebuilds this store's CURRENT model in it, writes the fixture's tuples and decides the assertions there — nothing of this store's data takes part, list the tuples the checks need (Seed from the store's data). Recorded as you; the test policy applies (other subjects, enumeration, explain).")}
        </h3>
        <p class="help">
          ${t("Add a case from a result (Single check, Search), or write it here. Without a model line the fixture tests this store's current model; model: name@version tests a registry model.")}
        </p>
        <label class="field wide"
          ><span>${t('tests.authz.yaml')}</span
          ><textarea
            class="mono"
            rows="18"
            spellcheck="false"
            .value=${yaml}
            @input=${(e) => this._emit(e.target.value)}
            data-testid="test-scenarios-yaml"
          ></textarea>
        </label>
        <div class="actions">
          <button
            class="primary sm"
            ?disabled=${this.busy || !yaml.trim()}
            data-testid="test-scenarios-run"
            @click=${this._run}
          >
            ${t('Run')}
          </button>
          <button
            class="sm"
            ?disabled=${this.busy || !canEdit || !dirty}
            title=${canEdit ? '' : t('saving needs can_edit_model (author or owner)')}
            data-testid="test-scenarios-save"
            @click=${this._save}
          >
            ${t('Save')}
          </button>
          <button class="sm" ?disabled=${this.busy || !dirty} @click=${() => this._emit(this.savedYaml)}>
            ${t('Revert')}
          </button>
          ${
            this.caps?.can_export
              ? html`<button
                  class="sm"
                  ?disabled=${this.busy}
                  title=${t("Replaces the tuples: block with up to {n} of the store's tuples — an export (can_export), recorded like one.", { n: seedLimit })}
                  data-testid="test-scenarios-seed"
                  @click=${this._seed}
                >
                  ${t("Seed from the store's data")}
                </button>`
              : nothing
          }
          <button
            class="sm"
            ?disabled=${this.busy || !this.savedYaml}
            data-testid="test-scenarios-export"
            @click=${this._export}
          >
            ${t('Export for pgauthzctl')}
          </button>
          ${
            this.info?.updated_at
              ? html`<span class="help" data-testid="test-scenarios-info"
                  >${t('{n} assertion(s) saved by {by}', { n: this.info.cases, by: this.info.updated_by })}
                  <span title=${fmtTime(this.info.updated_at)}>· ${fmtRelative(this.info.updated_at)}</span
                  >${dirty ? html` · <b>${t('unsaved changes')}</b>` : nothing}</span
                >`
              : dirty
                ? html`<span class="help"><b>${t('unsaved changes')}</b></span>`
                : nothing
          }
          ${this.seeded ? html`<span class="help">${t('{n} of {total} tuples seeded', this.seeded)}</span>` : nothing}
        </div>
        ${this.error ? errorBox(this.error) : nothing}
      </section>
      ${
        rep
          ? html`<section class="card" data-testid="test-scenarios-results">
              <div class="toolbar">
                <span class="decision ${rep.failed ? 'deny' : 'allow'}" data-testid="test-scenarios-summary"
                  >${rep.failed ? '✘ ' + t('{f} of {n} failed', { f: rep.failed, n: rep.passed + rep.failed }) : '✔ ' + t('{n} passed', { n: rep.passed })}</span
                >
                <span class="help">${t('{ms} ms, in an ephemeral store', { ms: rep.duration_ms })}</span>
              </div>
              <ul class="plain">
                ${rep.results.map(
                  (r) =>
                    html`<li class=${r.failed ? 'deny' : ''}>
                      <span class="mono">${r.failed ? '✘' : '✔'} ${r.name}</span>
                      ${r.failed ? html`<span class="muted"> — ${r.detail}</span>` : nothing}
                    </li>`,
                )}
              </ul>
            </section>`
          : nothing
      }
      ${
        this.exported
          ? html`<section class="card" data-testid="test-scenarios-exported">
              <h3>
                ${t('For pgauthzctl')}
                ${help('Save the two files next to each other and run the command; --junit writes a report for CI. The DSL is display-only: conditions, gates and grant rules have no DSL form, so a fixture relying on them runs in the console or against the registry model.')}
              </h3>
              <p class="mono">${this.exported.command}</p>
              <div class="actions">
                <button class="sm" @click=${() => this._copy('yaml', this.exported.yaml)}>
                  ${this.copied === 'yaml' ? t('Copied') : t('Copy tests.authz.yaml')}
                </button>
                ${this.exported.model_fga ? html`<button class="sm" @click=${() => this._copy('fga', this.exported.model_fga)}>${this.copied === 'fga' ? t('Copied') : t('Copy model.fga')}</button>` : nothing}
                <button class="sm" @click=${() => (this.exported = null)}>${t('Close')}</button>
              </div>
              ${this.exported.model_fga ? html`<pre class="mono small">${this.exported.model_fga}</pre>` : nothing}
            </section>`
          : nothing
      }`;
  }
}
customElements.define('pgc-scenarios', PgcScenarios);

// A YAML plain scalar when safe, else double-quoted (JSON strings are valid YAML).
export function yamlScalar(s) {
  return /^[A-Za-z0-9_][A-Za-z0-9_:.#*@/-]*$/.test(s) &&
    !/^(true|false|null|yes|no|on|off|~)$/i.test(s) &&
    !/^[0-9.]+$/.test(s)
    ? s
    : JSON.stringify(s);
}

// Drops a top-level tuples: block from the fixture text (replaced on seeding).
function stripTuples(yaml) {
  return yaml.replace(/^tuples:\s*\n(?:(?:[ \t].*|\s*)\n?)*/m, '');
}

// Renders one check as a fixture case, appended under tests:.
export function checkCaseYAML({ subject, action, resource, decision, context }) {
  const lines = [
    `  - name: ${yamlScalar(`${subject} ${action} ${resource}`)}`,
    `    check:`,
    `      - user: ${yamlScalar(subject)}`,
    `        object: ${yamlScalar(resource)}`,
    `        assertions: { ${yamlScalar(action)}: ${decision ? 'true' : 'false'} }`,
  ];
  if (context && Object.keys(context).length) lines.push(`        context: ${JSON.stringify(context)}`);
  return lines.join('\n') + '\n';
}

// Renders a list_objects result as a fixture case.
export function listCaseYAML({ subject, action, type, ids, context }) {
  const lines = [
    `  - name: ${yamlScalar(`${subject} ${action} ${type} objects`)}`,
    `    list_objects:`,
    `      - user: ${yamlScalar(subject)}`,
    `        type: ${yamlScalar(type)}`,
    `        assertions: { ${yamlScalar(action)}: [${ids.map((id) => yamlScalar(`${type}:${id}`)).join(', ')}] }`,
  ];
  if (context && Object.keys(context).length) lines.push(`        context: ${JSON.stringify(context)}`);
  return lines.join('\n') + '\n';
}

// Appends a case to the fixture text, opening tests: when there is none.
export function appendCase(yaml, caseYaml) {
  const base = yaml ?? '';
  if (/^tests:\s*$/m.test(base)) {
    // tests: is a top-level key; append at the end when it is the last block,
    // otherwise right after it (a later top-level key would end the list)
    const after = base.slice(base.search(/^tests:\s*$/m));
    const next = after.slice(after.indexOf('\n') + 1).search(/^[A-Za-z_]/m);
    if (next < 0) return base.replace(/\n*$/, '\n') + caseYaml;
    const at = base.length - after.length + after.indexOf('\n') + 1 + next;
    return base.slice(0, at) + caseYaml + base.slice(at);
  }
  return base.replace(/\n*$/, base ? '\n' : '') + 'tests:\n' + caseYaml;
}
