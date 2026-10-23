import { html, nothing } from 'lit';
import { PgcElement, help, errorBox } from '../base.js';
import { api } from '../api.js';
import { t } from '../i18n.js';
import { run, copyText, fmtTime, fmtRelative } from '../util.js';
import { highlightYAML } from '../highlight.js';
import { PgcExplainTree } from './pgc-explain-tree.js';
import { explainOptions } from './pgc-explain-options.js';

const seedLimit = 500;
const historyLimit = 100; // runs remembered per session (client side)

// Saved scenarios: the store's tests.authz.yaml, run through the engine in
// an ephemeral store (pgauthzadm's runner, the one behind `pgauthzctl model
// test`) against the store's current model, saved for the team, exported
// for the CLI and CI. Two views of the same text:
//   Test harness  — the parsed fixture as a form: the tuples as a table,
//                   every test as a collapsible block with its cases, the
//                   last run's outcome on each assertion; add, rename and
//                   remove tests, add and remove assertions and tuples, a
//                   description per test and a note per assertion (the
//                   reasoning, a requirement, a ticket). Every edit
//                   regenerates the YAML (comments do not survive a harness
//                   edit; the YAML view keeps them).
//   Edit as YAML  — one highlighted, line-numbered editor, validated as you
//                   type; paste a fixture, keep your comments.
// The parent (the Test tab) owns the YAML text so a result there can be
// appended as a case; this component loads it once, edits it and reports
// every change back (yaml-change).
export class PgcScenarios extends PgcElement {
  static properties = {
    store: { type: String },
    caps: { attribute: false },
    meta: { attribute: false }, // the store's subjects/objects/relations, for the harness's suggestions
    yaml: { attribute: false }, // null until loaded
    info: { state: true }, // saved: updated_at, updated_by, cases, can_edit
    savedYaml: { state: true },
    report: { state: true }, // the run shown (the latest, or one picked from the history)
    history: { state: true }, // this session's runs, newest first (client side only)
    runs: { state: true }, // how many runs this session: the result header numbers them
    picked: { state: true }, // {line} (YAML view) or {test} (harness): what a clicked result points at
    check: { state: true }, // the draft's validation: {ok, cases, tests, fixture} or {ok: false, error, line}
    view: { type: String }, // 'yaml' | 'harness' — from the URL (stores/<s>/test/scenarios/<view>), set by the Test tab
    folded: { state: true }, // collapsed harness blocks: a Set of 'tuples' and test indices
    draft: { state: true }, // the harness's add forms: {tuple: {...}, [testIndex]: {...}}
    adding: { state: true }, // which add rows are open: a Set of 'tuple' and test indices
    noting: { state: true }, // the assertion whose note is being edited: 'test/case/relation'
    explained: { state: true }, // {result, tree, redacted}: one assertion explained inside the fixture
    explainOpts: { state: true }, // {successfulOnly, redact}: the explain options, as on the Single check view
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
    this.meta = null;
    this.yaml = null;
    this.info = null;
    this.savedYaml = '';
    this.report = null;
    this.history = [];
    this.runs = 0;
    this.picked = null;
    this.check = null;
    this.view = 'harness';
    this.folded = new Set();
    this.draft = {};
    this.adding = new Set();
    this.noting = '';
    this.explained = null;
    this.explainOpts = { successfulOnly: false, redact: false };
    this.exported = null;
    this.seeded = null;
    this.busy = false;
    this.error = '';
    this.copied = '';
  }

  willUpdate(changed) {
    if (changed.has('store') && this.store) void this._load();
    if (changed.has('yaml')) this._validateSoon();
  }

  // The draft through the runner's own parser, debounced: the same error
  // Run or Save would raise, shown while typing with the YAML parser's line
  // marked; when it parses, the fixture the harness renders.
  _validateSoon() {
    clearTimeout(this._validateTimer);
    const yaml = this.yaml ?? '';
    if (!yaml.trim()) {
      this.check = null;
      return;
    }
    this._validateTimer = setTimeout(async () => {
      try {
        const c = await api.scenariosValidate(this.store, yaml);
        if ((this.yaml ?? '') === yaml) {
          this.check = c; // still the draft that was checked
          this._foldInitially(c);
        }
      } catch {
        /* the next Run or Save reports it */
      }
    }, 350);
  }

  _emit(yaml) {
    this.dispatchEvent(new CustomEvent('yaml-change', { detail: yaml, bubbles: true, composed: true }));
  }

  // A harness edit: the changed fixture becomes the YAML (regenerated), and
  // the harness keeps rendering the new structure while the server parses
  // it again.
  _apply(fixture) {
    this.picked = null;
    this.check = {
      ...(this.check ?? { ok: true }),
      ok: true,
      fixture,
      cases: countCases(fixture),
      tests: fixture.tests?.length ?? 0,
    };
    this._emit(fixtureYAML(fixture));
  }

  _fixture() {
    return this.check?.ok ? structuredClone(this.check.fixture ?? {}) : null;
  }

  async _load() {
    const d = await run(this, () => api.scenarios(this.store));
    if (!d) return;
    this.info = d;
    this.savedYaml = d.yaml;
    if (this.yaml === null) this._emit(d.yaml);
  }

  // Runs the whole fixture, or (only) the tests at these indices.
  async _run(only) {
    const indices = Array.isArray(only) ? only : undefined;
    this.report = null;
    this.picked = null;
    const r = await run(this, () => api.scenariosRun(this.store, this.yaml ?? '', indices));
    if (r) {
      this.runs += 1;
      // the tests' names as they were when the run was made: a result points
      // back by index first, by name when the fixture changed since
      const tests = this.check?.fixture?.tests ?? [];
      const testNames = tests.map((tc) => tc.name);
      const testDescs = tests.map((tc) => tc.description ?? '');
      this.report = {
        ...r,
        run: this.runs,
        only: indices,
        at: new Date().toISOString(),
        testNames,
        testDescs,
      };
      this.history = [this.report, ...this.history].slice(0, historyLimit);
    }
  }

  // Clears the shown run (the history keeps it) or the whole session's history.
  _clearRuns(all) {
    this.report = null;
    this.picked = null;
    if (all) this.history = [];
  }

  // A result points back at its scenario (the result's test index): in the
  // harness the test's block is opened and scrolled to; in the YAML view
  // the "- name:" line is highlighted, scrolled to and selected.
  // Which test a result belongs to NOW: its index while the test at that
  // index still has the name it had at run time, else the test with that
  // name wherever it moved; -1 when it is gone.
  _testOf(r) {
    const tests = this.check?.ok ? (this.check.fixture?.tests ?? []) : [];
    const was = this.report?.testNames?.[r.test];
    if (was === undefined || tests[r.test]?.name === was) return r.test;
    const i = tests.findIndex((tc) => tc.name === was);
    return i;
  }

  async _reveal(r) {
    const test = this._testOf(r);
    if (test < 0) return; // the test is gone: nothing to show
    if (this.view === 'harness') {
      this._fold(test, false);
      this.picked = { test };
      await this.updateComplete;
      this.querySelector(`[data-testid="test-scenarios-harness-test-${test}"]`)?.scrollIntoView({
        block: 'center',
      });
      return;
    }
    // the assertion's own line when it still exists (kind, user, relation,
    // object), else the line of the test that defined it
    const line = assertionLine(this.yaml ?? '', { ...r, test }) || scenarioLine(this.yaml ?? '', test);
    if (!line) return;
    this.picked = { line };
    await this.updateComplete;
    const ta = this.querySelector('[data-testid="test-scenarios-yaml"]');
    if (!ta) return;
    const lines = (this.yaml ?? '').split('\n');
    const start = lines.slice(0, line - 1).join('\n').length + (line > 1 ? 1 : 0);
    ta.focus({ preventScroll: true });
    ta.setSelectionRange(start, start + lines[line - 1].length);
    const lineHeight = parseFloat(getComputedStyle(ta).lineHeight) || 20;
    ta.scrollTop = Math.max(0, (line - 3) * lineHeight);
    ta.dispatchEvent(new Event('scroll'));
    ta.scrollIntoView({ block: 'nearest' });
  }

  // Navigates to a view: the URL is the state (and the history), the app's
  // router sets the view property back on this component.
  _goView(view) {
    const rel = `stores/${this.store}/test/scenarios/${view === 'yaml' ? 'edit-as-yaml' : 'harness'}`;
    this.dispatchEvent(new CustomEvent('navigate', { detail: rel, bubbles: true, composed: true }));
  }

  // This test's YAML: switch to the editor at its line.
  async _editTest(i) {
    this._goView('yaml');
    await new Promise((r) => requestAnimationFrame(r));
    await this.updateComplete;
    await this._reveal({ test: i });
  }

  // On entering (the first fixture that parses for this store) every test
  // starts collapsed: the list of names is the overview, a block opens on
  // demand. A test added in the harness opens itself; one appended from a
  // result (the last one, new since the previous parse) opens too.
  _foldInitially(c) {
    const tests = c?.ok ? (c.fixture?.tests ?? []) : [];
    if (!this._foldedFor || this._foldedFor !== this.store) {
      this._foldedFor = this.store;
      this._testCount = tests.length;
      this.folded = new Set(tests.map((_, i) => i));
      return;
    }
    if (tests.length === this._testCount + 1) this._fold(tests.length - 1, false);
    this._testCount = tests.length;
  }

  _fold(id, on) {
    const folded = new Set(this.folded);
    if (on) folded.add(id);
    else folded.delete(id);
    this.folded = folded;
  }

  // Every test folded or none — each stays its own block, so a single one
  // opens again after "collapse all".
  _foldAll(on) {
    const tests = this.check?.fixture?.tests ?? [];
    const folded = new Set(this.folded);
    tests.forEach((_, i) => (on ? folded.add(i) : folded.delete(i)));
    this.folded = folded;
  }

  // Tab indents instead of leaving the editor: four spaces at the caret, or
  // every selected line; Shift+Tab removes up to four leading spaces from
  // the line(s). Through insertText where the browser has it, so undo works.
  _editorKeys(e) {
    if (e.key !== 'Tab') return;
    e.preventDefault();
    const ta = e.target;
    const unit = '    ';
    const { selectionStart: a, selectionEnd: b, value } = ta;
    const replace = (from, to, text) => {
      ta.setSelectionRange(from, to);
      if (!document.execCommand?.('insertText', false, text)) {
        ta.setRangeText(text, from, to, 'end');
        ta.dispatchEvent(new Event('input', { bubbles: true }));
      }
    };
    const multiline = value.slice(a, b).includes('\n');
    if (!e.shiftKey && !multiline) {
      replace(a, b, unit);
      return;
    }
    // whole lines: from the start of the first selected line to the end of the last
    const from = value.lastIndexOf('\n', a - 1) + 1;
    let to = value.indexOf('\n', b);
    if (to < 0) to = value.length;
    const lines = value.slice(from, to).split('\n');
    const changed = lines.map((l) => (e.shiftKey ? l.replace(/^ {1,4}/, '') : l ? unit + l : l));
    replace(from, to, changed.join('\n'));
    ta.setSelectionRange(from, from + changed.join('\n').length);
  }

  _sync(e) {
    const pre = e.target.previousElementSibling;
    pre.scrollTop = e.target.scrollTop;
    pre.scrollLeft = e.target.scrollLeft;
    const track = e.target.parentElement.querySelector('.fx-play-track');
    if (track) track.style.transform = `translateY(${-e.target.scrollTop}px)`;
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

  // What a run decided against, as one line: the store, and the model —
  // registry name@version (with "drifted" when the live model differs from
  // it), or the fixture's registry ref, or the unmanaged live model — plus
  // the live model's checksum, the exact identity of what was tested.
  static provenance(rep) {
    const m = rep.model ?? {};
    const parts = [`store ${m.store ?? '?'}`];
    if (m.model_ref) parts.push(`model ${m.model_ref} (registry)`);
    else if (m.model_name)
      parts.push(`model ${m.model_name}@${m.model_version}${m.in_sync === false ? ' (drifted)' : ''}`);
    else parts.push('unmanaged model');
    if (m.checksum) parts.push(`checksum ${String(m.checksum).slice(0, 12)}`);
    return parts.join(' · ');
  }

  // The run's results grouped by test, in order: {test, name, description,
  // results, failed} — the table and the text copy show one group row per
  // test and the assertions under it, without repeating the test's name.
  // (The CSV stays flat: its test column carries the grouping.)
  static groups(rep) {
    const out = [];
    for (const r of rep.results) {
      let g = out.find((x) => x.test === r.test);
      if (!g) {
        g = {
          test: r.test,
          name: rep.testNames?.[r.test] ?? '',
          description: rep.testDescs?.[r.test] ?? '',
          results: [],
          failed: 0,
        };
        out.push(g);
      }
      g.results.push(r);
      if (r.failed) g.failed++;
    }
    for (const g of out) {
      g.id = `TC${g.test + 1}`;
      g.ids = new Map(g.results.map((r, k) => [r, `A${k + 1}`])); // the assertion's id within its test case
    }
    return out;
  }

  // "TC2.A3": a result's id in the run — the test case, the assertion within it.
  static resultID(rep, r) {
    const g = PgcScenarios.groups(rep).find((x) => x.results.includes(r));
    return g ? `${g.id}.${g.ids.get(r)}` : '';
  }

  // The assertion part of a result's name (the runner prefixes the test's name).
  static assertionLabel(r, testName) {
    return testName && r.name.startsWith(testName + ': ') ? r.name.slice(testName.length + 2) : r.name;
  }

  // A result as one line of text: outcome, assertion, detail, description.
  static resultText(r) {
    return [
      r.failed ? '✘' : '✔',
      r.name,
      r.failed && r.detail ? `(${r.detail})` : '',
      r.note ? `— ${r.note}` : '',
    ]
      .filter(Boolean)
      .join(' ');
  }

  // A run as CSV: one row per result with the run's number and time, the
  // test, what was asserted, the outcome, detail and description — a
  // header row, ";" as the delimiter (descriptions and assertion names
  // carry commas; ";" is what spreadsheets in comma-decimal locales open
  // directly), RFC 4180 quoting for cells holding ";", quotes or line
  // breaks, CRLF line ends.
  static runCSV(rep, perms = new Set()) {
    const cell = (v) => {
      const str = v == null ? '' : String(v);
      return /[";\r\n]/.test(str) ? `"${str.replace(/"/g, '""')}"` : str;
    };
    // a comment line first — not a cell row — saying what the run tested
    const comment = `# ${PgcScenarios.provenance(rep)} · run #${rep.run} · ${rep.at}`;
    const groups = PgcScenarios.groups(rep);
    const header = [
      'run',
      'at',
      'category',
      'test_case',
      'assertion_id',
      'test',
      'kind',
      'subject_type',
      'subject_id',
      'subject_relation',
      'relation',
      'object_type',
      'object_id',
      'assertion',
      'outcome',
      'expected',
      'actual',
      'expected_may',
      'expected_is',
      'actual_may',
      'actual_is',
      'detail',
      'description',
    ];
    // type:id[#relation] as columns; a bare type (list_objects' object type,
    // list_subjects' subject type) is the type with no id
    const ref = (v) => {
      const str = String(v ?? '');
      const hash = str.indexOf('#');
      const main = hash >= 0 ? str.slice(0, hash) : str;
      const colon = main.indexOf(':');
      return colon >= 0
        ? [main.slice(0, colon), main.slice(colon + 1), hash >= 0 ? str.slice(hash + 1) : '']
        : [main, '', ''];
    };
    // Sets are written sorted (stable output across runs); explain's reason
    // codes are a path and keep their order.
    const ordered = (r, items) => (r.kind === 'explain' ? [...(items ?? [])] : [...(items ?? [])].sort());
    // may / is: an action set split by the model's declared permissions
    const split = (r, items) => {
      if (r.kind !== 'list_actions' || !perms.size) return ['', ''];
      const xs = ordered(r, items);
      return [xs.filter((x) => perms.has(x)).join(' '), xs.filter((x) => !perms.has(x)).join(' ')];
    };
    const rows = rep.results.map((r) => {
      const g = groups.find((x) => x.results.includes(r));
      return [
        rep.run,
        rep.at,
        'assertion',
        g?.id ?? '',
        g?.ids.get(r) ?? '',
        r.test + 1,
        r.kind,
        ...ref(r.user),
        r.relation,
        ...ref(r.object).slice(0, 2),
        r.name,
        r.failed ? 'failed' : 'passed',
        ordered(r, r.expected).join(' '),
        ordered(r, r.actual).join(' '),
        ...split(r, r.expected),
        ...split(r, r.actual),
        r.failed ? r.detail : '',
        r.note ?? '',
      ];
    });
    return [comment, ...[header, ...rows].map((row) => row.map(cell).join(';'))].join('\r\n') + '\r\n';
  }

  // A run as text: the header line, then one line per result.
  static runText(rep) {
    const head = `Run #${rep.run}${rep.only?.length ? ` (${rep.only.map((x) => `TC${x + 1}`).join(', ')} only)` : ''}: ${rep.failed ? `${rep.failed} of ${rep.passed + rep.failed} failed` : `${rep.passed} passed`}, ${rep.duration_ms} ms`;
    const lines = [head, PgcScenarios.provenance(rep) + ` · ${rep.at}`];
    for (const g of PgcScenarios.groups(rep)) {
      lines.push('');
      lines.push(
        `${g.id} ${g.failed ? '✘' : '✔'} ${g.name}${g.description ? ` — ${g.description}` : ''} (${g.failed ? `${g.failed} of ${g.results.length} failed` : `${g.results.length} passed`})`,
      );
      for (const r of g.results) {
        const note = r.note && r.note !== g.description ? ` — ${r.note}` : '';
        lines.push(
          `  ${g.ids.get(r)} ${r.failed ? '✘' : '✔'} ${PgcScenarios.assertionLabel(r, g.name)}${r.failed && r.detail ? ` (${r.detail})` : ''}${note}`,
        );
      }
    }
    return lines.join('\n') + '\n';
  }

  // Explains one check assertion inside the fixture's world (the server
  // rebuilds the ephemeral store and asks the engine for the tree).
  async _explain(r) {
    const test = this._testOf(r);
    if (test < 0 || r.kind !== 'check') return;
    this.explained = null;
    const x = await run(this, () =>
      api.scenariosExplain(this.store, this.yaml ?? '', {
        test,
        user: r.user,
        relation: r.relation,
        object: r.object,
        successful_only: this.explainOpts.successfulOnly,
        redact: this.explainOpts.redact,
      }),
    );
    if (x) {
      this.explained = { result: r, tree: x.tree?.tree ?? x.tree, redacted: x.redacted };
      await this.updateComplete;
      this.querySelector('[data-testid="test-scenarios-explained"]')?.scrollIntoView({ block: 'nearest' });
    }
  }

  // The last run's result for one assertion, by the runner's result name.
  _result(name) {
    return this.report?.results.find((r) => r.name === name);
  }

  // The last run's result for a case, by what it asserted (kind, user,
  // relation, object) — the name is for people and carries the expected set.
  _resultOf(kind, user, relation, object) {
    return this.report?.results.find(
      (r) =>
        r.kind === kind && r.user === user && (r.relation ?? '') === (relation ?? '') && r.object === object,
    );
  }

  // Relation names the store's model declares as permissions (from the
  // Test tab's meta), to read an action set as "may …" next to "is …".
  _permissions() {
    const by = this.meta?.relations_by_type ?? {};
    const out = new Set();
    for (const rels of Object.values(by)) for (const r of rels) if (r.kind === 'permission') out.add(r.name);
    return out;
  }

  // --- harness edits: every one goes through _apply(fixture) ---

  _addTest() {
    const fx = this._fixture() ?? {};
    fx.tests = fx.tests ?? [];
    fx.tests.push({ name: `TC${fx.tests.length + 1}`, check: [] });
    this._apply(fx);
    const i = fx.tests.length - 1;
    this._fold(i, false);
    this._openAdd(i);
    this.updateComplete.then(() =>
      this.querySelector(`[data-testid="test-scenarios-harness-name-${i}"]`)?.select(),
    );
  }

  _setTest(i, field, value) {
    const fx = this._fixture();
    if (!fx?.tests?.[i] || (fx.tests[i][field] ?? '') === value) return;
    if (value) fx.tests[i][field] = value;
    else delete fx.tests[i][field];
    this._apply(fx);
  }

  _removeTest(i) {
    const fx = this._fixture();
    if (!fx?.tests) return;
    fx.tests.splice(i, 1);
    this._apply(fx);
  }

  // Adds an assertion to the test: to the check case for that subject and
  // object when there is one, else as a new case; its note when given.
  _addAssertion(i) {
    const d = this.draft[i] ?? {};
    const user = d.user?.trim();
    const object = d.object?.trim();
    const rel = d.relation?.trim();
    if (!user || !object || !rel) return;
    const fx = this._fixture();
    if (!fx?.tests?.[i]) return;
    const tc = fx.tests[i];
    tc.check = tc.check ?? [];
    let c = tc.check.find(
      (x) => x.user === user && x.object === object && !x.context && !x.contextual_tuples,
    );
    if (!c) {
      c = { user, object, assertions: {} };
      tc.check.push(c);
    }
    c.assertions = { ...(c.assertions ?? {}), [rel]: d.want !== 'false' };
    if (d.note?.trim()) c.notes = { ...(c.notes ?? {}), [rel]: d.note.trim() };
    this.draft = { ...this.draft, [i]: { ...d, relation: '', note: '' } }; // subject and object stay for the next one
    this._apply(fx);
  }

  _removeAssertion(i, ci, rel) {
    const fx = this._fixture();
    const c = fx?.tests?.[i]?.check?.[ci];
    if (!c) return;
    delete c.assertions[rel];
    if (c.notes) delete c.notes[rel];
    if (!Object.keys(c.assertions).length) fx.tests[i].check.splice(ci, 1);
    this._apply(fx);
  }

  // The description of a case (check / list_objects / explain); empty removes it.
  _setCaseDesc(i, kind, ci, text) {
    const fx = this._fixture();
    const c = fx?.tests?.[i]?.[kind]?.[ci];
    if (!c) return;
    const desc = text.trim();
    this.noting = '';
    if ((c.description ?? '') === desc) return;
    if (desc) c.description = desc;
    else delete c.description;
    this._apply(fx);
  }

  // Free text in place: the text with its links clickable and ✎ to edit
  // (or "+ description" when empty); while editing, an input — Enter or
  // blur saves, Escape cancels.
  _text(key, value, save, placeholder, testid) {
    if (this.noting === key)
      return html`<input
        class="fx-desc"
        placeholder=${placeholder}
        .value=${value ?? ''}
        @keydown=${(e) => {
          if (e.key === 'Enter') save(e.target.value);
          if (e.key === 'Escape') this.noting = '';
        }}
        @blur=${(e) => save(e.target.value)}
        data-testid=${testid}
      />`;
    const open = () => {
      this.noting = key;
      this.updateComplete.then(() => this.querySelector(`[data-testid="${testid}"]`)?.focus());
    };
    return value
      ? html`<span class="fx-text"
          >${linkify(value)}
          <button
            type="button"
            class="link"
            title=${t('edit')}
            data-testid=${testid + '-edit'}
            @click=${open}
          >
            ✎
          </button></span
        >`
      : html`<button type="button" class="link fx-text-add" data-testid=${testid + '-edit'} @click=${open}>
          + ${t('description')}
        </button>`;
  }

  // The note of one assertion (relation of a check case); empty removes it.
  _setNote(i, ci, rel, text) {
    const fx = this._fixture();
    const c = fx?.tests?.[i]?.check?.[ci];
    if (!c) return;
    const note = text.trim();
    if ((c.notes?.[rel] ?? '') === note) {
      this.noting = '';
      return;
    }
    c.notes = { ...(c.notes ?? {}) };
    if (note) c.notes[rel] = note;
    else delete c.notes[rel];
    if (!Object.keys(c.notes).length) delete c.notes;
    this.noting = '';
    this._apply(fx);
  }

  _removeCase(i, kind, ci) {
    const fx = this._fixture();
    if (!fx?.tests?.[i]?.[kind]) return;
    fx.tests[i][kind].splice(ci, 1);
    this._apply(fx);
  }

  _addTuple() {
    const d = this.draft.tuple ?? {};
    const user = d.user?.trim();
    const relation = d.relation?.trim();
    const object = d.object?.trim();
    if (!user || !relation || !object) return;
    const fx = this._fixture() ?? {};
    fx.tuples = fx.tuples ?? [];
    if (!fx.tuples.some((x) => x.user === user && x.relation === relation && x.object === object))
      fx.tuples.push({ user, relation, object });
    this.draft = { ...this.draft, tuple: { ...d, user: '' } };
    this._apply(fx);
  }

  _removeTuple(ti) {
    const fx = this._fixture();
    if (!fx?.tuples) return;
    fx.tuples.splice(ti, 1);
    this._apply(fx);
  }

  _setDraft(key, field, value) {
    this.draft = { ...this.draft, [key]: { ...(this.draft[key] ?? {}), [field]: value } };
  }

  // Opens (or closes) the add row of a test or of the tuples; opening
  // focuses its first field.
  _openAdd(key, on = true) {
    const adding = new Set(this.adding);
    if (on) adding.add(key);
    else adding.delete(key);
    this.adding = adding;
    if (on)
      this.updateComplete.then(() =>
        this.querySelector(
          `[data-testid="test-scenarios-${key === 'tuple' ? 'tuple-user' : 'add-user-' + key}"]`,
        )?.focus(),
      );
  }

  // --- the YAML view: one editor over the whole text ---

  _highlighted(yaml) {
    const lines = highlightYAML(yaml + '\n');
    const pick = this.picked?.line;
    if (pick && lines[pick - 1]) lines[pick - 1] = html`<span class="selline">${lines[pick - 1]}</span>`;
    const err = this.check && !this.check.ok ? this.check.line : 0;
    if (err && lines[err - 1]) lines[err - 1] = html`<span class="errline">${lines[err - 1]}</span>`;
    return lines;
  }

  // The play column of the YAML editor: a ▶ on every test's "- name:" line
  // (run that test only), coloured by the last run's outcome, scrolling
  // with the text (the track is shifted by the textarea's scrollTop).
  _playGutter(yaml) {
    // from the TEXT, not the last validation: the buttons stay while
    // typing (disabled while the text does not parse), and follow the lines
    const lines = scenarioLines(yaml);
    if (!lines.length) return nothing;
    const all = yaml.split('\n');
    const invalid = !!(this.check && !this.check.ok);
    return html`<div class="fx-play-layer" aria-hidden="false">
      <div class="fx-play-track" data-testid="test-scenarios-play-track">
        ${lines.map((line, i) => {
          const name = (/^\s*-\s+name:\s*(.*?)\s*$/.exec(all[line - 1])?.[1] ?? '').replace(
            /^(["'])(.*)\1$/,
            '$2',
          );
          const mine = this.report ? this.report.results.filter((r) => this._testOf(r) === i) : [];
          const failed = mine.filter((r) => r.failed).length;
          return html`<button
            type="button"
            class="fx-play ${mine.length ? (failed ? 'deny' : 'ok') : ''}"
            style=${`top: calc(var(--s-2) + ${line - 1} * 1.5em)`}
            ?disabled=${this.busy || invalid}
            title=${invalid ? t('fix the YAML first') : t('run {tc} only: {name}', { tc: `TC${i + 1}`, name })}
            data-testid=${`test-scenarios-play-${i}`}
            @click=${() => this._run([i])}
          >
            <span>▶</span>
          </button>`;
        })}
      </div>
    </div>`;
  }

  _yamlView(yaml) {
    const rows = Math.min(18, Math.max(6, yaml.split('\n').length + 1)); // ~a third of a screen; scrolls, and the corner resizes it
    const playable = scenarioLines(yaml).length > 0;
    return html`<div
      class="json-editor numbered ${playable ? 'playable' : ''} ${this.check && !this.check.ok ? 'invalid' : ''}"
    >
      ${this._playGutter(yaml)}
      <pre class="json-hl" aria-hidden="true">${this._highlighted(yaml)}</pre>
      <textarea
        class="mono"
        rows=${rows}
        spellcheck="false"
        autocomplete="off"
        wrap="off"
        placeholder=${t('tuples:\n  - user: user:alice\n    relation: viewer\n    object: doc:plan\ntests:\n  - name: …')}
        .value=${yaml}
        @input=${(e) => {
          this.picked = null;
          this._emit(e.target.value);
        }}
        @keydown=${this._editorKeys}
        @scroll=${this._sync}
        data-testid="test-scenarios-yaml"
      ></textarea>
    </div>`;
  }

  // --- the harness: the parsed fixture as a form ---

  _datalists() {
    const m = this.meta ?? {};
    return html`<datalist id="dl-scn-subjects">
        ${(m.subjects ?? []).map((x) => html`<option value=${x}></option>`)}
      </datalist>
      <datalist id="dl-scn-objects">
        ${(m.objects ?? []).map((x) => html`<option value=${x}></option>`)}
      </datalist>
      <datalist id="dl-scn-relations">
        ${(m.relations ?? []).map((x) => html`<option value=${x}></option>`)}
      </datalist>`;
  }

  // The fold toggle: a drawn chevron (CSS) with a 2em hit area.
  _toggle(id, open, testid) {
    return html`<button
      type="button"
      class="link fx-toggle"
      aria-expanded=${open}
      title=${t('collapse / expand')}
      data-testid=${testid}
      @click=${() => this._fold(id, open)}
    ></button>`;
  }

  _harness() {
    const yaml = this.yaml ?? '';
    if (yaml.trim() && !this.check) return html`<p class="help">${t('Parsing…')}</p>`;
    if (this.check && !this.check.ok)
      return html`<p class="json-warn" data-testid="test-scenarios-harness-invalid">
        ⚠ ${this.check.line ? t('line {n}', { n: this.check.line }) + ': ' : ''}${this.check.error}
        <button type="button" class="link" @click=${() => this._goView('yaml')}>${t('Edit as YAML')}</button>
      </p>`;
    const fx = this.check?.fixture ?? {};
    const tuples = fx.tuples ?? [];
    const tests = fx.tests ?? [];
    const tuplesOpen = !this.folded.has('tuples');
    return html`${this._datalists()}
      <p class="help">
        ${fx.model ? t('Tests the registry model {model}.', { model: fx.model }) : t("Tests this store's current model.")}
        ${t('Hermetic: only the tuples below exist in the ephemeral store a run creates — list what the checks rely on.')}
      </p>
      <div class="fx-block" data-testid="test-scenarios-harness-tuples">
        <div class="fx-head">
          ${this._toggle('tuples', tuplesOpen, 'test-scenarios-fold-tuples')}
          <span class="fx-label pick" @click=${() => this._fold('tuples', tuplesOpen)}
            >${t('Tuples')} <span class="muted">(${tuples.length})</span></span
          >
        </div>
        ${tuplesOpen ? this._tuples(tuples) : nothing}
      </div>
      <div class="fx-block">
        <div class="fx-head">
          <span class="fx-label">${t('Test cases')} <span class="muted">(${tests.length})</span></span>
          <span class="actions fx-lines">
            <button type="button" class="link" @click=${() => this._foldAll(true)}>
              ${t('collapse all')}
            </button>
            <button type="button" class="link" @click=${() => this._foldAll(false)}>
              ${t('expand all')}
            </button>
            <button type="button" class="sm" data-testid="test-scenarios-add-test" @click=${this._addTest}>
              + ${t('Add test case')}
            </button>
          </span>
        </div>
      </div>
      ${tests.map((tc, i) => this._harnessTest(tc, i))}`;
  }

  _tuples(tuples) {
    const td = this.draft.tuple ?? {};
    const onEnter = (e) => e.key === 'Enter' && this._addTuple();
    const field = (name, list, placeholder, testid) =>
      html`<input
        class="mono"
        list=${list}
        placeholder=${placeholder}
        .value=${td[name] ?? ''}
        @input=${(e) => this._setDraft('tuple', name, e.target.value)}
        @keydown=${onEnter}
        data-testid=${testid}
      />`;
    return html`<div class="fx-body">
      ${
        tuples.length
          ? html`<div class="table-wrap">
              <table class="compact">
                <thead>
                  <tr>
                    <th class="num">#</th>
                    <th>${t('Subject')}</th>
                    <th>${t('Relation')}</th>
                    <th>${t('Object')}</th>
                    <th>${t('Condition')}</th>
                    <th>${t('Expires at')}</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  ${tuples.map(
                    (x, i) =>
                      html`<tr data-testid=${`test-scenarios-tuple-${i}`}>
                        <td class="num muted">${i + 1}</td>
                        <td class="mono">${x.user}</td>
                        <td class="mono">${x.relation}</td>
                        <td class="mono">${x.object}</td>
                        <td class="mono">
                          ${x.condition ?? ''}${x.context ? html` <span class="muted">${JSON.stringify(x.context)}</span>` : nothing}
                        </td>
                        <td class="muted">${x.expires_at ?? ''}</td>
                        <td>
                          <button
                            type="button"
                            class="link"
                            title=${t('remove')}
                            @click=${() => this._removeTuple(i)}
                          >
                            ×
                          </button>
                        </td>
                      </tr>`,
                  )}
                </tbody>
              </table>
            </div>`
          : html`<p class="help">${t('No tuples: every check decides against an empty store.')}</p>`
      }
      ${
        this.adding.has('tuple')
          ? html`<div class="fx-add inline" data-testid="test-scenarios-tuple-add-row">
              ${field('user', 'dl-scn-subjects', 'user:alice', 'test-scenarios-tuple-user')}
              ${field('relation', 'dl-scn-relations', 'viewer', 'test-scenarios-tuple-relation')}
              ${field('object', 'dl-scn-objects', 'doc:plan', 'test-scenarios-tuple-object')}
              <button
                type="button"
                class="sm"
                ?disabled=${!(td.user && td.relation && td.object)}
                data-testid="test-scenarios-tuple-add"
                @click=${this._addTuple}
              >
                + ${t('Add')}
              </button>
              <button type="button" class="link" @click=${() => this._openAdd('tuple', false)}>
                ${t('done')}
              </button>
              <span class="help">${t('conditions, context and expiry: in the YAML')}</span>
            </div>`
          : html`<button
              type="button"
              class="sm"
              data-testid="test-scenarios-tuple-open"
              @click=${() => this._openAdd('tuple')}
            >
              + ${t('Add tuple')}
            </button>`
      }
    </div>`;
  }

  // One assertion's row in the run's table: i its index in the run, g its
  // group (the test), whose name the label leaves out and whose description
  // the description cell does not repeat.
  _resultRow(r, i, g) {
    return html`<tr
      class="pick ${r.failed ? 'deny' : ''} ${this.explained?.result === r ? 'explaining' : ''}"
      title=${t('Show {tc}', { tc: `TC${r.test + 1}` })}
      data-testid=${`test-scenarios-result-${i + 1}`}
      @click=${() => this._reveal(r)}
    >
      <td class="num muted">${g.ids.get(r)}</td>
      <td>${r.failed ? '✘' : '✔'}</td>
      <td class="mono">${PgcScenarios.assertionLabel(r, g.name)}</td>
      <td class="muted">${r.failed ? r.detail : ''}</td>
      <td class="muted">${r.note && r.note !== g.description ? linkify(r.note) : ''}</td>
      <td class="nowrap">
        ${
          r.kind === 'check'
            ? html`<button
                type="button"
                class="link"
                title=${t("why: the engine's resolution tree for this assertion, inside the fixture's world")}
                data-testid=${`test-scenarios-explain-${i + 1}`}
                @click=${(e) => {
                  e.stopPropagation();
                  this._explain(r);
                }}
              >
                ${this.explained?.result === r ? t('explained ↓') : t('explain')}
              </button>`
            : nothing
        }
        <button
          type="button"
          class="link"
          title=${t('copy this assertion and its outcome as text')}
          data-testid=${`test-scenarios-copy-${i + 1}`}
          @click=${(e) => {
            e.stopPropagation();
            this._copy(`r${i}`, PgcScenarios.resultText(r));
          }}
        >
          ${this.copied === `r${i}` ? t('Copied') : t('copy')}
        </button>
      </td>
    </tr>`;
  }

  // One assertion as a chip: the outcome of the last run when there was
  // one, its note (tooltip; ✎ edits it inline), × removes it.
  _chip(i, ci, rel, want, c, name) {
    const r = this._result(name);
    const key = `${i}/${ci}/${rel}`;
    const note = c.notes?.[rel] ?? '';
    const title = [r?.failed ? r.detail : '', note].filter(Boolean).join(' — ');
    return html`<span
      class="chip ${r ? (r.failed ? 'deny' : 'ok') : ''} ${note ? 'noted' : ''}"
      title=${title}
      >${r ? (r.failed ? '✘ ' : '✔ ') : ''}<span class="mono">${rel} = ${String(want)}</span>
      ${
        this.noting === key
          ? html`<input
              class="fx-note"
              placeholder=${t('description: a user story, a ticket, [JIRA-99](https://…) links')}
              .value=${note}
              @keydown=${(e) => {
                if (e.key === 'Enter') this._setNote(i, ci, rel, e.target.value);
                if (e.key === 'Escape') this.noting = '';
              }}
              @blur=${(e) => this._setNote(i, ci, rel, e.target.value)}
              data-testid=${`test-scenarios-note-${i}-${ci}-${rel}`}
            />`
          : html`<button
              type="button"
              class="link ${note ? '' : 'fx-note-add'}"
              title=${note ? t('edit the description') : t('describe this assertion')}
              data-testid=${`test-scenarios-note-edit-${i}-${ci}-${rel}`}
              @click=${() => {
                this.noting = key;
                this.updateComplete.then(() =>
                  this.querySelector(`[data-testid="test-scenarios-note-${i}-${ci}-${rel}"]`)?.focus(),
                );
              }}
            >
              ${note ? '✎' : '+✎'}
            </button>`
      }
      <button
        type="button"
        class="link"
        title=${t('remove')}
        @click=${() => this._removeAssertion(i, ci, rel)}
      >
        ×
      </button></span
    >`;
  }

  _harnessTest(tc, i) {
    const open = !this.folded.has(i);
    const mine = this.report ? this.report.results.filter((r) => r.test === i) : null;
    const failed = mine?.filter((r) => r.failed).length ?? 0;
    const outcome = (r, text) =>
      html`<span class="chip ${r ? (r.failed ? 'deny' : 'ok') : ''}" title=${r?.failed ? r.detail : ''}
        >${r ? (r.failed ? '✘ ' : '✔ ') : ''}${text}</span
      >`;
    const perms = this._permissions();
    const actionsText = (items) => {
      if (!perms.size) return (items ?? []).join(', ') || t('nothing');
      const may = (items ?? []).filter((x) => perms.has(x));
      const is = (items ?? []).filter((x) => !perms.has(x));
      return html`<span class="muted">${t('may')}</span> ${may.join(', ') || '—'}
        <span class="muted">· ${t('is')}</span> ${is.join(', ') || '—'}`;
    };
    const d = this.draft[i] ?? {};
    const ready = d.user?.trim() && d.object?.trim() && d.relation?.trim();
    const onEnter = (e) => e.key === 'Enter' && this._addAssertion(i);
    const field = (name, list, placeholder, testid, cls = 'mono') =>
      html`<input
        class=${cls}
        list=${list || nothing}
        placeholder=${placeholder}
        .value=${d[name] ?? ''}
        @input=${(e) => this._setDraft(i, name, e.target.value)}
        @keydown=${onEnter}
        data-testid=${testid}
      />`;
    return html`<div
      class="fx-block fx-test ${this.picked?.test === i ? 'picked' : ''}"
      data-testid=${`test-scenarios-harness-test-${i}`}
    >
      <div class="fx-head">
        ${this._toggle(i, open, `test-scenarios-fold-test-${i}`)}
        <span class="muted fx-num" title=${t('collapse / expand')} @click=${() => this._fold(i, open)}
          >TC${i + 1}</span
        >
        <input
          class="fx-name"
          .value=${tc.name ?? ''}
          title=${t("the scenario's name")}
          @change=${(e) => this._setTest(i, 'name', e.target.value.trim())}
          data-testid=${`test-scenarios-harness-name-${i}`}
        />
        ${
          mine && mine.length
            ? failed
              ? html`<span class="badge deny"
                  >✘ ${t('{f} of {n} failed', { f: failed, n: mine.length })}</span
                >`
              : html`<span class="badge ok">✔ ${t('{n} passed', { n: mine.length })}</span>`
            : html`<span class="muted">${t('{n} assertion(s)', { n: countTest(tc) })}</span>`
        }
        <span class="actions fx-lines">
          <button
            type="button"
            class="sm"
            ?disabled=${this.busy}
            title=${t('run this test only')}
            data-testid=${`test-scenarios-run-test-${i}`}
            @click=${() => this._run([i])}
          >
            ▶ ${t('Run')}
          </button>
          <button type="button" class="link" @click=${() => this._editTest(i)}>${t('edit YAML')}</button>
          <button
            type="button"
            class="link"
            title=${t('remove this test')}
            data-testid=${`test-scenarios-remove-test-${i}`}
            @click=${() => this._removeTest(i)}
          >
            ×
          </button>
        </span>
      </div>
      ${
        open
          ? html`<div class="fx-body">
              <div class="fx-descline">
                ${this._text(
                  `test/${i}`,
                  tc.description,
                  (v) => {
                    this.noting = '';
                    this._setTest(i, 'description', v.trim());
                  },
                  t('description: a user story, a ticket, [JIRA-99](https://…) links'),
                  `test-scenarios-harness-desc-${i}`,
                )}
              </div>
              ${
                tc.check?.length
                  ? html`<table class="compact">
                      <thead>
                        <tr>
                          <th>${t('Subject')}</th>
                          <th>${t('Object')}</th>
                          <th>${t('Assertions')}</th>
                          <th>${t('Context')}</th>
                        </tr>
                      </thead>
                      <tbody>
                        ${tc.check.map(
                          (c, ci) =>
                            html`<tr>
                              <td class="mono">${c.user}</td>
                              <td class="mono">${c.object}</td>
                              <td>
                                <div class="chips">
                                  ${Object.entries(c.assertions ?? {}).map(([rel, want]) =>
                                    this._chip(
                                      i,
                                      ci,
                                      rel,
                                      want,
                                      c,
                                      `${tc.name}: ${c.user} ${rel} ${c.object} = ${want}`,
                                    ),
                                  )}
                                  ${c.contextual_tuples?.length ? html`<span class="badge muted">${t('{n} contextual tuple(s)', { n: c.contextual_tuples.length })}</span>` : nothing}
                                </div>
                                ${Object.entries(c.notes ?? {}).map(
                                  ([rel, text]) =>
                                    html`<div class="help fx-text">
                                      <span class="mono">${rel}</span>: ${linkify(text)}
                                    </div>`,
                                )}
                                <div class="fx-descline">
                                  ${this._text(
                                    `check/${i}/${ci}`,
                                    c.description,
                                    (v) => this._setCaseDesc(i, 'check', ci, v),
                                    t('description: a user story, a ticket, [JIRA-99](https://…) links'),
                                    `test-scenarios-case-desc-${i}-${ci}`,
                                  )}
                                </div>
                              </td>
                              <td class="mono muted">${c.context ? JSON.stringify(c.context) : ''}</td>
                            </tr>`,
                        )}
                      </tbody>
                    </table>`
                  : nothing
              }
              ${
                this.adding.has(i)
                  ? html`<div class="fx-add inline" data-testid=${`test-scenarios-add-row-${i}`}>
                      ${field('user', 'dl-scn-subjects', 'user:alice', `test-scenarios-add-user-${i}`)}
                      ${field('object', 'dl-scn-objects', 'doc:plan', `test-scenarios-add-object-${i}`)}
                      ${field('relation', 'dl-scn-relations', 'can_read', `test-scenarios-add-relation-${i}`)}
                      <select
                        .value=${d.want ?? 'true'}
                        @change=${(e) => this._setDraft(i, 'want', e.target.value)}
                        data-testid=${`test-scenarios-add-want-${i}`}
                      >
                        <option value="true">${t('allowed')}</option>
                        <option value="false">${t('denied')}</option>
                      </select>
                      ${field('note', '', t('description (optional)'), `test-scenarios-add-note-${i}`, 'fx-note')}
                      <button
                        type="button"
                        class="sm"
                        ?disabled=${!ready}
                        data-testid=${`test-scenarios-add-assertion-${i}`}
                        @click=${() => this._addAssertion(i)}
                      >
                        + ${t('Add')}
                      </button>
                      <button type="button" class="link" @click=${() => this._openAdd(i, false)}>
                        ${t('done')}
                      </button>
                      <span class="help">${t('context and contextual tuples: in the YAML')}</span>
                    </div>`
                  : html`<button
                      type="button"
                      class="sm"
                      data-testid=${`test-scenarios-add-open-${i}`}
                      @click=${() => this._openAdd(i)}
                    >
                      + ${t('Add assertion')}
                    </button>`
              }
              ${
                tc.list_objects?.length
                  ? html`<table class="compact">
                      <thead>
                        <tr>
                          <th>${t('Subject')}</th>
                          <th>${t('Type')}</th>
                          <th>${t('Reaches (list_objects)')}</th>
                          <th></th>
                        </tr>
                      </thead>
                      <tbody>
                        ${tc.list_objects.map(
                          (l, li) =>
                            html`<tr>
                              <td class="mono">${l.user}</td>
                              <td class="mono">${l.type}</td>
                              <td>
                                <div class="chips">
                                  ${Object.entries(l.assertions ?? {}).map(([rel, ids]) =>
                                    outcome(
                                      this._resultOf('list_objects', l.user, rel, l.type),
                                      html`<span class="mono"
                                        >${rel} → ${ids.length ? ids.join(', ') : t('nothing')}</span
                                      >`,
                                    ),
                                  )}
                                </div>
                                <div class="fx-descline">
                                  ${this._text(
                                    `list/${i}/${li}`,
                                    l.description,
                                    (v) => this._setCaseDesc(i, 'list_objects', li, v),
                                    t('description: a user story, a ticket, [JIRA-99](https://…) links'),
                                    `test-scenarios-list-desc-${i}-${li}`,
                                  )}
                                </div>
                              </td>
                              <td>
                                <button
                                  type="button"
                                  class="link"
                                  title=${t('remove')}
                                  @click=${() => this._removeCase(i, 'list_objects', li)}
                                >
                                  ×
                                </button>
                              </td>
                            </tr>`,
                        )}
                      </tbody>
                    </table>`
                  : nothing
              }
              ${
                tc.list_subjects?.length
                  ? html`<table class="compact">
                      <thead>
                        <tr>
                          <th>${t('Object')}</th>
                          <th>${t('Subject type')}</th>
                          <th>${t('Reached by (list_subjects)')}</th>
                          <th></th>
                        </tr>
                      </thead>
                      <tbody>
                        ${tc.list_subjects.map(
                          (l, li) =>
                            html`<tr>
                              <td class="mono">${l.object}</td>
                              <td class="mono">${l.type}</td>
                              <td>
                                <div class="chips">
                                  ${Object.entries(l.assertions ?? {}).map(([rel, ids]) =>
                                    outcome(
                                      this._resultOf('list_subjects', l.type, rel, l.object),
                                      html`<span class="mono"
                                        >${rel} ← ${ids.length ? ids.join(', ') : t('nobody')}</span
                                      >`,
                                    ),
                                  )}
                                </div>
                                <div class="fx-descline">
                                  ${this._text(
                                    `list_subjects/${i}/${li}`,
                                    l.description,
                                    (v) => this._setCaseDesc(i, 'list_subjects', li, v),
                                    t('description: a user story, a ticket, [JIRA-99](https://…) links'),
                                    `test-scenarios-subjects-desc-${i}-${li}`,
                                  )}
                                </div>
                              </td>
                              <td>
                                <button
                                  type="button"
                                  class="link"
                                  title=${t('remove')}
                                  @click=${() => this._removeCase(i, 'list_subjects', li)}
                                >
                                  ×
                                </button>
                              </td>
                            </tr>`,
                        )}
                      </tbody>
                    </table>`
                  : nothing
              }
              ${
                tc.list_actions?.length
                  ? html`<table class="compact">
                      <thead>
                        <tr>
                          <th>${t('Subject')}</th>
                          <th>${t('Object')}</th>
                          <th>${t('May do exactly (list_actions)')}</th>
                          <th></th>
                        </tr>
                      </thead>
                      <tbody>
                        ${tc.list_actions.map(
                          (a, ai) =>
                            html`<tr>
                              <td class="mono">${a.user}</td>
                              <td class="mono">${a.object}</td>
                              <td>
                                ${outcome(
                                  this._resultOf('list_actions', a.user, '', a.object),
                                  html`<span class="mono">${actionsText(a.expect)}</span>`,
                                )}
                                <div class="fx-descline">
                                  ${this._text(
                                    `list_actions/${i}/${ai}`,
                                    a.description,
                                    (v) => this._setCaseDesc(i, 'list_actions', ai, v),
                                    t('description: a user story, a ticket, [JIRA-99](https://…) links'),
                                    `test-scenarios-actions-desc-${i}-${ai}`,
                                  )}
                                </div>
                              </td>
                              <td>
                                <button
                                  type="button"
                                  class="link"
                                  title=${t('remove')}
                                  @click=${() => this._removeCase(i, 'list_actions', ai)}
                                >
                                  ×
                                </button>
                              </td>
                            </tr>`,
                        )}
                      </tbody>
                    </table>`
                  : nothing
              }
              ${
                tc.explain?.length
                  ? html`<table class="compact">
                      <thead>
                        <tr>
                          <th>${t('Subject')}</th>
                          <th>${t('Relation')}</th>
                          <th>${t('Object')}</th>
                          <th>${t('Expected reasons (explain)')}</th>
                          <th></th>
                        </tr>
                      </thead>
                      <tbody>
                        ${tc.explain.map(
                          (e, ei) =>
                            html`<tr>
                              <td class="mono">${e.user}</td>
                              <td class="mono">${e.relation}</td>
                              <td class="mono">${e.object}</td>
                              <td>
                                ${outcome(
                                  this._resultOf('explain', e.user, e.relation, e.object),
                                  html`<span class="mono">${(e.expect_reasons ?? []).join(' → ')}</span>`,
                                )}
                                <div class="fx-descline">
                                  ${this._text(
                                    `explain/${i}/${ei}`,
                                    e.description,
                                    (v) => this._setCaseDesc(i, 'explain', ei, v),
                                    t('description: a user story, a ticket, [JIRA-99](https://…) links'),
                                    `test-scenarios-explain-desc-${i}-${ei}`,
                                  )}
                                </div>
                              </td>
                              <td>
                                <button
                                  type="button"
                                  class="link"
                                  title=${t('remove')}
                                  @click=${() => this._removeCase(i, 'explain', ei)}
                                >
                                  ×
                                </button>
                              </td>
                            </tr>`,
                        )}
                      </tbody>
                    </table>`
                  : nothing
              }
            </div>`
          : nothing
      }
    </div>`;
  }

  render() {
    const yaml = this.yaml ?? '';
    const dirty = yaml !== this.savedYaml;
    const canEdit = !!(this.info?.can_edit ?? this.caps?.can_edit_model);
    const rep = this.report;
    const views = [
      [
        'harness',
        'Test harness',
        "The fixture as a form: the tuples as a table, every test as a block with its cases and the last run's outcome; add, rename, remove, annotate.",
      ],
      [
        'yaml',
        'Edit as YAML',
        'The fixture as text: paste or edit it directly, highlighted and line-numbered, validated as you type; comments survive here.',
      ],
    ];
    return html`<section class="card" data-testid="test-scenarios">
        <h3>
          ${t('Scenarios')}
          ${help("The store's saved checks as a tests.authz.yaml fixture — the format pgauthzctl model test runs (a superset of OpenFGA's store tests). Hermetic: every run creates an ephemeral store, rebuilds this store's CURRENT model in it, writes the fixture's tuples and decides the assertions there — nothing of this store's data takes part, list the tuples the checks need (Seed from the store's data). Recorded as you; the test policy applies (other subjects, enumeration, explain).")}
        </h3>
        <p class="help">
          ${t("Add a case from a result (Single check, Search), in the harness, or as YAML. Without a model line the fixture tests this store's current model; model: name@version tests a registry model.")}
        </p>
        <div class="toolbar">
          <div class="seg" role="tablist">
            ${views.map(
              ([id, label, tip]) =>
                html`<button
                  type="button"
                  role="tab"
                  class=${this.view === id ? 'active' : ''}
                  title=${t(tip)}
                  data-testid=${`test-scenarios-view-${id}`}
                  @click=${() => this._goView(id)}
                >
                  ${t(label)}
                </button>`,
            )}
          </div>
          <div class="json-status" data-testid="test-scenarios-status">
            ${
              this.check && !this.check.ok
                ? html`<span class="json-warn"
                    >⚠
                    ${this.check.line ? t('line {n}', { n: this.check.line }) + ': ' : ''}${this.check.error}</span
                  >`
                : this.check?.ok && yaml.trim()
                  ? html`<span class="json-ok"
                      >✓
                      ${t('{n} assertion(s) in {m} scenario(s)', { n: this.check.cases, m: this.check.tests })}</span
                    >`
                  : nothing
            }
          </div>
        </div>
        ${this.view === 'harness' ? this._harness() : this._yamlView(yaml)}
        <div class="actions" style="margin-top:var(--s-3)">
          <button
            class="primary sm"
            ?disabled=${this.busy || !yaml.trim()}
            data-testid="test-scenarios-run"
            @click=${() => this._run()}
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
        rep || this.history.length
          ? html`<section class="card" data-testid="test-scenarios-results">
              ${
                this.history.length
                  ? html`<div class="toolbar fx-history" data-testid="test-scenarios-history">
                      <label class="inline"
                        ><span class="muted">${t('Execution')}</span>
                        <select
                          data-testid="test-scenarios-history-select"
                          @change=${(e) => {
                            this.report = this.history.find((h) => String(h.run) === e.target.value) ?? null;
                            this.picked = null;
                            this.explained = null;
                          }}
                        >
                          ${rep ? nothing : html`<option value="" selected>${t('(none shown)')}</option>`}
                          ${this.history.map(
                            (h) =>
                              html`<option value=${h.run} ?selected=${rep === h}>
                                ${t('Run #{n}', { n: h.run })} · ${fmtTime(h.at)} ·
                                ${h.failed ? '✘ ' + t('{f} of {n} failed', { f: h.failed, n: h.passed + h.failed }) : '✔ ' + t('{n} passed', { n: h.passed })}${h.only?.length ? ' · ' + t('{tc} only', { tc: h.only.map((x) => `TC${x + 1}`).join(', ') }) : ''}
                              </option>`,
                          )}
                        </select>
                      </label>
                      <span class="help"
                        >${t('{n} of this session, newest first', { n: this.history.length })}</span
                      >
                      <button
                        type="button"
                        class="link"
                        data-testid="test-scenarios-clear-all"
                        @click=${() => this._clearRuns(true)}
                      >
                        ${t('clear history')}
                      </button>
                    </div>`
                  : nothing
              }
              ${rep ? this._runReport(rep) : nothing}
              ${
                this.explained
                  ? html`<div class="fx-explained" data-testid="test-scenarios-explained">
                      <div class="toolbar">
                        <h3>
                          ${t('Why')}: <span class="mono">${this.explained.result.name}</span>
                          ${this.explained.redacted ? html`<span class="badge muted">${t('redacted')}</span>` : nothing}
                        </h3>
                        <span class="help"
                          >${t("decided inside the fixture's world: its model and its tuples, nothing of the store's data")}</span
                        >
                        <button
                          type="button"
                          class="sm"
                          title=${t('the resolution tree as indented text')}
                          data-testid="test-scenarios-copy-resolution"
                          @click=${() => this._copy('resolution', PgcExplainTree.toText(this.explained.tree))}
                        >
                          ${this.copied === 'resolution' ? t('Copied') : t('Copy resolution')}
                        </button>
                        <button type="button" class="sm" @click=${() => (this.explained = null)}>
                          ${t('Close')}
                        </button>
                      </div>
                      ${explainOptions({
                        ...this.explainOpts,
                        explainFull: !!this.caps?.can_test_explain_full,
                        policyNote: html`<span class="help"
                          >${t('identifiers are always redacted for you')}</span
                        >`,
                        onChange: (o) => {
                          this.explainOpts = o;
                          void this._explain(this.explained.result);
                        },
                      })}
                      <pgc-explain-tree .node=${this.explained.tree} root></pgc-explain-tree>
                    </div>`
                  : nothing
              }
            </section>`
          : nothing
      }
      ${this.exported ? this._exportedCard() : nothing}`;
  }

  _runReport(rep) {
    return html`<div class="toolbar">
        <h3>
          ${t('Run #{n}', { n: rep.run })}${rep.only?.length ? html` <span class="muted">· ${t('{tc} only', { tc: rep.only.map((x) => `TC${x + 1}`).join(', ') })}</span>` : nothing}
        </h3>
        <span
          class="help mono"
          title=${t("what this run decided against: the store, its model (registry version, or unmanaged) and the live model's checksum")}
          data-testid="test-scenarios-provenance"
          >${PgcScenarios.provenance(rep)}</span
        >
        <span class="decision ${rep.failed ? 'deny' : 'allow'}" data-testid="test-scenarios-summary"
          >${rep.failed ? '✘ ' + t('{f} of {n} failed', { f: rep.failed, n: rep.passed + rep.failed }) : '✔ ' + t('{n} passed', { n: rep.passed })}</span
        >
        <span class="help"
          >${fmtTime(rep.at)} · ${t('{ms} ms, in an ephemeral store', { ms: rep.duration_ms })} ·
          ${t('click a result to show its scenario')}</span
        >
        <button
          type="button"
          class="sm"
          title=${t('the run as text: one line per assertion with its outcome')}
          data-testid="test-scenarios-copy-run"
          @click=${() => this._copy('run', PgcScenarios.runText(rep))}
        >
          ${this.copied === 'run' ? t('Copied') : t('Copy results')}
        </button>
        <button
          type="button"
          class="sm"
          title=${t('the run as CSV: a header row, then one row per assertion with test, subject, relation, object, outcome, detail and description')}
          data-testid="test-scenarios-copy-csv"
          @click=${() => this._copy('csv', PgcScenarios.runCSV(rep, this._permissions()))}
        >
          ${this.copied === 'csv' ? t('Copied') : t('Copy as CSV')}
        </button>
        <button
          type="button"
          class="sm"
          data-testid="test-scenarios-clear"
          @click=${() => {
            this._clearRuns(false);
            this.explained = null;
          }}
        >
          ${t('Clear')}
        </button>
      </div>
      <div class="table-wrap">
        <table class="compact scenario-results">
          <thead>
            <tr>
              <th class="num">#</th>
              <th></th>
              <th>${t('Assertion')}</th>
              <th>${t('Detail')}</th>
              <th>${t('Description')}</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            ${PgcScenarios.groups(rep).flatMap((g) => [
              html`<tr
                class="group"
                title=${t('Show {tc}', { tc: `TC${g.test + 1}` })}
                data-testid=${`test-scenarios-group-${g.test + 1}`}
                @click=${() => this._reveal(g.results[0])}
              >
                <td class="num muted">${g.id}</td>
                <td>${g.failed ? '✘' : '✔'}</td>
                <td colspan="4">
                  <b>${g.name}</b
                  >${g.description ? html` <span class="muted">— ${linkify(g.description)}</span>` : nothing}
                  <span class="badge ${g.failed ? 'deny' : 'ok'}"
                    >${g.failed ? t('{f} of {n} failed', { f: g.failed, n: g.results.length }) : t('{n} passed', { n: g.results.length })}</span
                  >
                </td>
              </tr>`,
              ...g.results.map((r) => this._resultRow(r, rep.results.indexOf(r), g)),
            ])}
          </tbody>
        </table>
      </div>`;
  }

  _exportedCard() {
    return html`<section class="card" data-testid="test-scenarios-exported">
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
    </section>`;
  }
}
customElements.define('pgc-scenarios', PgcScenarios);

// Free text with its links clickable: markdown-style [JIRA-99](https://…)
// and bare http(s) URLs; everything else stays text. Only http(s) targets
// become links — a javascript: or data: target stays text — and every link
// is external by nature: a new tab, no opener, no referrer, nofollow.
export function linkify(text) {
  const parts = [];
  const re = /\[([^\]\n]+)\]\((https?:\/\/[^\s)]+)\)|https?:\/\/[^\s<>"')\]]+/g;
  const str = String(text ?? '');
  let last = 0;
  for (const m of str.matchAll(re)) {
    if (m.index > last) parts.push(str.slice(last, m.index));
    const [label, href] = m[1] ? [m[1], m[2]] : [m[0], m[0]];
    parts.push(
      html`<a href=${href} title=${href} target="_blank" rel="noopener noreferrer nofollow">${label}</a>`,
    );
    last = m.index + m[0].length;
  }
  if (last < str.length) parts.push(str.slice(last));
  return parts;
}

// A YAML plain scalar when safe, else double-quoted (JSON strings are valid YAML).
export function yamlScalar(s) {
  s = String(s);
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

function countTest(tc) {
  let n = 0;
  for (const c of tc.check ?? []) n += Object.keys(c.assertions ?? {}).length;
  for (const l of tc.list_objects ?? []) n += Object.keys(l.assertions ?? {}).length;
  for (const l of tc.list_subjects ?? []) n += Object.keys(l.assertions ?? {}).length;
  n += (tc.list_actions ?? []).length;
  n += (tc.explain ?? []).length;
  return n;
}

function countCases(fx) {
  return (fx.tests ?? []).reduce((n, tc) => n + countTest(tc), 0);
}

// The fixture structure (as the server parses it) rendered as
// tests.authz.yaml — the harness's edits become text through this. Flow
// style for assertions, notes, lists and JSON contexts (JSON is valid
// YAML); descriptions as quoted strings.
export function fixtureYAML(fx) {
  const out = [];
  const str = (s) => JSON.stringify(String(s));
  if (fx.model_file) out.push(`model_file: ${yamlScalar(fx.model_file)}`);
  if (fx.model) out.push(`model: ${yamlScalar(fx.model)}`);
  if (fx.store) out.push(`store: ${yamlScalar(fx.store)}`);
  const tuple = (x, indent) => {
    const p = ' '.repeat(indent);
    out.push(`${p}- user: ${yamlScalar(x.user)}`);
    out.push(`${p}  relation: ${yamlScalar(x.relation)}`);
    out.push(`${p}  object: ${yamlScalar(x.object)}`);
    if (x.condition) out.push(`${p}  condition: ${yamlScalar(x.condition)}`);
    if (x.context) out.push(`${p}  context: ${JSON.stringify(x.context)}`);
    if (x.expires_at) out.push(`${p}  expires_at: ${yamlScalar(x.expires_at)}`);
  };
  if (fx.tuples?.length) {
    out.push('tuples:');
    for (const x of fx.tuples) tuple(x, 2);
  }
  out.push('tests:');
  for (const tc of fx.tests ?? []) {
    out.push(`  - name: ${yamlScalar(tc.name ?? '')}`);
    if (tc.description) out.push(`    description: ${str(tc.description)}`);
    if (tc.check?.length) {
      out.push('    check:');
      for (const c of tc.check) {
        out.push(`      - user: ${yamlScalar(c.user)}`);
        out.push(`        object: ${yamlScalar(c.object)}`);
        out.push(`        assertions: ${flowMap(c.assertions ?? {})}`);
        if (c.notes && Object.keys(c.notes).length)
          out.push(
            `        notes: { ${Object.entries(c.notes)
              .map(([k, v]) => `${yamlScalar(k)}: ${str(v)}`)
              .join(', ')} }`,
          );
        if (c.description) out.push(`        description: ${str(c.description)}`);
        if (c.context) out.push(`        context: ${JSON.stringify(c.context)}`);
        if (c.contextual_tuples?.length) {
          out.push('        contextual_tuples:');
          for (const x of c.contextual_tuples) tuple(x, 10);
        }
      }
    }
    if (tc.list_objects?.length) {
      out.push('    list_objects:');
      for (const l of tc.list_objects) {
        out.push(`      - user: ${yamlScalar(l.user)}`);
        out.push(`        type: ${yamlScalar(l.type)}`);
        out.push(
          `        assertions: { ${Object.entries(l.assertions ?? {})
            .map(([k, ids]) => `${yamlScalar(k)}: [${(ids ?? []).map(yamlScalar).join(', ')}]`)
            .join(', ')} }`,
        );
        if (l.notes && Object.keys(l.notes).length)
          out.push(
            `        notes: { ${Object.entries(l.notes)
              .map(([k, v]) => `${yamlScalar(k)}: ${str(v)}`)
              .join(', ')} }`,
          );
        if (l.description) out.push(`        description: ${str(l.description)}`);
        if (l.context) out.push(`        context: ${JSON.stringify(l.context)}`);
        if (l.contextual_tuples?.length) {
          out.push('        contextual_tuples:');
          for (const x of l.contextual_tuples) tuple(x, 10);
        }
      }
    }
    if (tc.list_subjects?.length) {
      out.push('    list_subjects:');
      for (const l of tc.list_subjects) {
        out.push(`      - object: ${yamlScalar(l.object)}`);
        out.push(`        type: ${yamlScalar(l.type)}`);
        out.push(
          `        assertions: { ${Object.entries(l.assertions ?? {})
            .map(([k, ids]) => `${yamlScalar(k)}: [${(ids ?? []).map(yamlScalar).join(', ')}]`)
            .join(', ')} }`,
        );
        if (l.notes && Object.keys(l.notes).length)
          out.push(
            `        notes: { ${Object.entries(l.notes)
              .map(([k, v]) => `${yamlScalar(k)}: ${str(v)}`)
              .join(', ')} }`,
          );
        if (l.description) out.push(`        description: ${str(l.description)}`);
        if (l.context) out.push(`        context: ${JSON.stringify(l.context)}`);
        if (l.contextual_tuples?.length) {
          out.push('        contextual_tuples:');
          for (const x of l.contextual_tuples) tuple(x, 10);
        }
      }
    }
    if (tc.list_actions?.length) {
      out.push('    list_actions:');
      for (const a of tc.list_actions) {
        out.push(`      - user: ${yamlScalar(a.user)}`);
        out.push(`        object: ${yamlScalar(a.object)}`);
        out.push(`        expect: [${(a.expect ?? []).map(yamlScalar).join(', ')}]`);
        if (a.description) out.push(`        description: ${str(a.description)}`);
        if (a.context) out.push(`        context: ${JSON.stringify(a.context)}`);
        if (a.contextual_tuples?.length) {
          out.push('        contextual_tuples:');
          for (const x of a.contextual_tuples) tuple(x, 10);
        }
      }
    }
    if (tc.explain?.length) {
      out.push('    explain:');
      for (const e of tc.explain) {
        out.push(`      - user: ${yamlScalar(e.user)}`);
        out.push(`        relation: ${yamlScalar(e.relation)}`);
        out.push(`        object: ${yamlScalar(e.object)}`);
        out.push(`        expect_reasons: [${(e.expect_reasons ?? []).map(yamlScalar).join(', ')}]`);
        if (e.description) out.push(`        description: ${str(e.description)}`);
      }
    }
  }
  return out.join('\n') + '\n';
}

function flowMap(m) {
  const items = Object.entries(m).map(
    ([k, v]) => `${yamlScalar(k)}: ${v === true || v === false ? v : yamlScalar(v)}`,
  );
  return items.length ? `{ ${items.join(', ')} }` : '{}';
}

// Renders one check as a fixture case, appended under tests:.
export function checkCaseYAML({ subject, action, resource, decision, context, contextualTuples }) {
  const lines = [
    `  - name: ${yamlScalar(`${subject} ${action} ${resource}`)}`,
    `    check:`,
    `      - user: ${yamlScalar(subject)}`,
    `        object: ${yamlScalar(resource)}`,
    `        assertions: { ${yamlScalar(action)}: ${decision ? 'true' : 'false'} }`,
  ];
  if (context && Object.keys(context).length) lines.push(`        context: ${JSON.stringify(context)}`);
  lines.push(...contextualTuplesYAML(contextualTuples));
  return lines.join('\n') + '\n';
}

// The contextual_tuples: block of a case (one flow map per tuple), at the
// case's key indentation; nothing for none.
export function contextualTuplesYAML(tuples, indent = 8) {
  if (!tuples?.length) return [];
  const p = ' '.repeat(indent);
  return [
    `${p}contextual_tuples:`,
    ...tuples.map(
      (x) =>
        `${p}  - { user: ${yamlScalar(x.user)}, relation: ${yamlScalar(x.relation)}, object: ${yamlScalar(x.object)} }`,
    ),
  ];
}

// Parses contextual tuples typed one per line — "subject relation object"
// in OpenFGA notation (user:anne viewer doc:x; a userset subject as
// group:eng#member); blank lines and # comments are skipped. Throws with
// the 1-based line of the first malformed one.
export function parseTupleLines(text) {
  const out = [];
  const lines = String(text ?? '').split('\n');
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i].trim();
    if (!l || l.startsWith('#')) continue;
    const parts = l.split(/\s+/);
    if (parts.length !== 3 || !parts[0].includes(':') || !parts[2].includes(':')) {
      throw new Error(
        t('Contextual tuple on line {n} must read "subject relation object", e.g. user:anne viewer doc:x', {
          n: i + 1,
        }),
      );
    }
    out.push({ user: parts[0], relation: parts[1], object: parts[2] });
  }
  return out;
}

// Renders a list_objects result as a fixture case.
export function listCaseYAML({ subject, action, type, ids, context, contextualTuples }) {
  const lines = [
    `  - name: ${yamlScalar(`${subject} ${action} ${type} objects`)}`,
    `    list_objects:`,
    `      - user: ${yamlScalar(subject)}`,
    `        type: ${yamlScalar(type)}`,
    `        assertions: { ${yamlScalar(action)}: [${ids.map((id) => yamlScalar(`${type}:${id}`)).join(', ')}] }`,
  ];
  if (context && Object.keys(context).length) lines.push(`        context: ${JSON.stringify(context)}`);
  lines.push(...contextualTuplesYAML(contextualTuples));
  return lines.join('\n') + '\n';
}

// The 1-based editor line of one assertion inside its test's block: for a
// check, the assertions line (or the relation's own line in block style)
// of the case with that subject and object; for list_objects likewise by
// subject and type; for explain, the case's expect_reasons line. 0 when
// not found (the caller falls back to the test's name line).
export function assertionLine(yaml, r) {
  if (!r || r.test == null || !r.kind) return 0;
  const starts = scenarioLines(yaml);
  const from = starts[r.test];
  if (!from) return 0;
  const lines = yaml.split('\n');
  let to = starts[r.test + 1] ? starts[r.test + 1] - 1 : lines.length;
  for (let i = from; i < to; i++) if (/^[A-Za-z_]/.test(lines[i])) to = i; // another top-level key ends the tests
  const unq = (v) => v.trim().replace(/^(["'])(.*)\1$/, '$2');
  const field = (l, key) => {
    const m = new RegExp(`^\\s*(?:-\\s+)?${key}:\\s*(.*?)\\s*(?:#.*)?$`).exec(l);
    return m ? unq(m[1]) : null;
  };
  // the case's identifying pair per kind: the first field opens a case
  // ("- user:" / "- object:"), the second narrows it
  const first = r.kind === 'list_subjects' ? 'object' : 'user';
  const second = r.kind === 'list_objects' || r.kind === 'list_subjects' ? 'type' : 'object';
  const wantFirst = r.kind === 'list_subjects' ? r.object : r.user;
  const wantSecond = r.kind === 'list_subjects' ? r.user : r.object;
  let section = '';
  let a = null;
  let b = null;
  for (let i = from; i < to; i++) {
    const l = lines[i];
    const sec = /^\s{4}(check|list_objects|list_subjects|list_actions|explain):\s*$/.exec(l);
    if (sec) {
      section = sec[1];
      a = b = null;
      continue;
    }
    const f = field(l, first);
    if (f !== null && /^\s*-\s+/.test(l)) {
      a = f;
      b = null;
    }
    const g = field(l, second);
    if (g !== null) b = g;
    if (section !== r.kind || a !== wantFirst || b !== wantSecond) continue;
    if (r.kind === 'list_actions') {
      if (/^\s*expect:/.test(l)) return i + 1;
      continue;
    }
    if (r.kind === 'explain') {
      if (
        /^\s*expect_reasons:/.test(l) &&
        field(
          lines
            .slice(from, i + 1)
            .reverse()
            .find((x) => /^\s*relation:/.test(x)) ?? '',
          'relation',
        ) === r.relation
      )
        return i + 1;
      continue;
    }
    if (/^\s*assertions:/.test(l)) {
      if (new RegExp(`[{,\\s]${r.relation}\\s*:`).test(l)) return i + 1;
      // block style: the relation on one of the following, deeper lines
      const indent = l.search(/\S/);
      for (let j = i + 1; j < to && lines[j].search(/\S/) > indent; j++)
        if (new RegExp(`^\\s*${r.relation}\\s*:`).test(lines[j])) return j + 1;
      return i + 1;
    }
  }
  return 0;
}

// Renders a list_actions result as a fixture case: exactly these actions.
export function listActionsCaseYAML({ subject, resource, actions, context, contextualTuples }) {
  const lines = [
    `  - name: ${yamlScalar(`what ${subject} may do on ${resource}`)}`,
    `    list_actions:`,
    `      - user: ${yamlScalar(subject)}`,
    `        object: ${yamlScalar(resource)}`,
    `        expect: [${actions.map(yamlScalar).join(', ')}]`,
  ];
  if (context && Object.keys(context).length) lines.push(`        context: ${JSON.stringify(context)}`);
  lines.push(...contextualTuplesYAML(contextualTuples));
  return lines.join('\n') + '\n';
}

// Renders a list_subjects result as a fixture case.
export function listSubjectsCaseYAML({ object, action, type, ids, context, contextualTuples }) {
  const lines = [
    `  - name: ${yamlScalar(`${type} ${action} on ${object}`)}`,
    `    list_subjects:`,
    `      - object: ${yamlScalar(object)}`,
    `        type: ${yamlScalar(type)}`,
    `        assertions: { ${yamlScalar(action)}: [${ids.map((id) => yamlScalar(`${type}:${id}`)).join(', ')}] }`,
  ];
  if (context && Object.keys(context).length) lines.push(`        context: ${JSON.stringify(context)}`);
  lines.push(...contextualTuplesYAML(contextualTuples));
  return lines.join('\n') + '\n';
}

// The 1-based editor lines of every "- name:" entry under tests:, in order.
export function scenarioLines(yaml) {
  const out = [];
  const lines = yaml.split('\n');
  let inTests = false;
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    if (/^tests:\s*(#.*)?$/.test(l)) {
      inTests = true;
      continue;
    }
    if (inTests && /^[A-Za-z_]/.test(l)) inTests = false; // another top-level key
    if (inTests && /^\s*-\s+name:/.test(l)) out.push(i + 1);
  }
  return out;
}

// The 1-based editor line of the n-th (0-based) "- name:" entry under
// tests:, 0 when the text has no such entry.
export function scenarioLine(yaml, n) {
  const lines = yaml.split('\n');
  let inTests = false;
  let seen = -1;
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    if (/^tests:\s*(#.*)?$/.test(l)) {
      inTests = true;
      continue;
    }
    if (inTests && /^[A-Za-z_]/.test(l)) inTests = false; // another top-level key
    if (inTests && /^\s*-\s+name:/.test(l) && ++seen === n) return i + 1;
  }
  return 0;
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
