import { css } from 'lit';
import cytoscape from 'cytoscape';
import dagre from 'cytoscape-dagre';
import { PgGraph } from './pg-graph.js';

cytoscape.use(dagre);

// Visualizes the explain_access resolution tree as a directed graph. Cytoscape
// can't read CSS custom properties, so the palette literals mirror the tokens.
const ALLOW = '#1a7f37';   // a relation that grants (green)
const DENY = '#cf222e';    // explored but did not grant (red)
const ENTITY = '#607d8b';  // neutral step
const QUERY = '#0969da';   // the requested access (root) — blue outline
const GRANT = '#d4a72c';   // the direct tuple that ultimately grants — gold outline
const COND = '#8250df';    // a condition gates this step — purple dashed outline

export class PgAccessGraph extends PgGraph {
  static properties = { node: { attribute: false }, allowedOnly: { type: Boolean } };

  static styles = [PgGraph.styles, css`:host { min-height: 320px; }`];

  constructor() {
    super();
    this.allowedOnly = true;
  }

  graphName() { return 'access'; }
  // Keep node text readable: never fit below zoom 1 (text would shrink) or above 2.
  fitPadding() { return 40; }
  minReadableZoom() { return 1; }

  // Render the resolution *tree*: one node per step (a "<relation> on <object>"
  // sub-goal), parent->child edge labelled with the rule that links them
  // (`via <tupleset>` for a TTU, `rewrite` for a computed relation, `direct` for
  // a tuple lookup). The subject is constant across the trace, so the chain of
  // objects — not the subject — is what explains why access is granted. The root
  // (the requested access) and the granting leaf are marked.
  buildElements() {
    const root = this.node;
    if (!root) return [];
    // "Access path" (allowedOnly) shows only successful access paths — every denied
    // branch is pruned, so on a DENY there's simply nothing to show. "Full tree"
    // keeps the dead-ends (dashed/red) so you can see everything explored.
    const prune = this.allowedOnly;
    // No successful path (denied) in Access-path mode → just show the target, red.
    if (prune && !(root.allowed === true || root.result === true)) {
      return [{ data: { id: 'deny', label: root.object || '?' }, classes: 'deny' }];
    }
    const ruleLabel = (n) => {
      if (n.rule_type === 'ttu') { const m = /via (\w+)/.exec(n.detail || ''); return m ? 'via\n' + m[1] : 'ttu'; }
      if (n.rule_type === 'computed') return 'rewrite';
      if (n.rule_type === 'direct') {
        return (n.reason === 'object_wildcard_tuple' || n.reason === 'wildcard_tuple') ? 'wildcard' : 'direct';
      }
      return n.reason || '';
    };
    const els = [];
    // Identity of a trace step: the sub-goal (subject|relation|object), how it was
    // evaluated (rule_type|reason|condition), AND its outcome. The outcome matters
    // because a union (e.g. `accountant OR payroll_clerk`) emits the same sub-goal
    // twice as siblings — one denied, one granting; without the outcome the denied
    // one would claim the key and hide the granting subtree in the full tree. Only
    // truly identical converging steps merge (keeping the DAG for diamond graphs).
    const stepKey = (n) => `${n.subject}|${n.relation}|${n.object}|${n.rule_type || ''}|${n.reason || ''}|${n.condition_name || ''}|${n.allowed === true || n.result === true}`;
    const seen = new Map();    // stepKey → node id (dedupe only identical steps)
    const edgeSeen = new Set(); // source|target|label (dedupe repeated edges)
    const edgeEls = [];         // collected separately to spread parallel labels
    let i = 0, e = 0;
    const walk = (n, parentId, isRoot) => {
      const ok = n.allowed === true || n.result === true;
      if (prune && !ok) return;
      const key = stepKey(n);
      const seenId = isRoot ? undefined : seen.get(key);
      const id = seenId ?? ('n' + i++);
      // Edge from the parent — drawn even for a repeated sub-goal, so the graph shows
      // the convergence (a DAG) rather than duplicating the node + subtree.
      if (parentId != null) {
        const rl = ruleLabel(n);
        const ek = parentId + '|' + id + '|' + rl;
        if (!edgeSeen.has(ek)) {
          edgeSeen.add(ek);
          edgeEls.push({ data: { id: 'e' + e++, source: parentId, target: id, label: rl, tmy: 0, cpd: 0 },
            classes: ok ? 'allow' : 'deny' });
        }
      }
      if (seenId != null) return; // node (and its subtree) already emitted
      if (!isRoot) seen.set(key, id);
      const isLeaf = !isRoot && (!n.children || n.children.length === 0);
      const isGrant = ok && isLeaf;
      const isDenyLeaf = !ok && isLeaf;
      // A wildcard match grants via "type:*", not the concrete id — show the tuple
      // that actually granted it (object wildcard → object:*, subject wildcard → subject:*).
      const wObj = n.reason === 'object_wildcard_tuple' ? (n.object || '').replace(/:[^:]*$/, ':*') : n.object;
      const wSubj = n.reason === 'wildcard_tuple' ? (n.subject || '').replace(/:[^:]*$/, ':*') : n.subject;
      const lines = isGrant
        ? [`${n.relation} ✓`, wObj, wSubj].filter(Boolean)
        : isDenyLeaf
          ? [`${n.relation} ✗`, n.object, n.subject].filter(Boolean)
          : [n.relation, n.object].filter(Boolean);
      let arr = lines.length ? lines : [n.detail || n.subject || '?'];
      // A condition gates this step — show it (granted-if vs denied-by).
      if (n.condition_name) arr = [...arr, `⚖ ${ok ? 'if' : '✗'} ${n.condition_name}`];
      const label = arr.join('\n');
      const cls = [ok ? 'allow' : 'deny'];
      if (isRoot) cls.push('root');
      if (isGrant) cls.push('grant');
      if (n.condition_name) cls.push('conditional');
      els.push({ data: { id, label, detail: n.detail || '' }, classes: cls.join(' ') });
      (n.children || []).forEach((c) => walk(c, id, false));
    };
    walk(root, null, true);
    // Spread the labels of parallel edges (same node pair) apart horizontally so
    // they don't overlap on top of each other.
    const byPair = new Map();
    for (const ed of edgeEls) {
      const k = [ed.data.source, ed.data.target].sort().join('|');
      (byPair.get(k) || byPair.set(k, []).get(k)).push(ed);
    }
    for (const grp of byPair.values()) {
      if (grp.length < 2) continue;
      // Fan the parallel lines apart (cpd) and stagger their labels vertically (tmy).
      grp.forEach((ed, idx) => {
        const off = idx - (grp.length - 1) / 2;
        ed.data.cpd = Math.round(off * 75);
        ed.data.tmy = Math.round(off * 46);
      });
    }
    return [...els, ...edgeEls];
  }

  // Hierarchical DAG layout: ranks the root→…→grant flow top-to-bottom and respects
  // each node's box, so wide label nodes never overlap. Compact for the short
  // Access-path chain; roomier for the denser Full tree.
  layoutOptions() {
    const rankSep = this.allowedOnly ? 55 : 95;
    return { name: 'dagre', rankDir: 'TB', nodeSep: 28, edgeSep: 12, rankSep, padding: 20, fit: false };
  }

  cyStyle() {
    return [
      { selector: 'node', style: {
        label: 'data(label)', 'font-size': 14, 'text-wrap': 'wrap', 'text-max-width': 220,
        'text-valign': 'center', 'text-halign': 'center', color: '#fff',
        'background-color': ENTITY, shape: 'round-rectangle',
        width: 'label', height: 'label', padding: '10px',
      } },
      // Intermediate steps keep the neutral base fill; dead-ends go red.
      { selector: 'node.deny', style: { 'background-color': DENY } },
      // The requested access (root, blue outline) and the granting tuple (leaf,
      // green fill + gold outline) stand out from intermediate steps.
      { selector: 'node.root', style: { 'background-color': QUERY, 'border-width': 4, 'border-color': QUERY, shape: 'round-rectangle' } },
      { selector: 'node.grant', style: { 'background-color': ALLOW, 'border-width': 4, 'border-color': GRANT, shape: 'ellipse' } },
      // A condition gates this step (granted-if / denied-by): purple dashed ring.
      { selector: 'node.conditional', style: { 'border-width': 4, 'border-color': COND, 'border-style': 'dashed' } },
      { selector: 'edge', style: {
        'curve-style': 'unbundled-bezier', 'target-arrow-shape': 'triangle',
        'control-point-distances': 'data(cpd)', 'control-point-weights': 0.5,
        'line-color': '#b1b8c0', 'target-arrow-color': '#b1b8c0', width: 2,
        label: 'data(label)', 'font-size': 12, 'text-rotation': 'none', 'text-wrap': 'wrap',
        'text-margin-y': 'data(tmy)',
        color: '#57606a', 'text-background-color': '#ffffff', 'text-background-opacity': 0.9,
        'text-background-shape': 'round-rectangle', 'text-background-padding': '3px',
      } },
      { selector: 'edge.allow', style: { 'line-color': ALLOW, 'target-arrow-color': ALLOW, color: ALLOW, width: 3.5 } },
      { selector: 'edge.deny', style: { 'line-color': DENY, 'target-arrow-color': DENY, color: DENY,
        'line-style': 'dashed', width: 2 } },
    ];
  }

  onNodeTap(e) {
    this.dispatchEvent(new CustomEvent('node-selected', { detail: e.target.data(), bubbles: true, composed: true }));
  }

  updated(changed) {
    if ((changed.has('node') || changed.has('allowedOnly')) && this._cy) this._rebuild();
  }
}
customElements.define('pg-access-graph', PgAccessGraph);
