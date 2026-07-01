// Convert a Cytoscape instance to Graphviz DOT text (for copy-to-clipboard).
// Reads each element's *computed* style so the DOT roughly mirrors what's on
// screen, independent of the component's own class scheme.

const rgbToHex = (c) => {
  const m = /(\d+)\D+(\d+)\D+(\d+)/.exec(c || '');
  if (!m) return (c || '').startsWith('#') ? c : '#607d8b';
  const h = (n) => (+n).toString(16).padStart(2, '0');
  return '#' + h(m[1]) + h(m[2]) + h(m[3]);
};

// Readable text colour for a given fill (luminance threshold).
const fontFor = (hex) => {
  const m = /^#(..)(..)(..)$/.exec(hex);
  if (!m) return 'black';
  const [r, g, b] = [1, 2, 3].map((i) => parseInt(m[i], 16));
  return (0.299 * r + 0.587 * g + 0.114 * b) / 255 > 0.6 ? 'black' : 'white';
};

const esc = (s) => String(s ?? '')
  .replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n');

export function cyToDot(cy, { name = 'g', rankdir = 'TB' } = {}) {
  // Only export what's on screen (respects the type graph's hide filters).
  if (!cy || cy.elements(':visible').length === 0) return '';
  const lines = [
    `digraph ${name} {`,
    `  rankdir=${rankdir};`,
    '  node [shape=box, style="rounded,filled", fontname="Helvetica"];',
    '  edge [fontname="Helvetica"];',
  ];
  cy.nodes(':visible').forEach((n) => {
    const d = n.data();
    const fill = rgbToHex(n.style('background-color'));
    lines.push(`  "${esc(d.id)}" [label="${esc(d.label ?? d.id)}", fillcolor="${fill}", fontcolor="${fontFor(fill)}"];`);
  });
  cy.edges(':visible').forEach((e) => {
    const d = e.data();
    const color = rgbToHex(e.style('line-color'));
    const label = d.label ? `label="${esc(d.label)}", ` : '';
    lines.push(`  "${esc(d.source)}" -> "${esc(d.target)}" [${label}color="${color}"];`);
  });
  lines.push('}');
  return lines.join('\n');
}
