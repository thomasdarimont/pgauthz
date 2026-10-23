import { html } from 'lit';

// Small tokenizers for the Model tab's three read views. Each returns a list
// of lit templates (one per token), so the text stays escaped and only the
// classes change; styles.css colors the classes from the theme tokens.

// Tokenize into [class, text] pairs …
function scan(text, rules) {
  const out = [];
  let i = 0;
  outer: while (i < text.length) {
    for (const [cls, re] of rules) {
      re.lastIndex = i;
      const m = re.exec(text);
      if (m && m.index === i && m[0].length) {
        out.push([cls, m[0]]);
        i += m[0].length;
        continue outer;
      }
    }
    out.push(['', text[i]]);
    i += 1;
  }
  return out;
}

// … then render line by line: every line is a <span class="line"> so CSS can
// number it (counter) without the numbers ending up in a copy of the text.
// A token spanning lines (a raw string, a block) is cut at the newlines.
function tokens(text, rules) {
  const lines = [[]];
  for (const [cls, tok] of scan(text, rules)) {
    const parts = tok.split('\n');
    parts.forEach((part, i) => {
      if (i > 0) lines.push([]);
      if (part) lines[lines.length - 1].push(cls ? html`<span class="tk-${cls}">${part}</span>` : part);
    });
  }
  return lines.map((l) => html`<span class="line">${l}</span>`);
}

// OpenFGA-style DSL as describe_model renders it:
//   type doc / relations / define can_read: viewer or owner from parent  # permission
//   # comments (conditions, gates, grant rules), [user, team#member] restrictions
const DSL = [
  ['comment', /#[^\n]*/y],
  ['keyword', /\b(?:type|relations|define|store|condition|gate)\b/y],
  ['op', /\b(?:or|and|but not|from)\b/y],
  ['name', /(?<=define\s+)[A-Za-z_][A-Za-z0-9_]*/y],
  ['typename', /(?<=type\s+)[A-Za-z_][A-Za-z0-9_]*/y],
  ['restriction', /\[[^\]\n]*\]/y],
  ['ident', /[A-Za-z_][A-Za-z0-9_]*/y],
  ['', /\s+|./y],
];

const SQL = [
  ['comment', /--[^\n]*/y],
  ['string', /'(?:[^']|'')*'/y],
  ['keyword', /\b(?:SELECT|FROM|NULL|true|false|ARRAY|AS)\b/y],
  ['fn', /\bauthz\.[A-Za-z_]+/y],
  ['param', /\bp_[A-Za-z_]+(?=\s*=>)/y],
  ['number', /\b\d+(?:\.\d+)?\b/y],
  ['ident', /[A-Za-z_][A-Za-z0-9_]*/y],
  ['', /\s+|./y],
];

const JSON_RULES = [
  ['key', /"(?:[^"\\]|\\.)*"(?=\s*:)/y],
  ['string', /"(?:[^"\\]|\\.)*"/y],
  ['number', /-?\b\d+(?:\.\d+)?(?:[eE][+-]?\d+)?\b/y],
  ['keyword', /\b(?:true|false|null)\b/y],
  ['', /\s+|./y],
];

// Rego (OPA policy): comments, strings, keywords, rule heads at line start,
// package / import paths, input./data. references, builtin calls, operators.
const REGO = [
  ['comment', /#[^\n]*/y],
  ['string', /"(?:[^"\\\n]|\\.)*"|`[^`]*`/y],
  ['typename', /(?<=\b(?:package|import)\s+)[A-Za-z_][\w.]*(?:\["[^"]*"\][\w.]*)*/y],
  ['keyword', /\b(?:package|import|default|if|in|else|not|with|as|some|every|contains|true|false|null)\b/y],
  ['param', /\b(?:input|data)\b(?:\.[A-Za-z_][\w]*|\[[^\]\n]*\])*/y],
  ['name', /(?<=^|\n)[A-Za-z_]\w*(?=\s*(?::=|=[^=]|\{|\(|\[|\s+if\b|\s+contains\b))/y],
  ['fn', /[A-Za-z_][\w.]*(?=\()/y],
  ['number', /\b\d+(?:\.\d+)?\b/y],
  ['op', /:=|==|!=|>=|<=|\|/y],
  ['ident', /[A-Za-z_]\w*/y],
  ['', /\s+|./y],
];

// YAML as the scenario fixtures use it: comments, "- " list markers, keys
// before a colon, quoted strings, numbers, booleans/null, and type:id
// references as plain scalars (left uncoloured but kept as one token).
const YAML = [
  ['comment', /#[^\n]*/y],
  ['key', /(?<=^|\n|[ \t]|- )[A-Za-z_][\w.-]*(?=\s*:(?:\s|$|\n))/y],
  ['op', /(?<=^|\n|[ \t])-(?=\s)/y],
  ['string', /"(?:[^"\\\n]|\\.)*"|'(?:[^'\n]|'')*'/y],
  ['keyword', /\b(?:true|false|null|yes|no|on|off)\b/y],
  ['number', /(?<![\w:.-])-?\d+(?:\.\d+)?(?![\w:.-])/y],
  ['ident', /[A-Za-z_*][\w:#*@/.-]*/y],
  ['', /\s+|./y],
];

export const highlightYAML = (text) => tokens(text ?? '', YAML);
export const highlightRego = (text) => tokens(text ?? '', REGO);
export const highlightDSL = (text) => tokens(text ?? '', DSL);
export const highlightSQL = (text) => tokens(text ?? '', SQL);
export const highlightJSON = (text) => tokens(text ?? '', JSON_RULES);
