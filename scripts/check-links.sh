#!/usr/bin/env bash
#
# Markdown link checker: every relative link and every `#anchor` in the
# repository's *.md files must resolve (GitHub heading slug rules, plus
# explicit `<a id="…">` / `<a name="…">` anchors). External URLs are not
# fetched. Exit 1 with one line per broken link.
#
#   ./scripts/check-links.sh            # whole repo
#   ./scripts/check-links.sh README.md docs/API.md
#
# Runs in CI (main job) and in scripts/pre-release.sh so a doc move can never
# leave a dangling reference behind.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
python3 - "$@" <<'PY'
import os, re, sys, unicodedata

ROOT = os.getcwd()
SKIP_DIRS = {'.git', 'node_modules', 'scratch', 'target', 'dist', 'build', '.venv', 'vendor'}

def md_files(args):
    if args:
        return [os.path.normpath(a) for a in args]
    out = []
    for d, dirs, files in os.walk(ROOT):
        dirs[:] = [x for x in dirs if x not in SKIP_DIRS]
        for f in files:
            if f.endswith('.md'):
                out.append(os.path.relpath(os.path.join(d, f), ROOT))
    return sorted(out)

def slug(text):
    # GitHub: strip markdown emphasis/code/links, lowercase, drop punctuation
    # except hyphens and spaces, spaces -> hyphens.
    text = re.sub(r'\[([^\]]*)\]\([^)]*\)', r'\1', text)
    text = re.sub(r'[`*~]', '', text)   # GitHub keeps underscores in slugs
    text = unicodedata.normalize('NFKD', text).lower().strip()
    text = re.sub(r'[^\w\- ]', '', text)
    return text.replace(' ', '-')

def anchors_of(path):
    seen = {}
    ids = set()
    try:
        lines = open(path, encoding='utf-8').read().split('\n')
    except OSError:
        return ids
    fence = False
    for line in lines:
        if line.startswith('```') or line.startswith('~~~'):
            fence = not fence
            continue
        if fence:
            continue
        m = re.match(r'^(#{1,6})\s+(.*?)\s*#*\s*$', line)
        if m:
            s = slug(m.group(2))
            n = seen.get(s, 0)
            seen[s] = n + 1
            ids.add(s if n == 0 else f'{s}-{n}')
        for a in re.findall(r'<a\s+(?:id|name)="([^"]+)"', line):
            ids.add(a)
    return ids

LINK_RE = re.compile(r'(?<!\!)\[[^\]]*\]\(([^)\s]+)(?:\s+"[^"]*")?\)')
broken = []
anchor_cache = {}

def anchors(path):
    if path not in anchor_cache:
        anchor_cache[path] = anchors_of(path)
    return anchor_cache[path]

for f in md_files(sys.argv[1:]):
    try:
        text = open(f, encoding='utf-8').read()
    except OSError:
        broken.append(f'{f}: cannot read'); continue
    fence = False
    for ln, line in enumerate(text.split('\n'), 1):
        # skip fenced code blocks (example links in code are not checked),
        # keeping line numbers intact
        if line.startswith('```') or line.startswith('~~~'):
            fence = not fence
            continue
        if fence:
            continue
        for target in LINK_RE.findall(line):
            if re.match(r'^[a-z][a-z0-9+.-]*:', target):   # http:, mailto:, etc.
                continue
            path_part, _, frag = target.partition('#')
            if path_part == '':
                tgt = f
            else:
                tgt = os.path.normpath(os.path.join(os.path.dirname(f), path_part))
                if not os.path.exists(tgt):
                    broken.append(f'{f}:{ln}: missing file {target}'); continue
                if os.path.isdir(tgt):
                    if frag: broken.append(f'{f}:{ln}: anchor on a directory {target}')
                    continue
            if frag and tgt.endswith('.md') and frag not in anchors(tgt):
                broken.append(f'{f}:{ln}: missing anchor {target}')

for b in broken:
    print(b)
print(f'check-links: {len(broken)} broken link(s)', file=sys.stderr)
sys.exit(1 if broken else 0)
PY
