// Internationalization. English is the source language: every UI string is
// written in English in the components and passed through t(); a dictionary
// per language maps that English text to a translation. Dictionaries are
// plain JSON (src/i18n/<lang>.json) so they can be edited and diffed without
// touching code, and an operator can override entries — or add a language —
// by serving <lang>.json files from CONSOLE_I18N_DIR (GET api/i18n/<lang>);
// those entries win over the built-in ones. Missing entries fall back to
// English, so a half-translated language still renders. Placeholders are
// {name}. The chosen language is a per-viewer convenience kept in
// localStorage; components re-render on change (see base.js).

const BUILTIN = ['en', 'de'];
const NAMES = { en: 'English', de: 'Deutsch' };

// Languages offered in the picker: the built-in ones plus any an override
// file adds (api/i18n lists them; "@language" in the file names it).
export const LANGUAGES = BUILTIN.map((code) => [code, NAMES[code]]);

const DICTS = {}; // lang → merged dictionary (built-in + overrides), once loaded
let current = 'en';
try {
  const stored = localStorage.getItem('pgc_lang');
  if (stored && /^[a-z]{2,3}(-[A-Za-z]{2,4})?$/.test(stored)) current = stored;
} catch {
  /* storage unavailable */
}

async function fetchJSON(url) {
  try {
    const res = await fetch(url, { headers: { Accept: 'application/json' } });
    if (!res.ok) return {};
    const data = await res.json();
    return data && typeof data === 'object' && !Array.isArray(data) ? data : {};
  } catch {
    return {};
  }
}

// Load a language once: the built-in file (none for English — the source
// strings are the dictionary) merged with the operator's overrides.
async function load(lang) {
  if (DICTS[lang]) return DICTS[lang];
  const [builtin, overrides] = await Promise.all([
    BUILTIN.includes(lang) && lang !== 'en' ? fetchJSON(`src/i18n/${lang}.json`) : {},
    fetchJSON(`api/i18n/${lang}`),
  ]);
  const dict = { ...builtin, ...overrides };
  delete dict['@language'];
  DICTS[lang] = dict;
  return dict;
}

function announce(lang) {
  document.documentElement.lang = lang;
  window.dispatchEvent(new CustomEvent('pgc-lang', { detail: lang }));
}

// Called once at startup (pgc-app): the current language's dictionary and
// the list of extra languages the operator provides.
export async function initI18n() {
  const [, extra] = await Promise.all([load(current), fetchJSON('api/i18n')]);
  for (const x of Array.isArray(extra) ? extra : [])
    if (x?.code && !LANGUAGES.some(([c]) => c === x.code)) LANGUAGES.push([x.code, x.name || x.code]);
  announce(current);
}

export function getLang() {
  return current;
}

export async function setLang(lang) {
  if (lang === current) return;
  await load(lang);
  current = lang;
  try {
    localStorage.setItem('pgc_lang', lang);
  } catch {
    /* storage unavailable */
  }
  announce(lang);
}

function interpolate(text, params) {
  if (!params) return text;
  return text.replace(/\{(\w+)\}/g, (m, k) => (k in params ? String(params[k]) : m));
}

// t('Remove selected…') / t('{n} tuples shown', { n: 3 })
export function t(text, params) {
  const dict = DICTS[current];
  const translated = (dict && dict[text]) || text;
  return interpolate(translated, params);
}

// Plural helper: t2('tuple', 'tuples', n) → the right form, translated.
export function t2(one, many, n) {
  return t(n === 1 ? one : many, { n });
}

document.documentElement.lang = current;
