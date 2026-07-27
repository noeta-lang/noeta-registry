// Noeta registry — server-side syntax highlighting via shiki, using the CANONICAL Noeta
// TextMate grammar (synced into syntaxes/ by scripts/sync-grammars.mjs, imported as JSON at
// bundle time). This replaced the vendored regex tokenizers (src/highlight.ts /
// highlight-toml.ts) so the registry colors code with the exact same grammar as the editors
// and docs.noeta.dev — including tier-language injection (@sql{…} bodies get real SQL tokens).
//
// Engine: @shikijs/engine-javascript (pure JS, no WASM — workerd-friendly), with fine-grained
// language imports only, never the full shiki bundle. The precompiled-grammar variant
// (@shikijs/langs-precompiled + the raw JS engine) was evaluated and NOT chosen: the noeta and
// tier-injection grammars are custom TextMate JSON that must be compiled at runtime anyway, so
// the oniguruma-to-es translator cannot be dropped from the bundle — precompilation would only
// shave first-use compile time of the stock grammars while splitting the language set across
// two mechanisms. The render cache makes that saving irrelevant (see the CPU note below).
//
// CPU budget: a Workers request gets ~10ms CPU on the free tier — the reason the old regex
// tokenizers existed. Shiki's cold path (grammar compilation + tokenization of a README-sized
// input) costs on the order of tens to a few hundred ms, far past that budget. The neutralizer
// is the D1 render cache (src/render-cache.ts): package versions are IMMUTABLE, so each
// (version, fragment) pair pays the shiki cost at most once — every later view is a D1 row
// read. The highlighter itself is created lazily (module-level promise) and only on a cache
// miss, so cache-hit requests never touch shiki at all.
//
// Theme: not a pre-baked color theme — TextMate scopes map to the page's --syn-* CSS
// variables (ported from noeta-docs' remark-noeta-code.mjs). Shiki passes `var(…)` foregrounds
// straight through to inline style attributes, and the variables flip with
// prefers-color-scheme in layout()'s stylesheet, so one theme covers light AND dark.

import { createHighlighterCore, type HighlighterCore } from "@shikijs/core";
import { createJavaScriptRegexEngine } from "@shikijs/engine-javascript";
import type { LanguageRegistration, ThemeRegistration } from "@shikijs/types";

// The synced canonical grammars (gitignored; scripts/sync-grammars.mjs populates them).
import noetaGrammar from "../syntaxes/noeta.tmLanguage.json";
import tierGrammar from "../syntaxes/tier-languages.tmLanguage.json";

// Fine-grained language imports. Each module is the grammar plus its embedded dependencies
// (e.g. html brings javascript+css), so the bundle carries exactly these and their closures.
import langCss from "@shikijs/langs/css";
import langGraphql from "@shikijs/langs/graphql";
import langHtml from "@shikijs/langs/html";
import langJavascript from "@shikijs/langs/javascript";
import langJson from "@shikijs/langs/json";
import langJsonc from "@shikijs/langs/jsonc";
import langMarkdown from "@shikijs/langs/markdown";
import langPython from "@shikijs/langs/python";
import langRust from "@shikijs/langs/rust";
import langShellscript from "@shikijs/langs/shellscript";
import langShellsession from "@shikijs/langs/shellsession";
import langSparql from "@shikijs/langs/sparql";
import langSql from "@shikijs/langs/sql";
import langToml from "@shikijs/langs/toml";
import langXml from "@shikijs/langs/xml";
import langYaml from "@shikijs/langs/yaml";

/**
 * The bundled languages the highlighter registers:
 * - the languages the tier-languages injection grammar embeds (mirroring what noeta-docs
 *   registers, so `@sql{…}`/`@html{…}`/… bodies inside a noeta block resolve): sql, html, css,
 *   json, yaml, xml, graphql, markdown, javascript, python, shellscript, toml, sparql;
 * - plus the fence languages registry pages serve directly: jsonc, rust, and shellsession
 *   (the `console` alias for prompt-prefixed shell transcripts).
 * Every module already includes its embedded dependencies (html → javascript+css, …).
 */
const BUNDLED_LANGS: LanguageRegistration[][] = [
  langCss,
  langGraphql,
  langHtml,
  langJavascript,
  langJson,
  langJsonc,
  langMarkdown,
  langPython,
  langRust,
  langShellscript,
  langShellsession,
  langSparql,
  langSql,
  langToml,
  langXml,
  langYaml,
];

/** Ink & Signal as a shiki theme: scope → the layout's --syn-* CSS variables (ported verbatim
 *  from noeta-docs' remark-noeta-code.mjs, so all four noeta.dev properties color identically). */
const inkSignal: ThemeRegistration = {
  name: "noeta-ink-signal",
  type: "dark",
  colors: {
    "editor.foreground": "var(--text-0)",
    "editor.background": "transparent",
  },
  settings: [
    { settings: { foreground: "var(--text-0)", background: "transparent" } },
    { scope: "comment", settings: { foreground: "var(--syn-comment)", fontStyle: "italic" } },
    { scope: ["string", "punctuation.definition.string", "constant.character.escape"], settings: { foreground: "var(--syn-string)" } },
    { scope: "constant.numeric", settings: { foreground: "var(--syn-number)" } },
    { scope: ["keyword", "storage", "constant.language", "variable.language"], settings: { foreground: "var(--syn-keyword)" } },
    // Symbolic operators stay plain (as the site always rendered them);
    // word operators (`is`, `and`, …) read as keywords.
    { scope: "keyword.operator", settings: { foreground: "var(--text-0)" } },
    { scope: "keyword.operator.word", settings: { foreground: "var(--syn-keyword)" } },
    { scope: ["entity.name.type", "support.type", "support.class"], settings: { foreground: "var(--syn-type)" } },
    { scope: ["entity.name.function", "support.function"], settings: { foreground: "var(--syn-fn)" } },
    // @directives and @tier{…} openers — the tok-tier accent.
    { scope: "entity.name.function.decorator", settings: { foreground: "var(--accent-2-bright)" } },
    { scope: "entity.name.tag", settings: { foreground: "var(--syn-tag)" } },
    { scope: "entity.other.attribute-name", settings: { foreground: "var(--syn-string)" } },
    // ${…} interpolation/hole delimiters — the tok-hole accent.
    { scope: ["punctuation.definition.template-expression", "punctuation.section.embedded"], settings: { foreground: "var(--syn-hole)" } },
    // Markdown bodies inside @doc/text tiers.
    { scope: "markup.heading", settings: { foreground: "var(--syn-keyword)", fontStyle: "bold" } },
    { scope: "markup.bold", settings: { fontStyle: "bold" } },
    { scope: "markup.italic", settings: { fontStyle: "italic" } },
    { scope: "markup.inline.raw", settings: { foreground: "var(--syn-string)" } },
  ],
};

/**
 * Info-string → registered language name, for every language this highlighter knows (names and
 * aliases, all lowercase). Built from the registrations themselves so the set can never drift
 * from what is actually loaded; `resolveLang` is also the safety gate that keeps a
 * publisher-supplied info string from reaching a class attribute (only these known,
 * charset-safe names ever come back).
 */
const LANG_BY_ALIAS: ReadonlyMap<string, string> = (() => {
  const map = new Map<string, string>();
  for (const mod of BUNDLED_LANGS) {
    for (const reg of mod) {
      map.set(reg.name.toLowerCase(), reg.name);
      for (const alias of reg.aliases ?? []) map.set(alias.toLowerCase(), reg.name);
    }
  }
  map.set("noeta", "noeta");
  map.set("noe", "noeta");
  return map;
})();

/** The registered language a fence info-string names, or null when shiki doesn't know it
 *  (the caller renders those plain-escaped). */
export function resolveLang(info: string): string | null {
  return LANG_BY_ALIAS.get(info.toLowerCase()) ?? null;
}

let instance: HighlighterCore | null = null;
let pending: Promise<HighlighterCore> | null = null;

/**
 * The ONE module-level highlighter, created lazily on first use and shared by every request in
 * the isolate. Callers await this before any `highlightHtml` call — in practice only on a
 * render-cache miss, so cache-hit requests never pay grammar compilation.
 */
export function ensureHighlighter(): Promise<HighlighterCore> {
  pending ??= createHighlighterCore({
    // target ES2024 (NOT auto): auto detects ES2025 RegExp modifier support and emits (?i:…)
    // groups — which workerd's V8 MISCOMPILES for multi-char alternations ((?i:(select|from))
    // fails to match "SELECT" under workerd while matching under node), silently killing e.g.
    // every SQL keyword rule. ES2024 hoists/expands case-insensitivity instead, which both
    // runtimes execute correctly. forgiving: skip the rare untranslatable pattern rather than
    // failing the whole page render.
    engine: createJavaScriptRegexEngine({ forgiving: true, target: "ES2024" }),
    themes: [inkSignal],
    langs: [
      ...BUNDLED_LANGS,
      { ...(noetaGrammar as unknown as LanguageRegistration), name: "noeta" },
      {
        ...(tierGrammar as unknown as LanguageRegistration),
        name: "noeta-tier-languages",
        injectTo: ["source.noeta"],
      },
    ],
    langAlias: { noe: "noeta" },
  }).then((h) => (instance = h));
  return pending;
}

/**
 * Highlight `code` as `lang` (a name `resolveLang` returned) into INNER code HTML — token spans
 * with inline `var(--syn-*)` colors, one `span.line` per source line, newlines as real text
 * nodes — for embedding in the caller's own `<pre><code>` (snippetHtml in web.ts, which owns
 * the copy-button wrapper). Because the markup carries the source text verbatim in text nodes,
 * the `<code>` element's textContent is exactly the raw input — the copy button's contract.
 *
 * Synchronous by design: markdown-it's fence rule cannot await, so callers `await
 * ensureHighlighter()` first (render-cache misses do; see cachedRender in web.ts). Calling it
 * before the highlighter exists is a programming error and throws.
 */
export function highlightHtml(code: string, lang: string): string {
  if (!instance) throw new Error("highlightHtml called before ensureHighlighter resolved");
  const html = instance.codeToHtml(code, { lang, theme: "noeta-ink-signal" });
  const match = /^<pre[^>]*><code[^>]*>([\s\S]*)<\/code><\/pre>\s*$/.exec(html);
  if (!match) throw new Error("unexpected shiki output shape");
  return match[1];
}
