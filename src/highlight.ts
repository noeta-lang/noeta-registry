// Noeta registry — server-side syntax highlighting for Noeta code.
//
// VENDORED from the canonical source in the noeta-theme repo:
//   noeta-theme/js/highlight.js  (/home/niklas/Code/noeta-theme/js/highlight.js)
// This is a faithful TypeScript port — keep the rules, keyword set, and `tok-*` classes in
// lockstep with that file so registry pages and docs.noeta.dev color code identically (the
// theme file carries the mirror note; web.test.ts pins the exact spans as a drift tripwire).
//
// Not a real grammar — an ordered regex alternation good enough for curated samples and doc
// snippets, emitting <span class="tok-*"> for layout()'s inlined CSS to color. It HTML-escapes
// its input internally, so callers must pass RAW (un-escaped) source text — feeding it
// pre-escaped text would double-escape.

const esc = (s: string): string =>
  s.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;");

const KEYWORDS = new Set([
  "fn", "return", "if", "else", "for", "in", "match", "enum", "struct", "class",
  "use", "mut", "async", "await", "concurrent", "true", "false", "void",
]);

/* Order matters: earlier rules win. `tag` handles @html markup lines. */
const RULES: { re: RegExp; cls: string | null }[] = [
  { re: /\/\/[^\n]*/y, cls: "tok-cmt" },
  { re: /"(?:[^"\\]|\\.)*"/y, cls: "tok-str" },
  { re: /@[a-z_][a-zA-Z0-9_]*/y, cls: "tok-tier" },
  { re: /<\/?[a-zA-Z][^<>\n]*>/y, cls: "tok-tag" },
  { re: /\b\d[\d_]*(?:\.\d+)?\b/y, cls: "tok-num" },
  { re: /\b[A-Z][a-zA-Z0-9_]*\b/y, cls: "tok-type" },
  { re: /\b[a-z_][a-zA-Z0-9_]*(?=\s*\()/y, cls: "tok-fn" },
  { re: /\b[a-z_][a-zA-Z0-9_]*\b/y, cls: null }, // plain identifier (or keyword)
];

/** Inside a string literal, light up `${…}` interpolation holes. */
function highlightString(raw: string): string {
  return esc(raw).replace(/\$\{[^}]*\}/g, (hole) => `<span class="tok-hole">${hole}</span>`);
}

/** Highlight Noeta source into HTML spans (`tok-*` classes, colored by the layout's CSS). */
export function highlightNoeta(code: string): string {
  let out = "";
  let i = 0;
  outer: while (i < code.length) {
    for (const rule of RULES) {
      rule.re.lastIndex = i;
      const m = rule.re.exec(code);
      if (!m) continue;
      const text = m[0];
      if (rule.cls === "tok-str") {
        out += `<span class="tok-str">${highlightString(text)}</span>`;
      } else if (rule.cls === null) {
        out += KEYWORDS.has(text) ? `<span class="tok-kw">${text}</span>` : esc(text);
      } else {
        out += `<span class="${rule.cls}">${esc(text)}</span>`;
      }
      i += text.length;
      continue outer;
    }
    out += esc(code[i]);
    i += 1;
  }
  return out;
}
