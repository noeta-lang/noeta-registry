// Noeta registry — server-side syntax highlighting for TOML snippets.
//
// Registry-local (NOT vendored from noeta-theme — src/highlight.ts stays in lockstep with the
// theme; this file is free to evolve here). Same contract and style as highlightNoeta: an ordered
// regex alternation that HTML-escapes its input internally and emits <span class="tok-*"> for
// layout()'s inlined CSS, so callers must pass RAW (un-escaped) text and no new CSS variables are
// needed. It colors the TOML a registry page actually shows — the sidebar dependency line and
// README ```toml fences (manifest examples) — and deliberately skips multi-line strings: the
// tokenizer is line-based, which is all those snippets need.
//
// Token mapping (reusing the Noeta classes so both grammars share one palette):
//   [table] / [[array]] headers → tok-kw     comments  → tok-cmt
//   keys (incl. dotted, and inside inline tables) → tok-type
//   strings (basic w/ escapes, literal)      → tok-str
//   numbers (int/float/hex/oct/bin)          → tok-num
//   true/false                               → tok-kw
//   `=`, `{ }` inline-table braces, `,`      → plain (punctuation stays quiet)

const esc = (s: string): string =>
  s.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;");

/** A whole-line `[table]` / `[[array-of-tables]]` header, with optional trailing comment. */
const HEADER = /^(\s*)(\[\[?[^\]\n]*\]\]?)(\s*)(#.*)?$/;

/* Order matters: earlier rules win. The key rule fires on anything `=`-assigned — including keys
 * inside `{ … }` inline tables — via lookahead, so no brace-tracking state is needed. */
const RULES: { re: RegExp; cls: string }[] = [
  { re: /#[^\n]*/y, cls: "tok-cmt" },
  { re: /"(?:[^"\\\n]|\\.)*"/y, cls: "tok-str" },
  { re: /'[^'\n]*'/y, cls: "tok-str" },
  { re: /[A-Za-z0-9_-]+(?:\s*\.\s*[A-Za-z0-9_-]+)*(?=\s*=)/y, cls: "tok-type" },
  { re: /\b(?:true|false)\b/y, cls: "tok-kw" },
  { re: /[+-]?(?:0x[0-9A-Fa-f_]+|0o[0-7_]+|0b[01_]+|\d[\d_]*(?:\.\d[\d_]*)?(?:[eE][+-]?\d[\d_]*)?)/y, cls: "tok-num" },
];

function highlightLine(line: string): string {
  const h = line.match(HEADER);
  if (h) {
    const [, ws1, header, ws2, comment] = h;
    return `${ws1}<span class="tok-kw">${esc(header)}</span>${ws2}${
      comment ? `<span class="tok-cmt">${esc(comment)}</span>` : ""
    }`;
  }
  let out = "";
  let i = 0;
  outer: while (i < line.length) {
    for (const rule of RULES) {
      rule.re.lastIndex = i;
      const m = rule.re.exec(line);
      if (!m) continue;
      out += `<span class="${rule.cls}">${esc(m[0])}</span>`;
      i += m[0].length;
      continue outer;
    }
    out += esc(line[i]);
    i += 1;
  }
  return out;
}

/** Highlight TOML source into HTML spans (`tok-*` classes, colored by the layout's CSS). */
export function highlightToml(code: string): string {
  return code.split("\n").map(highlightLine).join("\n");
}
