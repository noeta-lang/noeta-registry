import { SELF } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";
import { highlightNoeta } from "../src/highlight";
import { highlightToml } from "../src/highlight-toml";

const ADMIN = "test-admin-token"; // matches vitest.config.ts miniflare bindings
const TOKEN = "acme-publish-token-abc123";

function post(path: string, body: unknown, token?: string): Promise<Response> {
  return SELF.fetch("https://registry.test/v1" + path, {
    method: "POST",
    headers: token ? { authorization: `Bearer ${token}` } : {},
    body: JSON.stringify(body),
  });
}
function putText(path: string, body: string, token?: string): Promise<Response> {
  return SELF.fetch("https://registry.test/v1" + path, {
    method: "PUT",
    headers: { ...(token ? { authorization: `Bearer ${token}` } : {}), "content-type": "application/json" },
    body,
  });
}
// The web UI lives at the root, not under /v1.
const web = (path: string) => SELF.fetch("https://registry.test" + path);

// A docs.json whose prose deliberately carries an XSS payload and a javascript: link, to prove the
// renderer escapes content and sanitizes link schemes.
const DOCS = JSON.stringify({
  schema: 1,
  package: { name: "acme/greeter", version: "1.1.0" },
  modules: [
    {
      file: "lib.noe",
      namespace: "greeter.lib",
      doc: "Friendly **greetings**. See `greet`.",
      items: [
        {
          section:
            "## Safety\n\n<script>alert(1)</script> and a [bad link](javascript:alert(1)) and a [good link](https://noeta.dev).",
        },
        {
          kind: "fn",
          name: "greet",
          signature: "pub fn greet(who: string): string",
          // A bare number and a code span together — the code-span placeholder must not collide
          // with the ` 2 ` in prose.
          doc: "Greets `who` by name in step 2 of the flow.",
          public: true,
        },
      ],
    },
  ],
});

// A by-module API-reference artifact (the shape `noeta doc --api` emits): native modules with no
// source file, several functions, and — deliberately — a `new` in two different modules, to prove
// anchors are scoped per module (a bare `decl-new` would collide across the reference).
const API_DOCS = JSON.stringify({
  schema: 1,
  modules: [
    {
      file: "",
      namespace: "std.math",
      doc: null,
      items: [
        { kind: "fn", name: "sqrt", signature: "fn sqrt(float): float", doc: "The square root.", public: true },
        { kind: "fn", name: "pow", signature: "fn pow(float, float): float", doc: null, public: true },
        { kind: "fn", name: "new", signature: "fn new(): float", doc: null, public: true },
      ],
    },
    {
      file: "",
      namespace: "std.cell",
      doc: null,
      items: [{ kind: "fn", name: "new", signature: "fn new(T): Cell<T>", doc: null, public: true }],
    },
  ],
});

// A README whose markdown deliberately carries an XSS payload, to prove the package page renders
// publisher READMEs through the same escape-first pipeline as doc prose.
const README =
  "# greeter\n\nA **friendly** greeting library.\n\n<script>alert(2)</script>\n\n```sh\nnoeta add acme/greeter\n```";

const LATEST_SHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4";

// A Noeta snippet exercising every token class the highlighter emits: comment, tier, keyword,
// function, type, number, string, interpolation hole, and markup tag — plus a bare `<` and `"`
// (the double-escape tripwires).
const NOETA_SNIPPET = [
  "// greet builds a card",
  "@html",
  "fn greet(name: string): Result {",
  '  if count < 2 { return "hi ${name}" }',
  "  <p>done</p>",
  "}",
].join("\n");

// The exact spans highlightNoeta must emit for NOETA_SNIPPET — pinned verbatim as the drift
// tripwire against the canonical copy in noeta-theme/js/highlight.js: if either copy's rules
// change, this fails before the sites diverge visually.
const NOETA_SNIPPET_HTML = [
  '<span class="tok-cmt">// greet builds a card</span>',
  '<span class="tok-tier">@html</span>',
  '<span class="tok-kw">fn</span> <span class="tok-fn">greet</span>(name: string): <span class="tok-type">Result</span> {',
  '  <span class="tok-kw">if</span> count &lt; <span class="tok-num">2</span> { <span class="tok-kw">return</span> ' +
    '<span class="tok-str">&quot;hi <span class="tok-hole">${name}</span>&quot;</span> }',
  '  <span class="tok-tag">&lt;p&gt;</span>done<span class="tok-tag">&lt;/p&gt;</span>',
  "}",
].join("\n");

// A README whose fenced code exercises the server-side highlighter end to end: a ```noeta fence
// (raw `<`, `"`, and `${…}` must land escaped exactly once), a ```rust fence that must keep the
// plain escaped rendering, a ```toml fence (the para READMEs' Installation sections), and a
// ```noe fence that tries to break out of the <code> element.
const NOETA_README = [
  "# codey",
  "",
  "Highlighting fixture.",
  "",
  "```noeta",
  NOETA_SNIPPET,
  "```",
  "",
  "```rust",
  'fn main() { println!("hi") }',
  "```",
  "",
  "```toml",
  "[dependencies]",
  'codey = { version = "^0.1.0" }',
  "```",
  "",
  "```noe",
  "</code><script>alert(3)</script>",
  "```",
].join("\n");

// A README exercising what markdown-it brought over the old hand-rolled renderer: a GFM table with
// per-column alignment (the para/p2p README shape that used to render as literal pipes), ordered +
// nested lists, a blockquote carrying a ```noeta fence (highlighting + copy button must survive the
// nesting), raw HTML payloads that must land escaped/inert, and a javascript: link that must be
// refused.
const GFM_README = [
  "# gfm",
  "",
  "| Feature | Status | Notes |",
  "|:--------|:------:|------:|",
  "| tables | yes | GFM |",
  "| lists | yes | nested |",
  "",
  "1. first",
  "2. second",
  "   - nested a",
  "   - nested b",
  "",
  "> A quoted warning with `code`.",
  ">",
  "> ```noeta",
  "> fn greet() {}",
  "> ```",
  "",
  "<script>alert(9)</script>",
  "",
  '<img src=x onerror="alert(10)">',
  "",
  "[evil](javascript:alert(11)) and [fine](https://noeta.dev/docs).",
].join("\n");

// The sidebar install command, as the server highlights it: the command word tok-fn, `--flags`
// tok-kw, values (and the shell continuations) plain.
const INSTALL_HTML =
  '<span class="tok-fn">noeta</span> add \\\n' +
  '  <span class="tok-kw">--package</span> acme/greeter \\\n' +
  '  <span class="tok-kw">--version</span> ^1.1.0';

// The sidebar's one-line TOML dependency snippet, highlighted: keys tok-type (including inside the
// inline table), strings tok-str with entity-escaped quotes, braces plain.
const MANIFEST_HTML =
  '<span class="tok-type">greeter</span> = { <span class="tok-type">version</span> = ' +
  '<span class="tok-str">&quot;^1.1.0&quot;</span>, <span class="tok-type">package</span> = ' +
  '<span class="tok-str">&quot;acme/greeter&quot;</span> }';

// The copy button: an inline SVG clipboard (the CSP allows no external assets) that COPY_SCRIPT
// swaps to a checkmark via [data-copied], with the accessible name on the button itself.
const COPY_BTN = '<button class="copy-btn" type="button" aria-label="Copy to clipboard"><svg class="ic-copy"';

beforeAll(async () => {
  expect((await post("/scopes", { scope: "acme", token: TOKEN }, ADMIN)).status).toBe(201);
  await post("/packages/acme/greeter", { version: "1.0.0", url: "https://github.com/acme/greeter", tag: "v1.0.0", sha: "aaa" }, TOKEN);
  // A full-length SHA, so the page's rendering of it is exercised at its real width.
  await post("/packages/acme/greeter", { version: "1.1.0", url: "https://github.com/acme/greeter", tag: "v1.1.0", sha: LATEST_SHA, license: "MIT OR Apache-2.0" }, TOKEN);
  expect((await putText("/packages/acme/greeter/docs/1.1.0", DOCS, TOKEN)).status).toBe(200);
  expect((await putText("/packages/acme/greeter/readme/1.1.0", README, TOKEN)).status).toBe(200);
  await post("/packages/acme/codey", { version: "0.1.0", url: "https://github.com/acme/codey", tag: "v0.1.0", sha: "bbb" }, TOKEN);
  expect((await putText("/packages/acme/codey/readme/0.1.0", NOETA_README, TOKEN)).status).toBe(200);
  await post("/packages/acme/gfm", { version: "0.1.0", url: "https://github.com/acme/gfm", tag: "v0.1.0", sha: "abc" }, TOKEN);
  expect((await putText("/packages/acme/gfm/readme/0.1.0", GFM_README, TOKEN)).status).toBe(200);
  await post("/packages/acme/std", { version: "1.0.0", url: "https://github.com/acme/std", tag: "v1.0.0", sha: "ccc" }, TOKEN);
  expect((await putText("/packages/acme/std/docs/1.0.0", API_DOCS, TOKEN)).status).toBe(200);
  // Two tagged packages, to prove a keyword listing groups rather than just echoing one row.
  await post(
    "/packages/acme/paraext",
    { version: "0.3.0", url: "https://github.com/acme/paraext", tag: "v0.3.0", sha: "ddd", keywords: ["para", "aether"] },
    TOKEN,
  );
  await post(
    "/packages/acme/parakit",
    { version: "0.1.0", url: "https://github.com/acme/parakit", tag: "v0.1.0", sha: "eee", keywords: ["para"] },
    TOKEN,
  );
  // A described package, so search can be exercised by name, keyword, and description text.
  await post(
    "/packages/acme/imgfx",
    {
      version: "1.2.0",
      url: "https://github.com/acme/imgfx",
      tag: "v1.2.0",
      sha: "fff",
      license: "MIT",
      description: "SIMD-accelerated image filters",
      keywords: ["image", "simd"],
    },
    TOKEN,
  );
});

describe("registry web UI", () => {
  it("serves an HTML home page listing published packages", async () => {
    const r = await web("/");
    expect(r.status).toBe(200);
    expect(r.headers.get("content-type")).toContain("text/html");
    const body = await r.text();
    expect(body).toContain("Noeta registry");
    expect(body).toContain("/acme/greeter");
    // The latest release's license shows in the listing (greeter 1.1.0 declared one).
    expect(body).toContain(`<span class="badge license">MIT OR Apache-2.0</span>`);
    // The listing card carries the description and keyword chips of each package's latest release.
    expect(body).toContain("SIMD-accelerated image filters");
    expect(body).toContain(`href="/keywords/simd"`);
    // The getting-started card points newcomers at the docs.
    expect(body).toContain("New to Noeta?");
    expect(body).toContain(`href="https://docs.noeta.dev/getting-started"`);
  });

  it("pins every served script in the CSP by its real hash", async () => {
    // Inline scripts are allowed only when pinned by SHA-256 — the anti-XSS property holds only if
    // every script the page serves has its hash in the CSP. The docs tab serves three (copy, the
    // shared chrome drawer, and docs search); recompute each from the served bytes and require it
    // in script-src, so editing a script without updating its hash (or vice versa) fails here.
    // The drawer's source lives in @noeta/theme, so this is also what catches a chrome change
    // landing in the sibling repo without a matching hash bump here.
    const sha256 = async (s: string) =>
      "sha256-" + btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)))));
    const r = await web("/acme/greeter/1.1.0/docs");
    const body = await r.text();
    const scripts = [...body.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((m) => m[1]);
    expect(scripts.length, "the docs tab serves the copy, drawer and docs-search scripts").toBe(3);
    const csp = r.headers.get("content-security-policy") ?? "";
    for (const s of scripts) expect(csp).toContain(`'${await sha256(s)}'`);
    // Hash sources only, never a blanket allowance.
    const scriptSrc = csp.match(/script-src ([^;]*)/)?.[1] ?? "";
    expect(scriptSrc).not.toContain("'unsafe-inline'");
  });

  it("shows the latest release with its metadata rail and a repository link", async () => {
    const body = await (await web("/acme/greeter")).text();
    // Latest by semver (1.1.0 > 1.0.0 — not lexicographic).
    expect(body).toContain(`<h1>acme/greeter <span class="version">1.1.0</span></h1>`);
    // The full pinned commit, not a truncation: the index is authoritative on version→commit, so
    // the value a reader verifies against must be on the page and selectable.
    expect(body).toContain(`<td class="mono sha">${LATEST_SHA}</td>`);
    // The rail tells you how to actually depend on it.
    // Shell continuations keep the whole command visible in the narrow rail; the highlight spans
    // wrap words without touching the text, so it still pastes as-is (textContent is the payload).
    expect(body).toContain(INSTALL_HTML);
    // Escape-first: the quotes are entity-escaped inside the tok-str spans and render as `"`.
    expect(body).toContain(MANIFEST_HTML);
    // A repository button — the release's git URL, labelled by destination.
    expect(body).toContain(`href="https://github.com/acme/greeter"`);
    expect(body).toContain("github.com/acme/greeter →");
    // A docs tab, because 1.1.0 has docs.
    expect(body).toContain("/acme/greeter/1.1.0/docs");
    // The declared license, as a badge on the selected version.
    expect(body).toContain(`<span class="badge license">MIT OR Apache-2.0</span>`);
    // 1.0.0 declared none — its page shows no license badge.
    const old = await (await web("/acme/greeter/1.0.0")).text();
    expect(old).not.toContain(`<span class="badge license">`);
  });

  it("splits the release into linkable tabs, each keeping the shell", async () => {
    const versions = await (await web("/acme/greeter/1.1.0/versions")).text();
    expect(versions).toContain("2 Versions");
    expect(versions).toContain(`href="/acme/greeter/1.0.0"`); // the older release is still listed
    expect(versions).toContain(`<tr class="here">`); // the selected version is marked
    // The shell (and the install line) survives the tab switch.
    expect(versions).toContain(INSTALL_HTML);

    const deps = await (await web("/acme/greeter/1.1.0/deps")).text();
    expect(deps).toContain("0 Dependencies");
    expect(deps).toContain("This release declares no dependencies.");

    // The readme URL is the bare version — `/readme` is not a second address for it.
    expect((await web("/acme/greeter/1.1.0/readme")).status).toBe(404);
  });

  it("marks the documentation tab inert when the release published none", async () => {
    const body = await (await web("/acme/greeter/1.0.0")).text();
    expect(body).toContain(`<span class="tab is-off">Documentation</span>`);
    expect(body).not.toContain(`/acme/greeter/1.0.0/docs"`);
  });

  it("shows keyword chips and browses packages by keyword", async () => {
    // Chips on the package page, sorted, each linking its listing.
    const pkg = await (await web("/acme/paraext")).text();
    expect(pkg).toContain(`<a href="/keywords/aether">#aether</a>`);
    expect(pkg).toContain(`<a href="/keywords/para">#para</a>`);

    // The listing answers "what builds on para?" — both packages, not just the tagged release.
    const para = await (await web("/keywords/para")).text();
    expect(para).toContain("<h1>#para</h1>");
    expect(para).toContain("2 packages tagged");
    expect(para).toContain(`href="/acme/paraext"`);
    expect(para).toContain(`href="/acme/parakit"`);

    // A narrower keyword lists only its own.
    const aether = await (await web("/keywords/aether")).text();
    expect(aether).toContain("1 package tagged");
    expect(aether).toContain(`href="/acme/paraext"`);
    expect(aether).not.toContain(`href="/acme/parakit"`);

    // A keyword nobody used is an empty listing, not a 404.
    const none = await (await web("/keywords/nobody-uses-this")).text();
    expect(none).toContain("No packages are tagged");

    // A malformed keyword is not a query.
    expect((await web("/keywords/NotAKeyword")).status).toBe(404);
  });

  it("searches packages by name, keyword, and description text", async () => {
    // The front page carries the search box.
    const home = await (await web("/")).text();
    expect(home).toContain(`action="/search"`);

    // By name.
    const byName = await (await web("/search?q=greeter")).text();
    expect(byName).toContain(`href="/acme/greeter"`);
    expect(byName).toContain("1 result for");

    // By keyword — both para packages surface.
    const byKeyword = await (await web("/search?q=para")).text();
    expect(byKeyword).toContain(`href="/acme/paraext"`);
    expect(byKeyword).toContain(`href="/acme/parakit"`);

    // By a word from the description — only acme/imgfx has "filters" in its blurb, and the blurb shows.
    const byDesc = await (await web("/search?q=filters")).text();
    expect(byDesc).toContain(`href="/acme/imgfx"`);
    expect(byDesc).toContain("SIMD-accelerated image filters");
    expect(byDesc).not.toContain(`href="/acme/greeter"`);

    // Prefix matching: "img" finds imgfx.
    expect(await (await web("/search?q=img")).text()).toContain(`href="/acme/imgfx"`);

    // A no-match query is an empty state, not an error.
    const none = await (await web("/search?q=zznotapackage")).text();
    expect(none).toContain("No packages match");

    // An empty query prompts rather than listing everything.
    expect(await (await web("/search?q=")).text()).toContain("Type a package name");
  });

  it("a #tag token requires the keyword instead of matching it as text", async () => {
    // `para` as free text prefix-matches the two para-keyword packages AND acme/paraext by name;
    // `#para` requires the keyword column, so only the tagged packages qualify.
    const tagged = await (await web("/search?q=%23para")).text();
    expect(tagged).toContain(`href="/acme/paraext"`);
    expect(tagged).toContain(`href="/acme/parakit"`);
    expect(tagged).not.toContain(`href="/acme/imgfx"`);

    // A tag composes with free terms: only paraext carries the aether keyword.
    const composed = await (await web("/search?q=para%20%23aether")).text();
    expect(composed).toContain(`href="/acme/paraext"`);
    expect(composed).not.toContain(`href="/acme/parakit"`);

    // "image" appears in imgfx's description AND keywords; requiring a keyword imgfx does not
    // carry excludes it even though the free term would match.
    const excluded = await (await web("/search?q=image%20%23para")).text();
    expect(excluded).toContain("No packages match");

    // A tag no package carries is an empty state, not an error; a bare `#` degrades to the prompt.
    expect(await (await web("/search?q=%23nosuchtag")).text()).toContain("No packages match");
    expect((await web("/search?q=%23")).status).toBe(200);

    // The empty-state hint teaches the syntax.
    expect(await (await web("/search?q=")).text()).toContain("#tag");
  });

  it("never lets a search query reach FTS as a syntax error or operator", async () => {
    // Quotes, stars, and boolean operators are user text here — reduced to prefix terms, never
    // MATCH syntax. Each must return 200 (a normal results page), not a 500 from a MATCH parse error.
    for (const q of [`"unterminated`, `AND OR NOT`, `img*fx"`, `para AND`, `*`, `()`]) {
      const r = await web(`/search?q=${encodeURIComponent(q)}`);
      expect(r.status, `query ${JSON.stringify(q)}`).toBe(200);
    }
  });

  it("surfaces advisories on the security tab, per selected release", async () => {
    // No advisory names acme/std, so its tab says so rather than showing an empty list.
    expect(await (await web("/acme/std/1.0.0/security")).text()).toContain(
      "No advisories have been published against this package.",
    );

    const adv = await post(
      "/advisories",
      {
        id: "NOETA-TEST-0001",
        package: "acme/greeter",
        ranges: ">=1.0.0, <1.1.0",
        patched: "1.1.0",
        severity: "high",
        summary: "Greeting overflow on a crafted name",
        details: "A crafted name overflows the greeting buffer.",
        url: "https://example.test/advisories/1",
      },
      ADMIN,
    );
    expect(adv.status).toBe(201);

    // 1.0.0 is inside the affected range.
    const hit = await (await web("/acme/greeter/1.0.0/security")).text();
    expect(hit).toContain("Greeting overflow on a crafted name");
    expect(hit).toContain(`<span class="badge yanked">affects 1.0.0</span>`);
    expect(hit).toContain("1.1.0"); // the patched release is named
    expect(hit).toContain(`<span class="tab-count is-alert">1</span>`); // and the tab bar flags it

    // 1.1.0 is the patched release — same advisory, opposite verdict, and no alert on the tab.
    const clear = await (await web("/acme/greeter/1.1.0/security")).text();
    expect(clear).toContain("Greeting overflow on a crafted name");
    expect(clear).toContain(`<span class="badge">1.1.0 not affected</span>`);
    expect(clear).not.toContain(`tab-count is-alert`);
  });

  it("renders the version's README on the package page, escaped", async () => {
    const body = await (await web("/acme/greeter")).text();
    expect(body).toContain("A <strong>friendly</strong> greeting library.");
    expect(body).toContain("noeta add acme/greeter"); // the fenced block survives
    expect(body).not.toContain("<script>alert(2)</script>"); // escaped, not executable
    expect(body).toContain("&lt;script&gt;alert(2)&lt;/script&gt;");
    // 1.0.0 has no README — its page renders without one.
    const old = await (await web("/acme/greeter/1.0.0")).text();
    expect(old).not.toContain("friendly");
  });

  it("renders documentation from the stored docs.json", async () => {
    const body = await (await web("/acme/greeter/1.1.0/docs")).text();
    expect(body).toContain("greeter.lib"); // module heading
    // The signature block is Noeta code, so it renders highlighted; the plain text still rides
    // the decl's data-text attribute for the search filter.
    expect(body).toContain(
      `<pre class="sig"><code>pub <span class="tok-kw">fn</span> <span class="tok-fn">greet</span>(who: string): string</code></pre>`,
    );
    expect(body).toContain("pub fn greet(who: string): string"); // data-text (search filter)
    expect(body).toContain("<strong>greetings</strong>"); // markdown bold rendered
    expect(body).toContain("<code>greet</code>"); // the decl name
    expect(body).toContain("step 2 of the flow"); // a bare number survives code-span restore
    expect(body).not.toContain("undefined");
  });

  it("escapes docs content and sanitizes link schemes (no XSS)", async () => {
    const body = await (await web("/acme/greeter/1.1.0/docs")).text();
    // The <script> payload is escaped, never live.
    expect(body).not.toContain("<script>alert(1)</script>");
    expect(body).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
    // A javascript: link is dropped (rendered as plain text); an https link survives.
    expect(body).not.toContain('href="javascript:');
    expect(body).toContain('href="https://noeta.dev"');
    // A response CSP forbids scripts as defense in depth.
    const r = await web("/acme/greeter/1.1.0/docs");
    expect(r.headers.get("content-security-policy")).toContain("default-src 'none'");
  });

  it("filters the docs server-side from ?q= (the no-JS search path)", async () => {
    // std.math has sqrt/pow/new; std.cell has new. A search for "sqrt" should match only sqrt.
    const body = await (await web("/acme/std/1.0.0/docs?q=sqrt")).text();
    // The container enters the searching state and the box carries the query back.
    expect(body).toContain(`class="docs-results searching"`);
    expect(body).toContain(`value="sqrt"`);
    expect(body).toContain(`for <code>sqrt</code>`); // the match summary
    // The matching decl is visible; the misses carry the native `hidden` attribute.
    expect(body).not.toMatch(/id="std-math--sqrt"[^>]*\bhidden/);
    expect(body).toMatch(/id="std-math--pow"[^>]*\bhidden/);
    expect(body).toMatch(/id="std-math--new"[^>]*\bhidden/);
    // A module with no match is hidden whole.
    expect(body).toMatch(/id="mod-std-cell"[^>]*\bhidden/);

    // No query → the full docs, no searching state, box empty.
    const plain = await (await web("/acme/std/1.0.0/docs")).text();
    expect(plain).toContain(`class="docs-results"`);
    expect(plain).not.toContain(`docs-results searching`); // not in the searching state
    expect(plain).not.toMatch(/class="decl"[^>]*\bhidden/); // nothing hidden
    // The enhancement script rides only the docs tab, never the readme.
    const readme = await (await web("/acme/std/1.0.0")).text();
    expect(readme).not.toContain(`id="docsearch"`);
  });

  it("renders a by-module API reference with a per-module contents list and module-scoped anchors", async () => {
    const body = await (await web("/acme/std/1.0.0/docs")).text();
    // Both modules render.
    expect(body).toContain("std.math");
    expect(body).toContain("std.cell");
    // A per-module contents list (≥3 decls) with a jump link to a scoped anchor.
    expect(body).toContain('<ul class="toc">');
    expect(body).toContain('href="#std-math--sqrt"');
    // `new` appears in both modules, but the anchors are distinct (no cross-module collision).
    expect(body).toContain('id="std-math--new"');
    expect(body).toContain('id="std-cell--new"');
    expect(body).not.toContain('id="decl-new"');
    // The one-decl module gets no contents list (would be noise).
    expect((body.match(/<ul class="toc">/g) || []).length).toBe(1);
  });

  it("404s an unknown package and an unknown docs version", async () => {
    expect((await web("/acme/nope")).status).toBe(404);
    expect((await web("/acme/greeter/1.0.0/docs")).status).toBe(404); // 1.0.0 has no docs
    expect((await web("/a/b/c/d/e")).status).toBe(404);
  });

  it("rejects a non-GET on a web path", async () => {
    const r = await SELF.fetch("https://registry.test/acme/greeter", { method: "DELETE" });
    expect(r.status).toBe(405);
  });
});

describe("noeta syntax highlighting", () => {
  it("highlights a known snippet into the exact token spans (drift tripwire vs noeta-theme)", () => {
    expect(highlightNoeta(NOETA_SNIPPET)).toBe(NOETA_SNIPPET_HTML);
  });

  it("renders a ```noeta fence highlighted, with every entity escaped exactly once", async () => {
    const body = await (await web("/acme/codey")).text();
    // The fence body is threaded to the highlighter RAW, so the page carries the exact spans the
    // unit test pins — including the single-escaped `<`, `"`, and the `${…}` hole.
    expect(body).toContain(`<pre class="noeta-code"><code>${NOETA_SNIPPET_HTML}</code></pre>`);
    // Double-escape tripwires: a pre-escaped line fed to the (internally escaping) highlighter
    // would produce these.
    expect(body).not.toContain("&amp;lt;");
    expect(body).not.toContain("&amp;quot;");
    expect(body).not.toContain("&amp;amp;");
  });

  it("keeps every other language fence on the plain escaped rendering", async () => {
    const body = await (await web("/acme/codey")).text();
    expect(body).toContain(`<pre><code>fn main() { println!(&quot;hi&quot;) }</code></pre>`);
    // The greeter README's ```sh install fence stays plain too.
    const greeter = await (await web("/acme/greeter")).text();
    expect(greeter).toContain(`<pre><code>noeta add acme/greeter</code></pre>`);
    expect(greeter).not.toContain(`noeta-code"><code>noeta add`);
  });

  it("renders a /docs signature with token spans", async () => {
    const body = await (await web("/acme/std/1.0.0/docs")).text();
    expect(body).toContain(
      `<pre class="sig"><code><span class="tok-kw">fn</span> <span class="tok-fn">sqrt</span>(float): float</code></pre>`,
    );
  });

  it("keeps a hostile noeta fence inert — the payload cannot leave the code element", async () => {
    const body = await (await web("/acme/codey")).text();
    expect(body).not.toContain("</code><script>");
    expect(body).not.toContain("<script>alert(3)");
    // The payload is present, but escaped inside token spans.
    expect(body).toContain(`<span class="tok-tag">&lt;/code&gt;</span><span class="tok-tag">&lt;script&gt;</span>`);
  });
});

describe("toml syntax highlighting", () => {
  it("highlights a known snippet into the exact token spans (pinned output)", () => {
    // Header + trailing comment, an inline table with two keys, a basic string with escaped quotes
    // and markup characters, a literal string with a backslash, numbers, and booleans.
    const toml = [
      "# manifest",
      "[dependencies] # deps",
      'greeter = { version = "^1.1.0", package = "acme/greeter" }',
      'title = "a \\"quoted\\" <name>"',
      "path = 'C:\\temp'",
      "max = 42",
      "pi = 3.14",
      "on = true",
      "off = false",
    ].join("\n");
    const expected = [
      '<span class="tok-cmt"># manifest</span>',
      '<span class="tok-kw">[dependencies]</span> <span class="tok-cmt"># deps</span>',
      MANIFEST_HTML,
      '<span class="tok-type">title</span> = <span class="tok-str">&quot;a \\&quot;quoted\\&quot; &lt;name&gt;&quot;</span>',
      "<span class=\"tok-type\">path</span> = <span class=\"tok-str\">'C:\\temp'</span>",
      '<span class="tok-type">max</span> = <span class="tok-num">42</span>',
      '<span class="tok-type">pi</span> = <span class="tok-num">3.14</span>',
      '<span class="tok-type">on</span> = <span class="tok-kw">true</span>',
      '<span class="tok-type">off</span> = <span class="tok-kw">false</span>',
    ].join("\n");
    expect(highlightToml(toml)).toBe(expected);
  });

  it("carries tok spans on the sidebar install and TOML snippets", async () => {
    const body = await (await web("/acme/greeter")).text();
    expect(body).toContain(INSTALL_HTML);
    expect(body).toContain(MANIFEST_HTML);
  });

  it("renders a ```toml README fence highlighted while ```rust stays plain", async () => {
    const body = await (await web("/acme/codey")).text();
    expect(body).toContain(
      `<pre class="toml-code"><code><span class="tok-kw">[dependencies]</span>\n` +
        `<span class="tok-type">codey</span> = { <span class="tok-type">version</span> = ` +
        `<span class="tok-str">&quot;^0.1.0&quot;</span> }</code></pre>`,
    );
    // The rust fence keeps the plain escaped rendering — no token spans.
    expect(body).toContain(`<pre><code>fn main() { println!(&quot;hi&quot;) }</code></pre>`);
  });
});

describe("markdown-it rendering (GFM)", () => {
  it("renders a GFM table as a real <table> with per-column alignment", async () => {
    const body = await (await web("/acme/gfm")).text();
    expect(body).toContain("<table>");
    expect(body).toContain('<th style="text-align:left">Feature</th>');
    expect(body).toContain('<th style="text-align:center">Status</th>');
    expect(body).toContain('<th style="text-align:right">Notes</th>');
    expect(body).toContain('<td style="text-align:center">yes</td>');
    // The old renderer's failure mode — literal pipes in a paragraph — is gone.
    expect(body).not.toContain("<p>| Feature | Status | Notes |");
  });

  it("renders ordered and nested lists", async () => {
    const body = await (await web("/acme/gfm")).text();
    expect(body).toContain("<ol>");
    expect(body).toContain("<li>first</li>");
    // The unordered list nests inside the second ordered item.
    expect(body).toMatch(/<li>second\s*<ul>\s*<li>nested a<\/li>\s*<li>nested b<\/li>\s*<\/ul>\s*<\/li>/);
  });

  it("renders a blockquote, and a noeta fence inside it keeps highlighting + copy button", async () => {
    const body = await (await web("/acme/gfm")).text();
    const quote = body.match(/<blockquote>([\s\S]*?)<\/blockquote>/);
    expect(quote).not.toBeNull();
    expect(quote![1]).toContain("A quoted warning with <code>code</code>.");
    // The fence inside the quote still routes through the highlighter and the .snippet wrapper.
    expect(quote![1]).toContain(
      `<div class="snippet"><pre class="noeta-code"><code><span class="tok-kw">fn</span> <span class="tok-fn">greet</span>() {}</code></pre>`,
    );
    expect(quote![1]).toContain('class="copy-btn"');
  });

  it("renders raw HTML in a README as escaped text, never markup (html: false)", async () => {
    const body = await (await web("/acme/gfm")).text();
    expect(body).not.toContain("<script>alert(9)");
    expect(body).toContain("&lt;script&gt;alert(9)&lt;/script&gt;");
    expect(body).not.toContain("<img");
    expect(body).toContain("&lt;img src=x onerror=");
  });

  it("refuses a javascript: link while a https link renders with rel", async () => {
    const body = await (await web("/acme/gfm")).text();
    expect(body).not.toContain('href="javascript:');
    expect(body).toContain('<a href="https://noeta.dev/docs" rel="nofollow noopener">fine</a>');
  });
});

describe("copy buttons", () => {
  it("renders as an inline SVG icon pair, not text, with the accessible name preserved", async () => {
    const body = await (await web("/acme/greeter")).text();
    // The clipboard icon rides the button markup; the checkmark sibling is swapped in by CSS on
    // the [data-copied] attribute COPY_SCRIPT sets (and the script also swaps the aria-label).
    expect(body).toContain(COPY_BTN);
    expect(body).toContain('<svg class="ic-check"');
    // The old text affordance is gone from the stylesheet.
    expect(body).not.toContain('content:"Copy"');
    expect(body).not.toContain('content:"Copied"');
    // The script flips the accessible name while copied, and back.
    expect(body).toContain('b.setAttribute("aria-label","Copied")');
    expect(body).toContain('b.setAttribute("aria-label","Copy to clipboard")');
  });

  it("appears on every README fenced block and docs code block, not just the sidebar", async () => {
    // codey's README: noeta, rust, toml, and noe fences — four blocks, plus two sidebar snippets.
    const readme = await (await web("/acme/codey")).text();
    expect((readme.match(/class="copy-btn"/g) || []).length).toBe(6);
    // Highlighted and plain fences alike sit in the .snippet wrapper the delegated script serves.
    expect(readme).toContain('<div class="snippet"><pre class="noeta-code">');
    expect(readme).toContain('<div class="snippet"><pre class="toml-code">');
    expect(readme).toContain('<div class="snippet"><pre><code>fn main()');
    // Docs signature blocks get the same affordance.
    const docs = await (await web("/acme/std/1.0.0/docs")).text();
    expect(docs).toContain('<div class="snippet"><pre class="sig">');
  });

  it("copies the RAW code of a highlighted block — textContent round-trips exactly", async () => {
    // COPY_SCRIPT copies the <code> element's textContent. Simulate that: strip the spans and
    // decode the entities of the served noeta block; the result must be the exact raw snippet —
    // including the `<`, `"`, and `${…}` that the highlighter escaped.
    const body = await (await web("/acme/codey")).text();
    const m = body.match(/<pre class="noeta-code"><code>([\s\S]*?)<\/code><\/pre>/);
    expect(m).not.toBeNull();
    const textContent = m![1]
      .replace(/<[^>]+>/g, "")
      .replace(/&lt;/g, "<")
      .replace(/&gt;/g, ">")
      .replace(/&quot;/g, '"')
      .replace(/&#39;/g, "'")
      .replace(/&amp;/g, "&");
    expect(textContent).toBe(NOETA_SNIPPET);
  });
});
