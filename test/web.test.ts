import { env, SELF } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";
import { RENDERER_REV } from "../src/render-cache";

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

// A Noeta snippet exercising the token classes the canonical grammar colors: comment, tier
// directive, keyword, function, type, number, string, interpolation hole — plus a bare `<` and
// `"` (the escape tripwires).
const NOETA_SNIPPET = [
  "// greet builds a card",
  "@html",
  "fn greet(name: string): Result {",
  '  if count < 2 { return "hi ${name}" }',
  "  <p>done</p>",
  "}",
].join("\n");

// The exact inner HTML shiki emits for NOETA_SNIPPET through the canonical noeta grammar and the
// Ink & Signal var(--syn-*) theme (src/shiki.ts) — pinned verbatim so a grammar resync or theme
// edit that changes tokenization fails HERE, as the reminder to bump RENDERER_REV. Shape notes:
// one span.line per source line, newlines as real text nodes (textContent stays the raw source),
// `<` escaped as &#x3C;, `"` left literal in text nodes (attribute-only escaping is fine there).
const NOETA_SNIPPET_HTML = [
  '<span class="line"><span style="color:var(--syn-comment);font-style:italic">// greet builds a card</span></span>',
  '<span class="line"><span style="color:var(--accent-2-bright)">@html</span></span>',
  '<span class="line"><span style="color:var(--syn-keyword)">fn</span><span style="color:var(--syn-fn)"> greet</span>' +
    '<span style="color:var(--text-0)">(name: </span><span style="color:var(--syn-type)">string</span>' +
    '<span style="color:var(--text-0)">): </span><span style="color:var(--syn-type)">Result</span>' +
    '<span style="color:var(--text-0)"> {</span></span>',
  '<span class="line"><span style="color:var(--syn-keyword)">  if</span><span style="color:var(--text-0)"> count &#x3C; </span>' +
    '<span style="color:var(--syn-number)">2</span><span style="color:var(--text-0)"> { </span>' +
    '<span style="color:var(--syn-keyword)">return</span><span style="color:var(--syn-string)"> "hi </span>' +
    '<span style="color:var(--syn-hole)">${</span><span style="color:var(--syn-string)">name</span>' +
    '<span style="color:var(--syn-hole)">}</span><span style="color:var(--syn-string)">"</span>' +
    '<span style="color:var(--text-0)"> }</span></span>',
  '<span class="line"><span style="color:var(--text-0)">  &#x3C;p>done&#x3C;/p></span></span>',
  '<span class="line"><span style="color:var(--text-0)">}</span></span>',
].join("\n");

// A README whose fenced code exercises the server-side highlighter end to end: a ```noeta fence
// (raw `<`, `"`, and `${…}` must land escaped exactly once), a ```rust fence (a bundled shiki
// grammar), a ```toml fence (the para READMEs' Installation sections), a fence whose language
// shiki does NOT know (must stay plain escaped), and a ```noe fence that tries to break out of
// the <code> element.
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
  "```zzz-unknown",
  '<b>not & "highlighted"</b>',
  "```",
  "",
  "```noe",
  "</code><script>alert(3)</script>",
  "```",
].join("\n");

// A README of fences in the bundled languages the registry registers beyond noeta/toml — plus a
// ```console transcript (the shellsession alias) and a noeta fence whose @sql{…} tier body must
// get REAL SQL tokens via the tier-languages injection grammar.
const LANGS_README = [
  "# langs",
  "",
  "```sql",
  "SELECT id FROM users WHERE age > 21;",
  "```",
  "",
  "```jsonc",
  '{ "name": "x" } // trailing note',
  "```",
  "",
  "```yaml",
  "name: demo",
  "count: 3",
  "```",
  "",
  "```sh",
  'echo "hi there"',
  "```",
  "",
  "```console",
  "$ noeta build",
  "```",
  "",
  "```noeta",
  "fn q() {",
  "  let rows = @sql{ SELECT id FROM users WHERE age > ${min} }",
  "}",
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

// The sidebar install command as shiki's shellscript grammar renders it (pinned): the command
// word colored as a function, flags/args in the grammar's argument coloring, the shell
// continuations preserved as text so the block still pastes as-is.
const INSTALL_HTML =
  '<span class="line"><span style="color:var(--syn-fn)">noeta</span><span style="color:var(--syn-string)"> add</span>' +
  '<span style="color:var(--syn-string)"> \\</span></span>\n' +
  '<span class="line"><span style="color:var(--syn-string)">  --package</span><span style="color:var(--syn-string)"> acme/greeter</span>' +
  '<span style="color:var(--syn-string)"> \\</span></span>\n' +
  '<span class="line"><span style="color:var(--syn-string)">  --version</span><span style="color:var(--syn-string)"> ^1.1.0</span></span>';

// The sidebar's one-line TOML dependency snippet through shiki's toml grammar (pinned): strings
// colored, the quotes left literal in text nodes (shiki escapes only <, >, & there).
const MANIFEST_HTML =
  '<span class="line"><span style="color:var(--text-0)">greeter = { version = </span>' +
  '<span style="color:var(--syn-string)">"^1.1.0"</span><span style="color:var(--text-0)">, package = </span>' +
  '<span style="color:var(--syn-string)">"acme/greeter"</span><span style="color:var(--text-0)"> }</span></span>';

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
  await post("/packages/acme/langs", { version: "0.1.0", url: "https://github.com/acme/langs", tag: "v0.1.0", sha: "bcd" }, TOKEN);
  expect((await putText("/packages/acme/langs/readme/0.1.0", LANGS_README, TOKEN)).status).toBe(200);
  // A README-sized document (many prose sections + fences) for the cold-render timing probe.
  await post("/packages/acme/bigread", { version: "1.0.0", url: "https://github.com/acme/bigread", tag: "v1.0.0", sha: "cde" }, TOKEN);
  const bigSection = [
    "## Section",
    "",
    "Some prose with `code`, **bold**, and a [link](https://noeta.dev).",
    "",
    "```noeta",
    NOETA_SNIPPET,
    "```",
    "",
    "```rust",
    'fn main() { println!("hi") }',
    "```",
    "",
  ].join("\n");
  expect((await putText("/packages/acme/bigread/readme/1.0.0", `# big\n\n${bigSection.repeat(30)}`, TOKEN)).status).toBe(200);
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
  // A release whose git coordinates carry HTML and a javascript: URL. `url`/`tag` are only
  // shape-checked at publish, and the transparency-log record echoes them verbatim — so the proof
  // page is one more surface that has to render publisher input inert.
  await post(
    "/packages/acme/nasty",
    {
      version: "1.0.0",
      url: 'javascript:alert(1)//<img src=x onerror="alert(2)">',
      tag: "<script>alert(3)</script>",
      sha: "f0f",
    },
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
    // every script the page serves has its hash in the CSP. The docs tab serves four (copy, the
    // shared chrome drawer, the log-proof modal, and docs search); recompute each from the served
    // bytes and require it in script-src, so editing a script without updating its hash (or vice
    // versa) fails here.
    // The drawer's source lives in @noeta/theme, so this is also what catches a chrome change
    // landing in the sibling repo without a matching hash bump here.
    const sha256 = async (s: string) =>
      "sha256-" + btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)))));
    const r = await web("/acme/greeter/1.1.0/docs");
    const body = await r.text();
    const scripts = [...body.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((m) => m[1]);
    expect(scripts.length, "the docs tab serves the copy, drawer, proof-modal and docs-search scripts").toBe(4);
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
    // The ```sh fence survives — now shiki-highlighted (shellscript), its text in token spans.
    expect(body).toContain(`<pre class="shellscript-code"><code>`);
    expect(body).toContain(">noeta</span>");
    expect(body).not.toContain("<script>alert(2)</script>"); // escaped, not executable
    expect(body).toContain("&lt;script&gt;alert(2)&lt;/script&gt;");
    // 1.0.0 has no README — its page renders without one.
    const old = await (await web("/acme/greeter/1.0.0")).text();
    expect(old).not.toContain("friendly");
  });

  it("renders documentation from the stored docs.json", async () => {
    const body = await (await web("/acme/greeter/1.1.0/docs")).text();
    expect(body).toContain("greeter.lib"); // module heading
    // The signature block is Noeta code, so it renders through the canonical grammar; the plain
    // text still rides the decl's data-text attribute for the search filter.
    expect(body).toContain(
      `<pre class="sig"><code><span class="line"><span style="color:var(--syn-keyword)">pub</span>` +
        `<span style="color:var(--syn-keyword)"> fn</span><span style="color:var(--syn-fn)"> greet</span>` +
        `<span style="color:var(--text-0)">(who: </span><span style="color:var(--syn-type)">string</span>` +
        `<span style="color:var(--text-0)">): </span><span style="color:var(--syn-type)">string</span></span></code></pre>`,
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

describe("noeta syntax highlighting (shiki, canonical grammar)", () => {
  it("renders a ```noeta fence into the exact pinned shiki spans, every entity escaped exactly once", async () => {
    const body = await (await web("/acme/codey")).text();
    // The fence body is threaded to shiki RAW, so the page carries the exact pinned markup —
    // including the single-escaped `<` and the `${…}` hole spans.
    expect(body).toContain(`<pre class="noeta-code"><code>${NOETA_SNIPPET_HTML}</code></pre>`);
    // Double-escape tripwires: pre-escaped text fed back through an escaping renderer would
    // produce these.
    expect(body).not.toContain("&amp;lt;");
    expect(body).not.toContain("&amp;quot;");
    expect(body).not.toContain("&amp;amp;");
    expect(body).not.toContain("&amp;#x3C;");
  });

  it("highlights rust, sql, jsonc, yaml, and sh fences through their bundled grammars", async () => {
    const codey = await (await web("/acme/codey")).text();
    // The rust fence — previously plain — now carries real rust tokens.
    expect(codey).toContain(
      `<pre class="rust-code"><code><span class="line"><span style="color:var(--syn-keyword)">fn</span>` +
        `<span style="color:var(--syn-fn)"> main</span>`,
    );
    const langs = await (await web("/acme/langs")).text();
    expect(langs).toContain(`<pre class="sql-code"><code>`);
    expect(langs).toContain(`<span style="color:var(--syn-keyword)">SELECT</span>`);
    expect(langs).toContain(`<pre class="jsonc-code"><code>`);
    expect(langs).toMatch(/class="jsonc-code"><code>[\s\S]*?var\(--syn-comment\)[\s\S]*?\/\/ trailing note/);
    expect(langs).toContain(`<pre class="yaml-code"><code>`);
    expect(langs).toMatch(/class="yaml-code"><code>[\s\S]*?style="color:var\(--syn-/);
    // `sh` resolves through the grammar's aliases to shellscript; `console` to shellsession.
    expect(langs).toContain(`<pre class="shellscript-code"><code>`);
    expect(langs).toContain(`<pre class="shellsession-code"><code>`);
  });

  it("keeps a fence in a language shiki does not know plain escaped", async () => {
    const body = await (await web("/acme/codey")).text();
    expect(body).toContain(`<pre><code>&lt;b&gt;not &amp; &quot;highlighted&quot;&lt;/b&gt;</code></pre>`);
    expect(body).not.toContain(`zzz-unknown-code`);
  });

  it("colors an embedded @sql tier body inside a noeta fence via the injection grammar", async () => {
    const body = await (await web("/acme/langs")).text();
    const block = body.match(/<pre class="noeta-code"><code>([\s\S]*?)<\/code><\/pre>/);
    expect(block).not.toBeNull();
    // The @sql opener carries the tier accent, and the body gets REAL SQL keyword tokens.
    expect(block![1]).toContain(`<span style="color:var(--accent-2-bright)">@sql</span>`);
    expect(block![1]).toContain(`<span style="color:var(--syn-keyword)">SELECT</span>`);
    expect(block![1]).toContain(`<span style="color:var(--syn-keyword)">FROM</span>`);
    // The ${…} hole delimiters keep the hole accent inside the tier body.
    expect(block![1]).toContain(`<span style="color:var(--syn-hole)">\${</span>`);
  });

  it("renders a /docs signature with shiki token spans", async () => {
    const body = await (await web("/acme/std/1.0.0/docs")).text();
    expect(body).toContain(
      `<pre class="sig"><code><span class="line"><span style="color:var(--syn-keyword)">fn</span>` +
        `<span style="color:var(--syn-fn)"> sqrt</span>`,
    );
  });

  it("keeps a hostile noeta fence inert — the payload cannot leave the code element", async () => {
    const body = await (await web("/acme/codey")).text();
    expect(body).not.toContain("</code><script>");
    expect(body).not.toContain("<script>alert(3)");
    // The payload is present, but its `<` land escaped inside shiki's text nodes.
    expect(body).toContain("&#x3C;/code>&#x3C;script>");
  });
});

describe("toml syntax highlighting", () => {
  it("carries the pinned shiki spans on the sidebar install and TOML snippets", async () => {
    const body = await (await web("/acme/greeter")).text();
    expect(body).toContain(INSTALL_HTML);
    expect(body).toContain(MANIFEST_HTML);
  });

  it("renders a ```toml README fence through the toml grammar", async () => {
    const body = await (await web("/acme/codey")).text();
    const block = body.match(/<pre class="toml-code"><code>([\s\S]*?)<\/code><\/pre>/);
    expect(block).not.toBeNull();
    // The version-requirement string is colored; the table header survives as text content.
    expect(block![1]).toContain(`<span style="color:var(--syn-string)">"^0.1.0"</span>`);
    expect(block![1].replace(/<[^>]+>/g, "")).toContain("[dependencies]");
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
      `<div class="snippet"><pre class="noeta-code"><code><span class="line">` +
        `<span style="color:var(--syn-keyword)">fn</span><span style="color:var(--syn-fn)"> greet</span>`,
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
    // codey's README: noeta, rust, toml, unknown, and noe fences — five blocks, plus two sidebar
    // snippets.
    const readme = await (await web("/acme/codey")).text();
    expect((readme.match(/class="copy-btn"/g) || []).length).toBe(7);
    // Highlighted and plain fences alike sit in the .snippet wrapper the delegated script serves.
    expect(readme).toContain('<div class="snippet"><pre class="noeta-code">');
    expect(readme).toContain('<div class="snippet"><pre class="toml-code">');
    expect(readme).toContain('<div class="snippet"><pre><code>&lt;b&gt;not');
    // Docs signature blocks get the same affordance.
    const docs = await (await web("/acme/std/1.0.0/docs")).text();
    expect(docs).toContain('<div class="snippet"><pre class="sig">');
  });

  it("copies the RAW code of a highlighted block — textContent round-trips exactly", async () => {
    // COPY_SCRIPT copies the <code> element's textContent. Simulate that: strip the spans and
    // decode the entities of the served noeta block; the result must be the exact raw snippet —
    // including the `<`, `"`, and `${…}` the fence body carried. Shiki emits hex numeric
    // references (&#x3C;) in text nodes, so the decoder handles those plus the named set.
    const body = await (await web("/acme/codey")).text();
    const m = body.match(/<pre class="noeta-code"><code>([\s\S]*?)<\/code><\/pre>/);
    expect(m).not.toBeNull();
    const textContent = m![1]
      .replace(/<[^>]+>/g, "")
      .replace(/&#x([0-9A-Fa-f]+);/g, (_, hex) => String.fromCodePoint(parseInt(hex, 16)))
      .replace(/&#(\d+);/g, (_, dec) => String.fromCodePoint(parseInt(dec, 10)))
      .replace(/&lt;/g, "<")
      .replace(/&gt;/g, ">")
      .replace(/&quot;/g, '"')
      .replace(/&#39;/g, "'")
      .replace(/&amp;/g, "&");
    expect(textContent).toBe(NOETA_SNIPPET);
  });
});

describe("transparency-log entry (the human surface)", () => {
  const proofJson = async (name: string, version: string) =>
    (await (await SELF.fetch(`https://registry.test/v1/log/proof/${name}/${version}`)).json()) as {
      index: number;
      tree_size: number;
      root_hash: string;
      record: string;
      proof: string[];
    };

  it("points the sidebar at the rendered entry, not the raw JSON", async () => {
    const body = await (await web("/acme/greeter/1.1.0")).text();
    const { index } = await proofJson("acme/greeter", "1.1.0");
    expect(body).toContain(`<a class="log-link" href="/acme/greeter/1.1.0/log">#${index}</a>`);
    // The JSON endpoint is no longer what a reader lands on from the rail.
    expect(body).not.toContain(`href="/v1/log/proof/acme/greeter/1.1.0"`);
    // The dialog the enhancement fills is server-rendered, so it exists before any script runs.
    expect(body).toContain(`<dialog id="proof-modal"`);
    expect(body).toContain(`<div class="modal-body"></div>`);
  });

  it("renders the entry as a page: what was logged, the tree head, and the audit path", async () => {
    const r = await web("/acme/greeter/1.1.0/log");
    expect(r.status).toBe(200);
    expect(r.headers.get("content-type")).toContain("text/html");
    const body = await r.text();
    const proof = await proofJson("acme/greeter", "1.1.0");
    expect(body).toContain("Transparency-log entry");
    // The tree head this is proven against, and every sibling on the path to it.
    expect(body).toContain(proof.root_hash);
    for (const sibling of proof.proof) expect(body).toContain(sibling);
    // What was logged, decoded — plus the canonical bytes themselves, which are what a client hashes.
    expect(body).toContain(LATEST_SHA);
    expect(body).toContain("MIT OR Apache-2.0");
    expect(body).toContain("https://github.com/acme/greeter");
    expect(body).toContain("noeta-transparency-log-v1");
    // The machine surface stays one click away rather than being replaced.
    expect(body).toContain(`href="/v1/log/proof/acme/greeter/1.1.0"`);
    expect(body).toContain(`href="/v1/log/checkpoint"`);
  });

  it("serves the bare card to the modal's fetch", async () => {
    const r = await web("/acme/greeter/1.1.0/log?fragment=1");
    expect(r.status).toBe(200);
    const body = await r.text();
    expect(body.startsWith(`<section class="proof">`)).toBe(true);
    // A fragment, not a document — the modal injects it into a page that already has chrome.
    expect(body).not.toContain("<!doctype html>");
    expect(body).not.toContain("site-foot");
    // Same card as the page serves.
    const page = await (await web("/acme/greeter/1.1.0/log")).text();
    expect(page).toContain(body.trim());
  });

  it("404s a release with no log entry, on both the page and the fragment", async () => {
    expect((await web("/acme/greeter/9.9.9/log")).status).toBe(404);
    expect((await web("/acme/nope/1.0.0/log")).status).toBe(404);
    // The modal's fetch sees the failure and falls back to navigating to the (404) page.
    const fragment = await web("/acme/nope/1.0.0/log?fragment=1");
    expect(fragment.status).toBe(404);
    expect(await fragment.text()).toBe("");
  });

  it("renders publisher-controlled record fields inert", async () => {
    const body = await (await web("/acme/nasty/1.0.0/log")).text();
    expect(body).toContain("&lt;script&gt;alert(3)&lt;/script&gt;");
    expect(body).not.toContain("<script>alert(3)</script>");
    // The <img> payload survives only as text: no tag, and no attribute an escape would have opened.
    expect(body).toContain("&lt;img src=x onerror=&quot;alert(2)&quot;&gt;");
    expect(body).not.toContain(`onerror="`);
    // A javascript: repository URL is shown as text, never linked.
    expect(body).not.toContain(`href="javascript:`);
    expect(body).toContain("javascript:alert(1)");
  });

  it("allows the modal's same-origin fetch without loosening script-src", async () => {
    const csp = (await web("/acme/greeter/1.1.0")).headers.get("content-security-policy") ?? "";
    expect(csp).toContain("connect-src 'self'");
    const scriptSrc = csp.match(/script-src ([^;]*)/)?.[1] ?? "";
    expect(scriptSrc).not.toContain("'unsafe-inline'");
    expect(scriptSrc).not.toContain("'self'");
  });
});

describe("render cache (rendered_pages)", () => {
  // Isolated storage means every test here must populate the cache itself (a fetch inside an
  // earlier test is undone when that test ends) — each test is a self-contained story.
  const row = (name: string, version: string, kind: string) =>
    env.DB.prepare("SELECT renderer_rev, html FROM rendered_pages WHERE name = ? AND version = ? AND kind = ?")
      .bind(name, version, kind)
      .all<{ renderer_rev: string; html: string }>();

  it("stores the rendered readme, docs, and sidebar fragments under the current renderer rev", async () => {
    await web("/acme/greeter");
    await web("/acme/std/1.0.0/docs");
    for (const [name, version, kind] of [
      ["acme/greeter", "1.1.0", "readme"],
      ["acme/greeter", "1.1.0", "side"],
      ["acme/std", "1.0.0", "docs"],
      ["acme/std", "1.0.0", "side"],
    ] as const) {
      const { results } = await row(name, version, kind);
      expect(results.map((r) => r.renderer_rev), `${name}@${version} ${kind}`).toEqual([RENDERER_REV]);
    }
  });

  it("serves the second view from D1 — mutating the cached row changes the page", async () => {
    await web("/acme/greeter"); // miss: renders and stores
    await env.DB.prepare(
      "UPDATE rendered_pages SET html = ? WHERE name = 'acme/greeter' AND version = '1.1.0' AND kind = 'readme'",
    )
      .bind(`<p id="from-cache-sentinel">served from D1</p>`)
      .run();
    const body = await (await web("/acme/greeter")).text();
    // The sentinel proves the page body came from the mutated row, not a re-render.
    expect(body).toContain("from-cache-sentinel");
    expect(body).not.toContain("A <strong>friendly</strong> greeting library.");
  });

  it("treats a renderer_rev bump as a miss and retires the stale row on write", async () => {
    // A row from a hypothetical older renderer: wrong rev, poisoned content.
    await env.DB.prepare(
      "INSERT INTO rendered_pages (name, version, kind, renderer_rev, html, created_at) VALUES " +
        "('acme/greeter', '1.1.0', 'readme', 'stale-rev-0', '<p id=\"stale-poison\">old renderer</p>', '2020-01-01T00:00:00Z')",
    ).run();
    const body = await (await web("/acme/greeter")).text();
    // The stale row is NOT served — the rev mismatch forced a fresh render.
    expect(body).not.toContain("stale-poison");
    expect(body).toContain("A <strong>friendly</strong> greeting library.");
    // And the write opportunistically deleted the stale row, leaving only the current rev.
    const { results } = await row("acme/greeter", "1.1.0", "readme");
    expect(results.map((r) => r.renderer_rev)).toEqual([RENDERER_REV]);
  });

  it("shares the cached sidebar snippets across tabs", async () => {
    await web("/acme/greeter/1.1.0/versions"); // populates kind='side'
    await env.DB.prepare(
      "UPDATE rendered_pages SET html = ? WHERE name = 'acme/greeter' AND version = '1.1.0' AND kind = 'side'",
    )
      .bind(`<p id="side-cache-sentinel">cached rail</p>`)
      .run();
    // A different tab still serves the (mutated) cached snippets — one fragment, every tab.
    const deps = await (await web("/acme/greeter/1.1.0/deps")).text();
    expect(deps).toContain("side-cache-sentinel");
  });

  it("bypasses the docs cache for a ?q= search (its filtering is query-dependent)", async () => {
    await web("/acme/std/1.0.0/docs"); // populates kind='docs' (unqueried render)
    await env.DB.prepare(
      "UPDATE rendered_pages SET html = ? WHERE name = 'acme/std' AND version = '1.0.0' AND kind = 'docs'",
    )
      .bind(`<p id="docs-cache-sentinel">cached docs</p>`)
      .run();
    // Unqueried: served from the mutated cache.
    expect(await (await web("/acme/std/1.0.0/docs")).text()).toContain("docs-cache-sentinel");
    // Queried: rendered live — the sentinel never appears, the filter markup does.
    const searched = await (await web("/acme/std/1.0.0/docs?q=sqrt")).text();
    expect(searched).not.toContain("docs-cache-sentinel");
    expect(searched).toContain(`class="docs-results searching"`);
  });

  it("invalidates the cached readme when a last-wins upload overwrites it", async () => {
    await web("/acme/codey"); // cache the original render
    expect((await row("acme/codey", "0.1.0", "readme")).results.length).toBe(1);
    expect(
      (await putText("/packages/acme/codey/readme/0.1.0", "# codey\n\nReplaced by a re-upload.", TOKEN)).status,
    ).toBe(200);
    // The PUT dropped the row, so the next view renders the NEW markdown.
    expect((await row("acme/codey", "0.1.0", "readme")).results.length).toBe(0);
    const body = await (await web("/acme/codey")).text();
    expect(body).toContain("Replaced by a re-upload.");
    expect(body).not.toContain("Highlighting fixture.");
  });

  it("cold-renders a README-sized page once, then serves it cached (timing probe)", async () => {
    // Rough wall-clock only (workerd advances timers on I/O, so CPU time under-reports): the
    // numbers are logged for the perf report, not asserted — flakiness lives in CI load.
    const t0 = Date.now();
    await web("/acme/bigread");
    const t1 = Date.now();
    const body = await (await web("/acme/bigread")).text();
    const t2 = Date.now();
    console.log(`[render-cache] bigread cold=${t1 - t0}ms warm=${t2 - t1}ms`);
    expect(body).toContain(`<pre class="noeta-code">`);
    // The warm view really was a cache hit.
    expect((await row("acme/bigread", "1.0.0", "readme")).results.length).toBe(1);
  });
});
