import { SELF } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";

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

beforeAll(async () => {
  expect((await post("/scopes", { scope: "acme", token: TOKEN }, ADMIN)).status).toBe(201);
  await post("/packages/acme/greeter", { version: "1.0.0", url: "https://github.com/acme/greeter", tag: "v1.0.0", sha: "aaa" }, TOKEN);
  // A full-length SHA, so the page's rendering of it is exercised at its real width.
  await post("/packages/acme/greeter", { version: "1.1.0", url: "https://github.com/acme/greeter", tag: "v1.1.0", sha: LATEST_SHA, license: "MIT OR Apache-2.0" }, TOKEN);
  expect((await putText("/packages/acme/greeter/docs/1.1.0", DOCS, TOKEN)).status).toBe(200);
  expect((await putText("/packages/acme/greeter/readme/1.1.0", README, TOKEN)).status).toBe(200);
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
  });

  it("pins every served script in the CSP by its real hash", async () => {
    // Inline scripts are allowed only when pinned by SHA-256 — the anti-XSS property holds only if
    // every script the page serves has its hash in the CSP. The docs tab serves two (copy + docs
    // search); recompute both from the served bytes and require each in script-src, so editing a
    // script without updating its hash (or vice versa) fails here.
    const sha256 = async (s: string) =>
      "sha256-" + btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)))));
    const r = await web("/acme/greeter/1.1.0/docs");
    const body = await r.text();
    const scripts = [...body.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((m) => m[1]);
    expect(scripts.length, "the docs tab serves the copy and docs-search scripts").toBe(2);
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
    // Shell continuations keep the whole command visible in the narrow rail; it pastes as-is.
    expect(body).toContain("noeta add \\\n  --package acme/greeter \\\n  --version ^1.1.0");
    // Escape-first: the quotes are entity-escaped in the source and render as `"` in the browser.
    expect(body).toContain(
      `greeter = { version = &quot;^1.1.0&quot;, package = &quot;acme/greeter&quot; }`,
    );
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
    expect(versions).toContain("noeta add \\\n  --package acme/greeter \\\n  --version ^1.1.0");

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
    expect(body).toContain("pub fn greet(who: string): string"); // signature code block
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
