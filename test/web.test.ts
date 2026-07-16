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

beforeAll(async () => {
  expect((await post("/scopes", { scope: "acme", token: TOKEN }, ADMIN)).status).toBe(201);
  await post("/packages/acme/greeter", { version: "1.0.0", url: "https://github.com/acme/greeter", tag: "v1.0.0", sha: "aaa" }, TOKEN);
  await post("/packages/acme/greeter", { version: "1.1.0", url: "https://github.com/acme/greeter", tag: "v1.1.0", sha: "bbb", license: "MIT OR Apache-2.0" }, TOKEN);
  expect((await putText("/packages/acme/greeter/docs/1.1.0", DOCS, TOKEN)).status).toBe(200);
  expect((await putText("/packages/acme/greeter/readme/1.1.0", README, TOKEN)).status).toBe(200);
  await post("/packages/acme/std", { version: "1.0.0", url: "https://github.com/acme/std", tag: "v1.0.0", sha: "ccc" }, TOKEN);
  expect((await putText("/packages/acme/std/docs/1.0.0", API_DOCS, TOKEN)).status).toBe(200);
});

describe("registry web UI", () => {
  it("serves an HTML home page listing published packages", async () => {
    const r = await web("/");
    expect(r.status).toBe(200);
    expect(r.headers.get("content-type")).toContain("text/html");
    const body = await r.text();
    expect(body).toContain("Noeta registry");
    expect(body).toContain("/acme/greeter");
  });

  it("shows a package page with the latest version, source, and version list", async () => {
    const body = await (await web("/acme/greeter")).text();
    // Latest by semver (1.1.0 > 1.0.0 — not lexicographic).
    expect(body).toMatch(/greeter<\/a>?[\s\S]*1\.1\.0/);
    expect(body).toContain("1.0.0"); // the older version is still listed
    expect(body).toContain("github.com/acme/greeter");
    expect(body).toContain("bbb"); // pinned commit of the latest
    // A docs link, because 1.1.0 has docs.
    expect(body).toContain("/acme/greeter/1.1.0/docs");
    // The declared license, as a badge on the selected version.
    expect(body).toContain(`<span class="badge license">MIT OR Apache-2.0</span>`);
    // 1.0.0 declared none — its page shows no license badge.
    const old = await (await web("/acme/greeter/1.0.0")).text();
    expect(old).not.toContain(`badge license`);
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
