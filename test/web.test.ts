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

beforeAll(async () => {
  expect((await post("/scopes", { scope: "acme", token: TOKEN }, ADMIN)).status).toBe(201);
  await post("/packages/acme/greeter", { version: "1.0.0", url: "https://github.com/acme/greeter", tag: "v1.0.0", sha: "aaa" }, TOKEN);
  await post("/packages/acme/greeter", { version: "1.1.0", url: "https://github.com/acme/greeter", tag: "v1.1.0", sha: "bbb" }, TOKEN);
  expect((await putText("/packages/acme/greeter/docs/1.1.0", DOCS, TOKEN)).status).toBe(200);
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
