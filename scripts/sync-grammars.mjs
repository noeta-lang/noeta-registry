/**
 * Populates `syntaxes/` with the canonical Noeta TextMate grammars from the
 * language repo, for the shiki highlighter in src/shiki.ts (which imports them
 * as JSON at bundle time). Invoked by the dev/test/typecheck/deploy scripts in
 * package.json, so each works from a fresh clone without manual setup;
 * `syntaxes/` is generated and gitignored.
 *
 * Adapted from the same-named script in the noeta-docs repo (the precedent for
 * rendering Noeta through the canonical grammar); the Astro cache-busting step
 * is dropped — the registry has no content-layer cache. The render cache in D1
 * is keyed by RENDERER_REV (src/render-cache.ts), which is bumped by hand when
 * grammars change.
 *
 * Two grammars are synced:
 *   - noeta.tmLanguage.json          — the core language grammar (source.noeta)
 *   - tier-languages.tmLanguage.json — the injection grammar that colors
 *     embedded-language tier bodies (@sql/@html/… → that language's grammar,
 *     ${…} holes back to source.noeta); injected into source.noeta by the
 *     shiki registration in src/shiki.ts.
 *
 * Two sources, in order of preference (same shape as noeta-docs):
 *   1. A local sibling checkout (`../lang`, or $NOETA_GRAMMAR_LOCAL) — the
 *      normal development setup, always freshly copied (cheap).
 *   2. A blobless sparse `git` clone of the hosted repo — CI and machines
 *      without the language checkout. No token needed for a public repo.
 *
 * Env:
 *   NOETA_GRAMMAR_LOCAL — path to a local syntaxes/ dir (default:
 *                         ../lang/editors/vscode-noeta/syntaxes, when it exists)
 *   NOETA_GRAMMAR_REPO  — GitHub repo for the clone fallback
 *                         (default noeta-lang/noeta)
 *   NOETA_GRAMMAR_REF   — branch or tag to pull from (default main)
 *   NOETA_SKIP_SYNC=1   — short-circuit entirely; require existing syntaxes/
 */

import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { cp, mkdir, rm } from "node:fs/promises";
import { join, resolve } from "node:path";

const GRAMMARS = ["noeta.tmLanguage.json", "tier-languages.tmLanguage.json"];
const GRAMMAR_PATH = "editors/vscode-noeta/syntaxes";

const repoRoot = process.cwd();
const outDir = resolve(repoRoot, "syntaxes");
const tmpDir = resolve(repoRoot, ".noeta-grammar.tmp");

const LOCAL =
  process.env.NOETA_GRAMMAR_LOCAL ?? resolve(repoRoot, "..", "lang", GRAMMAR_PATH);
const REPO = process.env.NOETA_GRAMMAR_REPO ?? "noeta-lang/noeta";
const REF = process.env.NOETA_GRAMMAR_REF ?? "main";

const haveGrammars = () => GRAMMARS.every((g) => existsSync(join(outDir, g)));

if (process.env.NOETA_SKIP_SYNC === "1") {
  if (!haveGrammars()) {
    console.error("[sync-grammars] FATAL: NOETA_SKIP_SYNC=1 but syntaxes/ is incomplete");
    process.exit(1);
  }
  console.log("[sync-grammars] Skipping (NOETA_SKIP_SYNC=1); using existing syntaxes/");
  process.exit(0);
}

async function copyFrom(dir) {
  await mkdir(outDir, { recursive: true });
  for (const g of GRAMMARS) {
    const src = join(dir, g);
    if (!existsSync(src)) throw new Error(`${g} not found in ${dir}`);
    await cp(src, join(outDir, g));
  }
}

function syncFromClone() {
  console.log(`[sync-grammars] Cloning ${GRAMMAR_PATH} from ${REPO}@${REF}`);
  execFileSync(
    "git",
    ["clone", "--depth", "1", "--branch", REF, "--filter=blob:none", "--sparse", `https://github.com/${REPO}.git`, tmpDir],
    { stdio: ["ignore", "inherit", "inherit"] },
  );
  execFileSync("git", ["-C", tmpDir, "sparse-checkout", "set", GRAMMAR_PATH], {
    stdio: ["ignore", "inherit", "inherit"],
  });
}

try {
  if (existsSync(LOCAL)) {
    console.log(`[sync-grammars] Copying grammars from local checkout ${LOCAL}`);
    await copyFrom(LOCAL);
  } else {
    await rm(tmpDir, { recursive: true, force: true });
    syncFromClone();
    await copyFrom(join(tmpDir, GRAMMAR_PATH));
    await rm(tmpDir, { recursive: true, force: true });
  }
  console.log(
    `[sync-grammars] syntaxes/{${GRAMMARS.join(",")}} up to date (${existsSync(LOCAL) ? "local" : `${REPO}@${REF}`})`,
  );
} catch (err) {
  await rm(tmpDir, { recursive: true, force: true });
  if (haveGrammars()) {
    console.warn(`[sync-grammars] WARNING: ${err.message}; using existing syntaxes/`);
  } else {
    console.error(`[sync-grammars] FATAL: ${err.message}`);
    process.exit(1);
  }
}
