// SHA-256 of `test/fixtures/wire/MANIFEST.sha256` — the cross-repo protocol stamp.
//
// `test/fixtures/wire/` is a VERBATIM copy of the canonical fixture set in the language repo
// (`crates/noeta-pm/test_data/wire/`), and `MANIFEST.sha256` pins the fixtures. But the manifest
// lives *inside* the copied directory and is copied with it, so before this constant each repo
// hashed its own fixtures against its own manifest: edit a fixture there, regenerate the manifest,
// forget to copy — both suites green, protocol diverged. The hash test proved no local hand-edit had
// happened; it could not prove the copy was current, which is the case the sync ritual exists to
// prevent.
//
// This value is the one thing that is NOT inside the copied set. The language repo carries the
// identical stamp as `noeta_pm::registry::WIRE_MANIFEST_SHA256`, so a protocol change has to be
// acknowledged in each repo's *source*, not just have bytes dropped into a fixture directory:
// copying fixtures across without moving the stamp fails this repo's build, by name
// (`test/wire-fixtures.test.ts`).
//
// NEVER edit by hand. `scripts/sync-wire-fixtures.sh` in the language repo regenerates the manifest,
// rewrites both stamps and copies the set across in one step; `--check` asserts without writing.
//
// It lives under `src/` rather than `test/` because it is a fact about the protocol this Worker
// speaks, not about how it is tested — the Worker itself does not import it, and it is tree-shaken
// out of the deployed bundle.
export const WIRE_MANIFEST_SHA256 = "7b8b70d917b295839ccf548792e41339589375f519c3c3e434d25cf628ed69ae";
