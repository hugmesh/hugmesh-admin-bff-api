# admin-bff-api docs index

This directory is this repo's "wiki" (the HugMesh platform does not use GitHub's
built-in wiki feature — each repo's `docs/` tree is the canonical place for
longer-form, code-adjacent documentation). Start with the top-level
[`README.md`](../README.md) for the architecture overview, endpoint catalogue, and
security model; the pages here go deeper on specific subsystems that don't fit that
file, or that are still open design questions.

| Page | What it covers | Status |
|---|---|---|
| [`SUBSYSTEMS.md`](SUBSYSTEMS.md) | The shipped subsystems that aren't yet covered by the main README's endpoint catalogue (local login, go-live wizard, account-ban appeals, Mastodon appearance defaults, character/sticker moderation activation, optional-services reconciler, node radio attachments, federation bearer-forwarding, edge-AI infra triage, the a11y profile forwarder) | Real code on `main`, kept in sync with source |
| [`CANONICAL-FP.md`](CANONICAL-FP.md) | The still-open question of which headscale-reported key (`machineKey` vs `nodeKey`) is the canonical `device_registry.machine_key_fp` for the device-license AUTO-CAPTURE flow, and the steps a maintainer must run on a **live** headscale control node to resolve it | ⚠ Unresolved — needs a live control node this environment does not have |

## Conventions

- **Freshness.** Every page here should describe what is actually on `main` as of its
  own text — if you find a claim here that no longer matches `src/main/java`, treat the
  code as ground truth and fix (or delete) the page, not the other way around.
- **State markers.** Pages use the same convention as the top-level README: **✅
  shipped** (merged to `main`), **🚧 in-flight** (open branch/PR), **🔭 planned**
  (design only, no code).
- Cross-repo docs referenced from here (e.g. the platform reactive-BFF contract in
  `hugmesh-generator/tests/stack/mock-bff.mjs`, or the generator's device-provisioning
  scripts) live in their own repos — this index only covers pages physically in this
  repo's `docs/`.
