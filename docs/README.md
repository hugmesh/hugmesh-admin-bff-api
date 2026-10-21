# admin-bff-api docs index

This directory is this repo's "wiki". The HugMesh platform does not use GitHub's
built-in wiki: each repo's `docs/` tree holds the longer documentation that sits next
to the code. Start with the top-level [`README.md`](../README.md) for the architecture
overview, endpoint catalogue and security model. The pages here go deeper on
subsystems that do not fit that file, or that are still open design questions.

| Page | What it covers | Status |
|---|---|---|
| [`SUBSYSTEMS.md`](SUBSYSTEMS.md) | The shipped subsystems that aren't yet covered by the main README's endpoint catalogue (local login, go-live wizard, account-ban appeals, Mastodon appearance defaults, character/sticker moderation activation, optional-services reconciler, node radio attachments, federation bearer-forwarding, edge-AI infra triage, the a11y profile forwarder) | Real code on `main`, kept in sync with source |
| [`CANONICAL-FP.md`](CANONICAL-FP.md) | The still-open question of which headscale-reported key (`machineKey` vs `nodeKey`) is the canonical `device_registry.machine_key_fp` for the device-license AUTO-CAPTURE flow, and the steps a maintainer must run on a **live** headscale control node to resolve it | ⚠ Unresolved — needs a live control node this environment does not have |

## Conventions

- **Freshness.** Every page here should describe what is on `main`. If a claim no
  longer matches `src/main/java`, the code is right: fix or delete the page.
- **State markers.** Pages use the same convention as the top-level README: **✅
  shipped** (merged to `main`), **🚧 in-flight** (open branch/PR), **🔭 planned**
  (design only, no code).
- Cross-repo docs referenced from here (for example the platform reactive-BFF contract
  in `hugmesh-generator/tests/stack/mock-bff.mjs`, or the generator's
  device-provisioning scripts) live in their own repos. This index covers only the
  pages in this repo's `docs/`.
