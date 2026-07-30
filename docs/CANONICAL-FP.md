# CANONICAL machine_key_fp field — ⚠ UNCONFIRMED (needs a LIVE control node)

> **This document is the freeze point for the first step of the device-license-registry
> `machine_key_fp` AUTO-CAPTURE rollout. Until a maintainer completes the steps below on a
> live headscale control node, the headscale-anchored re-validation SHIPS DARK
> (advisory) and Layer-B (per-node sshd, generator PR #68) remains the load-bearing
> SSH boundary.**

## Why this is blocking

The whole point of the AUTO-CAPTURE flow is that **one fingerprint string is identical
on every surface**:

```
device_registry.machine_key_fp  ==  headscale-reported fp  ==  node-baked MACHINE_KEY_FP
                                 ==  Layer-B baked (authorized-keys lookup %f match base)
                                 ==  Layer-A force-tag key
```

If the BFF stores a *different* representation of the fingerprint than what the node
bakes / what Layer-A and Layer-B key on, then `entry.fp == baked-fp` **never matches**
and the enforcement layers **fail closed and DENY EVERYONE**. So we must copy the
*correct, canonical* field — faithfully copying the wrong one is a silent fleet-wide
lockout.

## The ambiguity

- `provision.sh` (hugmesh-generator) bakes `MACHINE_KEY_FP` from
  `tailscale status --json | jq -r '.Self.PublicKey'` — i.e. the **node key**.
- `headscale nodes list -o json` reports BOTH a `machineKey` and a `nodeKey` per node
  (exact JSON key spelling varies by headscale version), and the Layer-A force-tags
  helper historically reached for `.machineKey // .nodeKey` **ambiguously**.
- These are **different keys**. Picking the wrong one for the BFF's stored
  `machine_key_fp` breaks the equality chain above.

We **cannot** resolve this in CI / this environment: there is no live headscale control
node here, and the JSON shape of `headscale nodes list -o json` is version-dependent and
unconfirmed.

## What ships TODAY (dark / advisory)

- `app.registry.headscale.fp-field` is a **config parameter**, default **`nodeKey`** —
  the design's best guess, chosen to MATCH what `provision.sh` already bakes
  (`.Self.PublicKey` == the node key, surfaced by `headscale nodes list` as `nodeKey`).
  The `HeadscaleNodesClient` reads the configured field, falling back to the two known
  spellings (`machineKey`, `nodeKey`) only to avoid a hard parse failure.
- `app.registry.headscale.allow-manual-fp` is a **break-glass, default ON**: the
  register-time headscale re-validation is advisory — on a mismatch / unreachable
  headscale / wrong field it accepts the superadmin-supplied opaque fingerprint anyway
  with a loud `WARN`. So a wrong default cannot brick registration; it just means the
  re-validation is not yet a real gate.
- `app.registry.headscale.enabled` is **default OFF**: no headscale binary is invoked at
  all (pending list is registry-only, register skips the re-query).

## What a maintainer MUST do on a LIVE control node to make Layer-A load-bearing

1. **Confirm the canonical field.** On the live headscale control node, run
   `headscale nodes list -o json` and compare a node's reported `machineKey` / `nodeKey`
   against that same node's baked `MACHINE_KEY_FP`
   (`cat /etc/hugmesh/registry/node.env`, the `MACHINE_KEY_FP=` line) and against the
   string Layer-A force-tags / Layer-B `%f` matching actually keys on. Identify the ONE
   field whose value is byte-identical across all surfaces.
2. **Freeze it here.** Replace this paragraph with the confirmed field name + a captured
   example (redact the key body), and set the confirmed value as the default of
   `app.registry.headscale.fp-field` (here, in `application.yml`, and in
   `RegistryHeadscaleProperties.DEFAULT_FP_FIELD`). Also confirm the generator's
   `provision.sh` and the Layer-A force-tags helper read the SAME field
   (the next step in this rollout).
3. **Enable + enforce.** Set `app.registry.headscale.enabled=true` (so the pending list
   shows real enrolled candidates and register re-queries), then — only after steps 1-2 —
   set `app.registry.headscale.allow-manual-fp=false` so register fails closed (409) on a
   fingerprint that is not actually enrolled / is in the wrong mesh.

Until step 3 is complete, **Layer-B (per-node sshd, generator PR #68) is the load-bearing
SSH boundary**; Layer-A (headscale policy) and this AUTO-CAPTURE re-validation are
defence-in-depth that ships dark.
