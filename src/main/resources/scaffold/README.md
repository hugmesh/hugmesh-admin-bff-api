# Embedded scaffold archetype codebases

This directory holds the **example starter codebases** the SUPERADMIN Service-Store
*scaffold* surface renders and hands to a brand as a downloadable ZIP
(`GET /bff/superadmin/service-store/{domain}/scaffold/{id}/archive`).

Each sub-directory is one archetype:

| archetype        | what it renders                                                         |
|------------------|-------------------------------------------------------------------------|
| `spring-bff`     | a minimal, runnable Spring Boot 4 WebFlux BFF (Java 25, hugmesh-parent) |
| `angular-mfe`    | an Angular 22 native-federation **remote** exposing `./routes`           |
| `angular-host`   | an Angular 22 native-federation **host shell** (dynamic manifest union)  |
| `remote-fragment`| a pointer README to the real base as the fragment example                |

## Provenance — VENDORED, not hand-authored

These trees are a **build-time copy** of the canonical source of truth in the
generator repo:

```
hugmesh-generator  templates/archetypes/<archetype>/_skeleton/
```

vendored from generator commit `05fcab39ef09d8265eb60888fbac999cf9fa1a58`.

The copy is mechanical and lossless:

- every `<file>.hbs` becomes `<file>` (the `.hbs` suffix is stripped);
- the file **content is verbatim** — the `{{TOKEN}}` placeholders are kept
  exactly as the generator authors them (they are rendered at request time by
  `TokenRenderer`, not at copy time);
- file **paths are unchanged** (the Java sources stay under the neutral
  `src/main/java/net/hugmesh/app/` directory the generator uses; the
  scaffold renderer relocates them into the real package path per request — see
  `ScaffoldService`).

This mirrors the existing `resources/catalog/*.json` vendoring convention
(`ImageCatalogProvider`): a single source of truth in the generator, copied in,
never forked.

## Resync procedure

When the generator archetype skeletons change, re-vendor them:

```sh
GEN=<hugmesh-generator checkout>/templates/archetypes
DST=src/main/resources/scaffold
rm -rf "$DST"/{spring-bff,angular-mfe,angular-host,remote-fragment}
for a in spring-bff angular-mfe angular-host remote-fragment; do
  SRC="$GEN/$a/_skeleton"
  while IFS= read -r f; do
    rel="${f#"$SRC/"}"; out="$DST/$a/${rel%.hbs}"
    mkdir -p "$(dirname "$out")"; cp "$f" "$out"
  done < <(find "$SRC" -type f)
done
```

Then bump the generator commit hash recorded above and in the module `README.md`,
and re-run the scaffold render tests (`ScaffoldServiceTest`,
`TokenRendererTest`) — they hard-fail on any unrendered `{{UPPER_SNAKE}}`
residual, so a newly-introduced token is caught immediately (add it to
`TokenRenderer`'s context map).

## No secrets

The skeletons carry **no secret material** — every credential is an
`${ENV:default}` seam with an empty default (config is injected at deploy time).
`ScaffoldServiceTest` asserts the rendered output contains no PEM private-key
blocks, so a future skeleton edit that leaks a secret fails the build.
