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

These trees are a **build-time copy** of the source of truth in the generator repo:

```
hugmesh-generator  templates/archetypes/<archetype>/_skeleton/
```

The first copy came from generator commit `05fcab39ef09d8265eb60888fbac999cf9fa1a58`.
That commit is not in the generator's history today (a fetch of `origin/main` on
2026-10-07 does not have it).

The copy rule:

- every `<file>.hbs` becomes `<file>` (the `.hbs` suffix is stripped);
- the `{{TOKEN}}` placeholders stay as the generator wrote them. `TokenRenderer`
  fills them at request time, not at copy time;
- the Java sources sit under the neutral `src/main/java/net/hugmesh/app/` directory,
  and `ScaffoldArchiveRenderer` moves them into the real package path per request.

The trees are no longer a clean copy. Compared with generator `main` on 2026-10-07:

- The generator keeps the Java sources under `src/main/java/systems/hugmesh/app/` and
  declares `systems.hugmesh`. This repo moved to `net.hugmesh` in commit `877de6e`
  (`pom.xml`, `settings.xml`, the `Dockerfile`, the README and the Java files).
- Other `spring-bff` files differ too. `deploy/deployment.yaml` and
  `deploy/kustomization.yaml` fix the namespace to `hugmesh-backend` and the image to
  `hugmesh-systems/`, where the generator uses `{{BRAND}}-backend` and `hugmesh/`. The
  generator's `Dockerfile` also reads a `packages_read_token` secret, and the generator
  has a `.github/maven-ci-settings.xml` that this copy lacks.
- `angular-mfe` differs in `federation-base.js` and `src/styles.scss`, and
  `angular-host` in `src/styles.scss`.
- The `README.md` files here carry corrected pointers (`angular-host`,
  `remote-fragment`, `spring-bff`). The generator's copies still carry the old ones.

The `resources/catalog/*.json` vendoring (`ImageCatalogProvider`) follows the same
idea: one source of truth in the generator, copied in.

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

**Do not run this as it stands.** It copies the generator's
`systems/hugmesh/app/` Java path, and `ScaffoldArchiveRenderer` relocates only
`net/hugmesh/app/`. After a resync, move the Java sources (main and test) back to
`net/hugmesh/app/` and rename `systems.hugmesh` to `net.hugmesh`. Diff first: the
`rm -rf` also drops every change made here.

Then bump the generator commit hash recorded above, and re-run the scaffold render
tests (`ScaffoldArchiveRendererTest`, `TokenRendererTest`, `ScaffoldServiceTest`).
The render hard-fails on any unrendered `{{UPPER_SNAKE}}` residual, so a
newly-introduced token is caught immediately (add it to the context that
`ScaffoldRenderContext` builds).

## No secrets

The skeletons carry **no secret material** — every credential is an
`${ENV:default}` seam with an empty default (config is injected at deploy time).
`ScaffoldArchiveRendererTest` asserts the rendered output contains no PEM private-key
blocks, so a future skeleton edit that leaks a secret fails the build.
