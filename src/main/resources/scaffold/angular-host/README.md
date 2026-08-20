# {{BRAND_TITLE}} — {{REPO_NAME}} (host-shell runnable example skeleton)

A minimal but **REAL** Angular 22 native-federation **HOST** in the platform
shape, rendered by the mesh repo-templating **angular-host** archetype when the
Tier-2 base (the `hugmesh.net` host shell, reachable only via
`HOST_SHELL_BASE_DIR` — see the archetype README) is not pullable:

```
npm ci && npm run build          # real @angular-architects/native-federation:build
npm start                        # serve the shell on :4200
```

Serve the angular-mfe example remote next to it (`ng serve` in its rendered
tree, port 4201 — where the static floor points) and the menu entry mounts it.

## What it contains

| Piece | File | Shape |
|---|---|---|
| Federation | `federation.config.js` + `federation-base.js` | `hugmeshHost({ name: '{{HOST_NAME}}' })` — consumer only, no `exposes`; ONE shared-deps surface (singleton, strictVersion) |
| Static floor | `src/assets/federation.manifest.json` | `{ "{{APP_SLUG}}": dev remoteEntry URL }` — the build-time remote FLOOR |
| Bootstrap | `src/main.ts` + `src/app/federation/federation-bootstrap.ts` | DYNAMIC `/api/federation/manifest` UNION over the static floor; static-URL fallback so the shell always boots (exemplar pattern, carried whole) |
| Routes | `src/app/app.routes.ts` | the `REMOTE_ROUTES` spec table -> `loadRemoteModule` lazy loaders; one row wired to the example remote (`./routes` -> `ROUTES`) |
| Menu | `src/app/menu.component.ts` | keyed off `CapabilitiesStub.installed(slug)` — greyed-not-hidden for absent services |
| Styles | `src/styles.scss` + `src/styles/_tokens.scss` | BOTH palette tiers: host-local SCSS tokens + the cross-repo `--hug-*` runtime contract |
| Serving | `nginx.conf` + `Dockerfile` | strict nonce-CSP host serving (exemplar shape) on nginx-unprivileged:8080 |
| CI | `.gitlab-ci.yml` | fleet include (centralized pentest stage) + build-smoke + image build |

## Identity this skeleton needs

The host row's `repos[].identity` must carry the EXAMPLE REMOTE's identity so
the floor/routes/menu wire to it: `app_slug` (the remote's federation name +
mount path) and `title_word` (its menu label). `HOST_NAME` itself is
brand-derived (`<brand>-host`) — never an identity row.

## No Angular interpolation, no karma lane — deliberately

Angular's own double-curly interpolation cannot appear in a skeleton source
file (the templating renderer fail-closes on non-allowlisted mustache
identifiers), so every component binds text via `[textContent]`. The skeleton
ships no karma lane yet; CI's test stage is an honest full build. Adopt the
exemplar's karma + REMOTE_ROUTES contract specs as the first tests.

## Growing into the real shell

Session/guards (`roleHomeGuard`, per-remote guards), the HTTP-backed
capabilities service (public `GET /api/federation/capabilities`), a prod
manifest + `fileReplacements` split, and every further remote are walked in
docs/FEDERATION-EXAMPLES.md (the 8-place registration surface).
