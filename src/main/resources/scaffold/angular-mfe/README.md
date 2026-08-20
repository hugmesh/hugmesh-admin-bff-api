# {{BRAND_TITLE}} — {{REPO_NAME}} (Angular-MFE runnable example skeleton)

A minimal but **REAL** Angular 22 **native-federation remote** in the house
shape, rendered by the mesh repo-templating **angular-mfe** archetype when the
Tier-2 base (`hugmesh-{{REPO_NAME}}`) is not pullable:

```
npm ci                      # honest committed lockfile — see archetype README
npm run build               # @angular-architects/native-federation:build -> dist/{{APP_SLUG}}
npm test                    # karma/jasmine on ChromeHeadlessCI (CHROME_BIN)
npm start                   # standalone dev shell on :4201
```

## Shape (mirrors hugmesh-user-ui)

- `federation.config.js` — `hugmeshRemote({ name: '{{APP_SLUG}}', exposes: { './routes': ... } })`;
  the shared singleton/strictVersion surface + RxJS skip list live in
  `federation-base.js` (the class-A contract file, one source of truth).
- `src/app/remote.routes.ts` — exports the `ROUTES` const the host mounts
  (`loadRemoteModule({ remoteName: '{{APP_SLUG}}', exposedModule: './routes' })`).
- `src/app/hello.component.ts` — standalone + signals + OnPush; binds text via
  `[textContent]` because Angular's double-curly interpolation mustaches would
  collide with the templating renderer's fail-closed brand-token scan (see the
  comment in the component).
- `src/styles.scss` — the cross-repo `--hug-*` palette contract (standalone
  floor; the host's `:root` wins when federated).
- `nginx.conf` — CORS `Access-Control-Allow-Origin *` on every bundle path (the
  host fetches remoteEntry.json cross-origin); serves on 8080 for the
  `nginx-unprivileged` runtime image in `Dockerfile`.
- `.gitlab-ci.yml` — fleet include (centralized pentest stage) + containerized
  karma test job + image build. The e2e harness mounts as an `e2e/` subproject
  exactly like user-ui when this remote grows behaviour worth driving.

## Wiring this remote into the platform

Registering a remote is an 8-place surface (repo, static floor, host routes,
menu, federation_modules registry, fe-gateway route, route-access rows,
k8s+ArgoCD) — see docs/FEDERATION-EXAMPLES.md in the generator for the
walkthrough, including how the superadmin service-catalog wizard drives it.

## Version-skew warning

The federation share surface is `singleton: true, strictVersion: true`
(federation-base.js): this remote's Angular major MUST match the host's, or the
mount fails at runtime. Bump majors host-first, remotes in the same wave.
