// The bundled static manifest as an OBJECT, imported at build time (no runtime
// fetch). Shape is the flat { remoteName: remoteEntryUrl } map native-federation
// consumes. Used as the FLOOR the dynamic overlay is unioned ON TOP of, so a
// successful DB read is never strictly worse than the baked set.
// resolveJsonModule is enabled in tsconfig.json.
//
// The SKELETON ships one environment (this file) whose floor is the DEV
// localhost manifest. When this shell grows a production deployment, adopt the
// hugmesh.systems exemplar's split: a federation.manifest.prod.json with the
// fe-gateway public paths (/hello/remoteEntry.json, ...) selected via an
// environment.prod.ts + `fileReplacements` (static assets are copied wholesale
// by the `assets` glob and are NOT touched by fileReplacements, so the manifest
// must be SELECTED here — via the file-replaced environment — rather than
// swapped as an asset).
import federationStaticManifest from '../assets/federation.manifest.json';

export const environment = {
  production: false,
  /** Native-federation remote manifest PATH (the bundled static asset URL) —
   *  the fallback artifact initFederation fetches itself when the dynamic
   *  manifest is unreachable. */
  federationManifest: 'assets/federation.manifest.json',
  /** The SAME static manifest as an in-memory OBJECT (build-time import, no
   *  fetch): the platform-remote FLOOR resolveFederationSource() unions the
   *  dynamic overlay over, so every baked remote is ALWAYS registered while the
   *  DB can still ADD remotes without a host redeploy. Route guards + BFF authz
   *  do all gating — this only maps name -> public entry URL. */
  federationStaticManifest: federationStaticManifest as Record<string, string>,
  /** Base URL for federation-api reads. Same-origin ('' = relative request) so
   *  the dev proxy / fe-gateway routes /api/* to federation-api; kept
   *  configurable for a future cross-origin host. */
  federationApiBase: '',
  /** DB-driven DYNAMIC manifest endpoint (federation-api
   *  GET /api/federation/manifest, `authenticated()`). Fetched FIRST by the
   *  bootstrap; on ANY failure (incl. the anonymous 401) it falls back to the
   *  BUNDLED `federationManifest` above so the shell always boots. */
  federationManifestUrl: '/api/federation/manifest',
};
