import { initFederation } from '@angular-architects/native-federation';
import { resolveFederationSource } from './app/federation/federation-bootstrap';

// Native-federation HOST entrypoint. Resolve every remote's remoteEntry.json
// BEFORE bootstrapping Angular, then hand off to ./bootstrap. initFederation maps
// remote name -> remoteEntry URL; loadRemoteModule in app.routes.ts relies on it.
//
// DYNAMIC-FIRST, STATIC-FLOOR (the hugmesh.systems host-shell pattern).
// resolveFederationSource() first fetches the DB-driven manifest (federation-api
// GET /api/federation/manifest) so new/disabled/kill-switched remotes land
// WITHOUT a host redeploy. On dynamic SUCCESS it returns the UNION of the bundled
// static manifest (the build-time FLOOR — every baked remote) and the dynamic
// overlay (overrides/adds), so a successful read is never strictly worse than the
// static build. On ANY failure — including the 401 an ANONYMOUS pre-login caller
// gets from the `authenticated()` endpoint, plus network/5xx/parse/empty — it
// returns the BUNDLED static manifest URL so the shell ALWAYS boots. Either value
// (a remotes OBJECT or a manifest-URL STRING) is a valid initFederation argument.
// See app/federation/federation-bootstrap.ts for the auth-timing + floor contract.
//
// The trailing .catch is deliberately swallowed: an empty/bad manifest still boots
// the shell DARK (no remotes) rather than hard-failing — graceful degrade.
resolveFederationSource()
  .then((source) => initFederation(source))
  .catch((err) => console.error(err))
  .then(() => import('./bootstrap'))
  .catch((err) => console.error(err));
