// Shared federation config helpers for the host shell + any future remote
// bundles authored in this repo.
//
// The host's federation.config.js used to inline the same shareAll args and
// skip list every other HugMesh repo carries. Centralising them here means
// the federation surface (singletons, strictVersion, the RxJS skip list) lives
// in ONE place — so a drift between host and remotes (e.g. one bundle sharing a
// different RxJS subpath) can't quietly produce a "shared is not a function"
// runtime failure. Mirrors hugmesh.games/frontend/federation-base.js.
//
// Used by:
//   - ./federation.config.js (this host)

const { withNativeFederation, shareAll } = require('@angular-architects/native-federation/config');

// RxJS subpaths the native-federation builder can't resolve as ESM —
// shareAll would otherwise pull them in and the runtime fails to wire.
// (Default native-federation guidance.)
const STD_SKIP = [
  'rxjs/ajax',
  'rxjs/fetch',
  'rxjs/testing',
  'rxjs/webSocket',
];

const STD_SHARED = shareAll({
  singleton: true,
  strictVersion: true,
  requiredVersion: 'auto',
});

/**
 * Federation config for a remote bundle. `exposes` is the public surface the
 * host's loadRemoteModule({ remoteName, exposedModule }) consumes.
 *
 * `extraSkip` lets a specific remote tack on its own skip entries without
 * losing the standard list.
 */
function hugmeshRemote({ name, exposes, extraSkip = [] }) {
  return withNativeFederation({
    name,
    exposes,
    shared: { ...STD_SHARED },
    skip: [...STD_SKIP, ...extraSkip],
  });
}

/**
 * Federation config for the host shell. The host has no `exposes` block (it's a
 * consumer, not a provider), only a shared-deps surface and the skip list.
 * Naming the host explicitly keeps the convention shared across HugMesh
 * repos; a host carries no manifest self-row requirement.
 */
function hugmeshHost({ name = '{{HOST_NAME}}', extraSkip = [] } = {}) {
  return withNativeFederation({
    name,
    shared: { ...STD_SHARED },
    skip: [...STD_SKIP, ...extraSkip],
  });
}

module.exports = {
  hugmeshRemote,
  hugmeshHost,
  STD_SKIP,
  STD_SHARED,
};
