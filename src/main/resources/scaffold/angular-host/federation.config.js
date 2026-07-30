// HOST-SHELL federation config (native-federation host name "{{HOST_NAME}}").
// The host is a CONSUMER: no `exposes` block — it resolves every remote's
// remoteEntry.json at runtime (dynamic /api/federation/manifest unioned over the
// static floor in src/assets/federation.manifest.json; see
// src/app/federation/federation-bootstrap.ts) and mounts the exposed routes via
// the REMOTE_ROUTES table in src/app/app.routes.ts.
//
// The shared-deps surface + RxJS skip list live in ./federation-base.js so a
// change to the federation contract lands in one file, consistent with every
// HugMesh remote (games convention). Remotes MUST match this host's Angular
// major — shared singletons are strictVersion (see federation-base.js).
const { hugmeshHost } = require('./federation-base');

module.exports = hugmeshHost({ name: '{{HOST_NAME}}' });
