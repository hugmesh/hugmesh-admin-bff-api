// REMOTE bundle config for the {{TITLE_WORD}} micro-frontend (native-federation
// remote name "{{APP_SLUG}}"). The {{HOST_NAME}} host consumes the exposed
// modules via loadRemoteModule({ remoteName: '{{APP_SLUG}}', exposedModule:
// './routes' }) and mounts the exported ROUTES — so the remote name and the
// exposed module key MUST stay unchanged or the host's views break.
//
// The shared-deps surface + RxJS skip list live in ./federation-base.js so a
// change to the federation contract lands in one file, consistent with the host
// and every other HugMesh remote (games convention).
const { hugmeshRemote } = require('./federation-base');

module.exports = hugmeshRemote({
  name: '{{APP_SLUG}}',
  exposes: {
    './routes': './src/app/remote.routes.ts',
  },
});
