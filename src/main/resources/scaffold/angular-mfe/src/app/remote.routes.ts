import { Routes } from '@angular/router';
import { HelloComponent } from './hello.component';

/**
 * The PUBLIC federated surface of this remote — the host shell mounts this
 * constant via loadRemoteModule({ remoteName: '{{APP_SLUG}}', exposedModule:
 * './routes' }) and reads the exported const named `ROUTES` (the host's
 * REMOTE_ROUTES entry pins BOTH names; renaming either breaks the mount).
 *
 * NOTE ON THE FILE NAME: fleet remotes name this file `<slug>.routes.ts` with a
 * per-repo const (USER_ROUTES, ...). The templating renderer substitutes tokens
 * in file CONTENT only (paths are static), so the skeleton uses the neutral
 * `remote.routes.ts` + the neutral `ROUTES` const; the host skeleton's routes
 * table is wired to exactly this pair. Rename both in lock-step with the host
 * entry if you adopt the per-repo convention.
 */
export const ROUTES: Routes = [
  { path: '', component: HelloComponent },
];
