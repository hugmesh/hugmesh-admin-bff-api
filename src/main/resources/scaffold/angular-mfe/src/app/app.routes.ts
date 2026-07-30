import { Routes } from '@angular/router';
import { ROUTES } from './remote.routes';

/**
 * Dev-shell routes: mount the remote's own public surface at the root so
 * `ng serve {{APP_SLUG}}` shows exactly what the host will federate. The host
 * never consumes THIS table — it loads `./routes` (ROUTES) from
 * federation.config.js.
 */
export const routes: Routes = [...ROUTES];
