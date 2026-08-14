import { CanActivateFn, Route, Routes } from '@angular/router';
import { loadRemoteModule } from '@angular-architects/native-federation';

/**
 * Host shell routes — the REMOTE_ROUTES table pattern from the
 * hugmesh.net exemplar. Every feature path is a native-federation REMOTE
 * (its own repo + nginx), loaded at runtime from the manifest initFederation
 * resolved in main.ts (dynamic /api/federation/manifest unioned over the static
 * floor in src/assets/federation.manifest.json).
 *
 * The skeleton wires exactly ONE remote: the angular-mfe archetype's example
 * remote (remote name = its app_slug identity, exposes ./routes -> the exported
 * `ROUTES` const — the skeleton pair; fleet remotes use per-repo consts like
 * USER_ROUTES). Registering a SECOND remote is one REMOTE_ROUTES row + one
 * static-floor entry + one menu entry — the full 8-place platform surface is
 * walked in docs/FEDERATION-EXAMPLES.md.
 *
 * GUARDS: `canActivate` is part of the spec so a row can pin its access rule
 * (the exemplar's adminGuard/modGuard/userGuard pattern). The skeleton ships no
 * session service yet, so the example row is unguarded — guards are
 * defence-in-depth ABOVE the BFF's own authz, never a substitute for it.
 */

/** Declarative wiring for each federated remote, exported so tests can assert
 *  the contract (remote name -> exposed module -> exported routes constant ->
 *  guard) without spying the frozen native-federation ESM namespace. */
export interface RemoteRouteSpec {
  readonly path: string;
  readonly remoteName: string;
  readonly exposed: string;
  readonly routesConst: string;
  readonly canActivate?: readonly CanActivateFn[];
}

export const REMOTE_ROUTES: readonly RemoteRouteSpec[] = [
  { path: '{{APP_SLUG}}', remoteName: '{{APP_SLUG}}', exposed: './routes', routesConst: 'ROUTES' },
];

/** Resolve a remote's exported routes constant via native-federation. Indirected
 *  through a holder so unit tests can stub the loader (the ESM namespace export
 *  itself is read-only and cannot be spied directly). */
export const federationLoader = {
  load: (remoteName: string, exposed: string): Promise<Record<string, unknown>> =>
    loadRemoteModule(remoteName, exposed) as Promise<Record<string, unknown>>,
};

function remoteRoute(spec: RemoteRouteSpec): Route {
  return {
    path: spec.path,
    ...(spec.canActivate ? { canActivate: [...spec.canActivate] } : {}),
    loadChildren: () =>
      federationLoader
        .load(spec.remoteName, spec.exposed)
        .then((m) => m[spec.routesConst] as Routes),
  };
}

export const routes: Routes = [
  // Local landing view (the exemplar's public marketing pages slot).
  {
    path: 'home',
    loadComponent: () =>
      import('./home.component').then((m) => m.HomeComponent),
  },

  // Federated remotes (data-driven from REMOTE_ROUTES above).
  ...REMOTE_ROUTES.map(remoteRoute),

  // Default: the local landing page. The exemplar replaces this with a pure
  // AUTHGATE + role-home redirect guard (roleHomeGuard) once sessions exist.
  { path: '', pathMatch: 'full', redirectTo: 'home' },
  { path: '**', redirectTo: 'home' },
];
