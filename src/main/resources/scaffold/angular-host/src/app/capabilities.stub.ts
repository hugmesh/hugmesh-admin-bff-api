import { Injectable, signal } from '@angular/core';

/**
 * Install-state STUB the skeleton menu keys off — the shape (but not the
 * transport) of the exemplar host's CapabilitiesService, whose single predicate
 * `installed(slug)` the menu + launcher cards read to GREY-OUT optional
 * services (visible-but-disabled, never a dead link; an UNKNOWN slug reports
 * NOT installed).
 *
 * The real host loads the PUBLIC federation-api projection
 * `GET /api/federation/capabilities` (permitAll — the greying must work
 * logged-out) and NEVER hard-fails: a fetch error leaves an empty map so
 * services grey out by absence rather than the shell breaking. Replace this
 * stub with that HTTP-backed service (+ provideHttpClient(withFetch()) in
 * bootstrap.ts) as the first step of growing this skeleton into a real shell;
 * the menu only reads `installed()`/`loaded()`, so nothing else changes.
 */
@Injectable({ providedIn: 'root' })
export class CapabilitiesStub {
  /** Mutable installed-slug set. Defaults to the one example remote wired in
   *  REMOTE_ROUTES so the skeleton menu lights up out of the box. */
  readonly installedSlugs = signal<Set<string>>(new Set(['{{APP_SLUG}}']));
  readonly loaded = signal(true);

  /** Whether an OPTIONAL service is installed and serveable right now. */
  installed(slug: string): boolean {
    return this.installedSlugs().has(slug);
  }
}
