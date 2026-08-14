import { environment } from '../../environments/environment';

/**
 * DYNAMIC-FIRST + STATIC-FALLBACK manifest resolution for the native-federation
 * HOST bootstrap (main.ts). This is the hugmesh.net host-shell pattern,
 * carried whole because every clause is load-bearing:
 *
 * WHY THIS RUNS PRE-DI (raw fetch, not HttpClient). `initFederation(...)` MUST
 * resolve every remoteEntry BEFORE `bootstrapApplication`, so this code runs
 * before Angular's DI exists. `credentials: 'include'` re-creates the
 * bearer-interceptor seam by hand: the gateway exchanges the same-origin session
 * cookie for the upstream bearer SERVER-SIDE, so an already-authenticated full
 * reload gets its role/visibility-scoped manifest while a logged-out first load
 * fetches anonymously. The browser never holds a bearer.
 *
 * THE AUTH-TIMING NUANCE. `GET /api/federation/manifest` is `authenticated()`
 * server-side, NOT public — an ANONYMOUS pre-login caller gets 401. That is FINE
 * and is exactly why the static fallback exists: on a 401 (or any network/5xx/
 * parse/empty failure) we hand `initFederation` the BUNDLED static manifest URL
 * string instead, so the shell ALWAYS boots (never a white screen).
 *
 * THE STATIC FLOOR (union, not replace). On dynamic SUCCESS we return the UNION
 * of the bundled static manifest (the build-time FLOOR) and the dynamic overlay,
 * with the overlay OVERRIDING matching slugs and ADDING new ones — a successful
 * DB read is never strictly worse than the static build, and the DB can ADD
 * remotes without a host redeploy. Role gating is done by the per-route GUARDS +
 * BFF authz, NOT by manifest presence, so unioning the public entry-URL map is
 * not an authz weakening.
 */

/** A single remote row as returned by federation-api's manifest endpoint. */
export interface DynamicRemote {
  readonly slug: string;
  readonly remoteEntryUrl: string;
  // Other fields (displayName, kind, version, contentHash, visibility, metadata,
  // exposedModule) are present on the wire but irrelevant to initFederation, which
  // only needs name -> remoteEntry URL. Kept loose so a schema add never breaks us.
  readonly [k: string]: unknown;
}

/** Wire shape of `GET /api/federation/manifest`: {generatedAt, remotes[]}. */
export interface DynamicManifestResponse {
  readonly generatedAt?: string;
  readonly remotes?: readonly DynamicRemote[];
}

/** The flat `{ remoteName: remoteEntryUrl }` map native-federation consumes. */
export type RemotesMap = Record<string, string>;

/** Composed dynamic endpoint (same base convention as the capabilities read). */
export const FEDERATION_MANIFEST_URL =
  `${environment.federationApiBase}${environment.federationManifestUrl}`;

/**
 * Map the DB manifest's `remotes[]` to the `{ name: remoteEntryUrl }` shape
 * initFederation wants. Drops rows missing a slug or remoteEntryUrl (a malformed
 * row never poisons the map). Returns null when there is NOTHING usable so the
 * caller treats it as a failure and falls back to the static manifest rather
 * than booting DARK with zero remotes.
 */
export function toRemotesMap(body: DynamicManifestResponse | null): RemotesMap | null {
  const remotes = body?.remotes;
  if (!Array.isArray(remotes) || remotes.length === 0) return null;
  const map: RemotesMap = {};
  for (const r of remotes) {
    if (r && typeof r.slug === 'string' && typeof r.remoteEntryUrl === 'string'
        && r.slug.length > 0 && r.remoteEntryUrl.length > 0) {
      map[r.slug] = r.remoteEntryUrl;
    }
  }
  return Object.keys(map).length > 0 ? map : null;
}

/**
 * Fetch the DYNAMIC manifest and return the remotes map, or null on ANY failure
 * (network error, non-2xx incl. the 401 an anonymous caller gets, non-JSON,
 * empty/malformed body). NEVER throws — the caller falls back to the static
 * manifest on null. `fetchImpl` is injectable so a unit test can drive it
 * without a real network.
 */
export async function fetchDynamicRemotes(
  fetchImpl: typeof fetch = typeof fetch !== 'undefined' ? fetch : (undefined as unknown as typeof fetch),
): Promise<RemotesMap | null> {
  if (!fetchImpl) return null;
  try {
    const res = await fetchImpl(FEDERATION_MANIFEST_URL, {
      credentials: 'include',
      headers: { Accept: 'application/json' },
    });
    if (!res || !res.ok) return null; // 401 (anonymous), 5xx, etc. -> fall back
    const body = (await res.json()) as DynamicManifestResponse;
    return toRemotesMap(body);
  } catch {
    return null; // network / parse failure -> fall back to the static manifest
  }
}

/**
 * Resolve what to hand `initFederation`.
 *
 * ON DYNAMIC SUCCESS: the UNION of the bundled static FLOOR and the dynamic
 * overlay — floor first, dynamic overrides/adds.
 * ON DYNAMIC FAILURE (401 anonymous / 5xx / network / parse / empty): the
 * BUNDLED static manifest URL string (which initFederation fetches itself), so
 * the shell ALWAYS boots. Both returns are valid initFederation arguments
 * (object | url-string). Pure resolution — does not call initFederation, so it
 * is trivially testable.
 */
export async function resolveFederationSource(
  fetchImpl?: typeof fetch,
): Promise<RemotesMap | string> {
  const dynamic = await fetchDynamicRemotes(fetchImpl);
  if (dynamic) {
    // Static floor UNION dynamic overlay: floor first, dynamic overrides/adds.
    return { ...environment.federationStaticManifest, ...dynamic };
  }
  // Fallback: the bundled static asset path.
  return environment.federationManifest;
}
