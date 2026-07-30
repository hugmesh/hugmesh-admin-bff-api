package systems.hugmesh.adminbff.servicecatalog.federation;

import reactor.core.publisher.Mono;

/**
 * The narrow federation-registry admin seam the Service-Store FEDERATE leg needs. Registering a
 * newly-scaffolded service's UI as a federation module (and de-registering it) is a WRITE to the
 * federation-api admin API ({@code /api/federation/admin/modules}, SUPERADMIN-guarded) — net-new
 * to admin-bff.
 *
 * <p>TWO implementations gated by {@code app.appstore.federation.enabled} (default false → ships
 * dark): the real {@link RestFederationModuleClient} (talks to federation-api's admin API) and the
 * fail-closed {@link NoopFederationModuleClient} (the default — every call is a logged no-op that
 * dials nothing). {@link #isReal()} is the runtime seam signal a test/caller asserts on (it feeds
 * {@code FederateOutcome.federationReal} + the federation-status {@code enabled} flag).
 *
 * <p>This is the DIRECT federation-registry write. GitOps descriptor automation (writing the
 * remote's ArgoCD descriptor so the manifest floor is reconciled) does NOT exist yet, so the
 * federate leg reports {@code gitopsDescriptorPending=true} regardless of this client's mode.
 */
public interface FederationModuleClient {

    /**
     * Upsert-by-slug a federation module against the federation-api admin API
     * ({@code POST /api/federation/admin/modules}). Idempotent: an existing module of the same
     * {@code slug} is updated. Returns the registered slug.
     *
     * @param slug           the DNS-label module slug (upsert key)
     * @param displayName    the human label
     * @param kind           the module kind ({@code remote-shell}|{@code fragment})
     * @param remoteEntryUrl the http(s) remote-entry URL (validated by the caller)
     * @param exposedModule  the exposed module (e.g. {@code ./routes})
     * @param version        the version (nullable)
     * @param visibility     {@code public}|{@code internal}
     * @param enabled        whether the module is enabled on registration
     * @param metadata       the module {@code metadata} JSON STRING (carries {@code mountAt}/{@code requiresRole})
     * @return the registered module slug
     */
    Mono<String> registerModule(String slug, String displayName, String kind, String remoteEntryUrl,
                                String exposedModule, String version, String visibility,
                                boolean enabled, String metadata);

    /**
     * Soft-disable a federation module by slug ({@code DELETE /api/federation/admin/modules/{slug}}
     * — the federation-api never hard-deletes). Idempotent: an already-absent module (404) is
     * tolerated as success. Returns true when the disable was issued (or the module was already
     * gone), false on a hard failure the caller should retry.
     */
    Mono<Boolean> unregisterModule(String slug);

    /** True when this client actually talks to federation-api (the runtime seam signal). The Noop
     *  default returns false so a ships-dark assertion is structural. */
    boolean isReal();
}
