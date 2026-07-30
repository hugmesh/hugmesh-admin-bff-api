package systems.hugmesh.adminbff.domainregistry;

import java.time.Instant;

/**
 * A single {@code domain_registry} row — the RUNTIME source of truth for one
 * brand/domain in the cluster (schema in Liquibase
 * {@code db/changelog/012-domain-registry.xml}). The SUPERADMIN-managed twin of the
 * BUILD-TIME {@code hugmesh-generator/brands/domains.conf} the generator (#79)
 * bakes in, so build-time and runtime are ONE source of truth (multi-tenancy PR9).
 *
 * <p>Named {@code DomainRegistration} (not {@code DomainRegistry}) to avoid colliding
 * with {@link systems.hugmesh.commons.security.DomainRegistry}, which is the
 * issuer&rarr;domain converter map (a different concept entirely).
 *
 * <p>Column mapping {@code brands/domains.conf} &rarr; {@code domain_registry}:
 * <ul>
 *   <li>conf {@code DOMAIN} &rarr; {@link #clusterDomain()} — the brand's base domain
 *       (the {@code CLUSTER_DOMAIN}); the natural key, NOT NULL + UNIQUE.</li>
 *   <li>conf {@code BRAND} &rarr; {@link #brand()} — the short slug used in names.</li>
 *   <li>conf {@code CA_CERT}/{@code CA_KEY} &rarr; {@link #caRef()} — a CA *REFERENCE*
 *       (e.g. a Vault PKI path / secret name / {@code "generate"}), NEVER the
 *       cert/key bytes and NEVER a private-key path. The CA private key stays on the
 *       key-USB / in Vault; this is just the pointer a later ProvisionCa effector
 *       resolves.</li>
 * </ul>
 * Superset (runtime-only) fields: {@link #org()}, {@link #nsPrefix()} (the k8s
 * namespace prefix the ApplicationSet expands into {@code ${nsPrefix}-pki/-backend/
 * -frontend}), {@link #casdoorOrg()} (the per-brand Casdoor org — the token issuer is
 * the per-domain discriminator), {@link #meshTag()} (the headscale/tailnet mesh tag),
 * and {@link #enabled()} (desired-state on/off; a domain is SOFT-DISABLED, never
 * hard-deleted). {@link #createdBySubject()} is stamped from the SUPERADMIN's
 * {@code jwt.getSubject()}.
 *
 * <h3>Provisioning-status fields (Liquibase band 190)</h3>
 * {@link #caProvisioned()} / {@link #appsetRegistered()} / {@link #lastReconciledGeneration()}
 * are the bridge between a SUPERADMIN-REGISTERED domain (this table) and an actually
 * PROVISIONED brand (the per-domain CA + the brand-list ArgoCD ApplicationSet). They DEFAULT
 * {@code false}/{@code false}/{@code 0} and SHIP DARK: only the (not-yet-built) generator
 * domain-reconcile EFFECTOR (internal-mTLS) ever flips them. Until then every freshly
 * registered domain reads "registered but not yet provisioned" so the admin-ui can render the
 * platform-capability-gating chip (the SUPERADMIN console mandate). They are READ-only here +
 * carried on the signed {@link DomainRegistryExportService} export the effector reconciles
 * against; NO write path in this band (the create/update CRUD never sets them).
 */
public record DomainRegistration(
        String id,
        String clusterDomain,
        String brand,
        String org,
        String caRef,
        String nsPrefix,
        String casdoorOrg,
        String meshTag,
        boolean enabled,
        Instant createdAt,
        String createdBySubject,
        Instant updatedAt,
        boolean caProvisioned,
        boolean appsetRegistered,
        long lastReconciledGeneration) {

    /**
     * Back-compat constructor for the pre-band-190 12-arg shape (CRUD that never sets the
     * provisioning-status fields). Defaults the three status fields to the unprovisioned
     * floor ({@code false}/{@code false}/{@code 0}) — exactly the DB column defaults — so
     * every existing caller (create/update merge, the unit tests) keeps compiling + behaves
     * identically (ships dark).
     */
    public DomainRegistration(
            String id, String clusterDomain, String brand, String org, String caRef,
            String nsPrefix, String casdoorOrg, String meshTag, boolean enabled,
            Instant createdAt, String createdBySubject, Instant updatedAt) {
        this(id, clusterDomain, brand, org, caRef, nsPrefix, casdoorOrg, meshTag, enabled,
                createdAt, createdBySubject, updatedAt, false, false, 0L);
    }
}
