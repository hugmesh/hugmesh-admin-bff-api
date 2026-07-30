package systems.hugmesh.adminbff.backingservices;

import java.util.List;
import java.util.Optional;

/**
 * The DECLARATIVE MANAGED-BACKING-SERVICE CATALOG — the closed set of in-mesh backing
 * services that have a managed cloud equivalent (AWS / Azure), the admin web-UI copy of the
 * generator's {@code specs/cluster/backing-services.yaml} ({@code kind: BackingServiceRegistry}).
 * Every front-end (CLI / ncurses / Studio / this admin plane) reads ONE vocabulary, so "a new
 * managed service is one row, not four edits" — the same posture as
 * {@link systems.hugmesh.adminbff.golive.GoLiveProviderCatalog} and
 * {@link systems.hugmesh.adminbff.optionalservices.OptionalServiceRegistry}.
 *
 * <p><b>Closed set, pinned to the generator recon (managedrecon-2 §1–§12).</b> The {@code id}
 * an intent pins MUST be one of these — an unknown id is refused by the service (never
 * actuated). The set + tiers mirror the design's feasibility ranking (cloud-deploy DESIGN
 * I8-DESIGN):
 * <ul>
 *   <li><b>Tier 1</b> (trivial): {@code object-store}, {@code smtp} — already
 *       endpoint-strategy / external-submission shaped.</li>
 *   <li><b>Tier 2</b> (easy/medium): {@code kafka}, {@code clickhouse},
 *       {@code federation-bundles}, and the per-service Postgres set (the 5 core BFF DBs +
 *       {@code postgres-casdoor}).</li>
 *   <li><b>Tier 3</b> (hard — DOCS ONLY in v1): {@code cassandra}, {@code harbor},
 *       {@code vault-kv}, {@code vault-pki}. These are {@link BackingService#docsOnly()} =
 *       true; the service REFUSES a mode change for them with an honest blocker message (the
 *       managed swap is architecturally blocked and ships as design docs + emitted checklists,
 *       NOT code, in v1).</li>
 * </ul>
 *
 * <p><b>NO SECRETS.</b> Entries carry PUBLIC provider metadata only (id / kind / tier / the
 * managed target names / a one-line note). The operator's managed endpoint + creds-reference
 * are recorded per-intent by {@link BackingServiceService}; the credential BYTES never transit
 * this BFF — they route to the ESO/Vault paths on the generator side (operator-supplied,
 * never generator-minted).
 */
public final class BackingServiceCatalog {

    private BackingServiceCatalog() {
    }

    /** The three difficulty tiers (see the class javadoc). Tier 3 == docs-only. */
    public static final int TIER_TRIVIAL = 1;
    public static final int TIER_EASY = 2;
    public static final int TIER_DOCS_ONLY = 3;

    /**
     * One catalog row. All fields are PUBLIC metadata (never a credential).
     *
     * @param id           the stable catalog id an intent's {@code serviceId} pins
     * @param kind         the backing-service KIND (object-storage / smtp / kafka / analytics /
     *                     postgres / cassandra / registry / secrets / pki) — the swap shape
     * @param tier         the feasibility tier (1 trivial, 2 easy/medium, 3 docs-only)
     * @param displayName  the human name the admin UI renders
     * @param awsTarget    the AWS managed equivalent (public product name)
     * @param azureTarget  the Azure managed equivalent (public product name)
     * @param notes        one-line UI hint (the honest parity note)
     */
    public record BackingService(
            String id,
            String kind,
            int tier,
            String displayName,
            String awsTarget,
            String azureTarget,
            String notes) {

        /** True iff this service is DOCS-ONLY in v1 (tier 3) — a mode change is REFUSED with a
         *  blocker message; the managed swap is architecturally blocked and ships as design
         *  docs + emitted checklists, not code. */
        public boolean docsOnly() {
            return tier == TIER_DOCS_ONLY;
        }
    }

    // Kinds (the swap shape a consumer/effector keys on).
    public static final String KIND_OBJECT_STORAGE = "object-storage";
    public static final String KIND_SMTP = "smtp";
    public static final String KIND_KAFKA = "kafka";
    public static final String KIND_ANALYTICS = "analytics";
    public static final String KIND_POSTGRES = "postgres";
    public static final String KIND_CASSANDRA = "cassandra";
    public static final String KIND_REGISTRY = "registry";
    public static final String KIND_SECRETS = "secrets";
    public static final String KIND_PKI = "pki";

    /** The closed v1 catalog, in tier order (mirrors backing-services.yaml). */
    public static final List<BackingService> SERVICES = List.of(
            // ── Tier 1 (trivial) ──────────────────────────────────────────────────────────
            new BackingService("object-store", KIND_OBJECT_STORAGE, TIER_TRIVIAL,
                    "Object storage (Velero / MinIO)", "S3", "Blob Storage",
                    "Velero BSL is already the aws-plugin + INI-creds shape — the easiest swap; "
                            + "Azure = the velero-plugin-for-microsoft-azure initContainer."),
            new BackingService("smtp", KIND_SMTP, TIER_TRIVIAL,
                    "SMTP mail relay", "SES", "Communication Services",
                    "Pure MAIL_* data through gen-cluster-secrets — no manifest edits; already an "
                            + "external-submission model."),
            // ── Tier 2 (easy / medium) ────────────────────────────────────────────────────
            new BackingService("kafka", KIND_KAFKA, TIER_EASY,
                    "Kafka usage-event bus", "MSK", "Event Hubs",
                    "One bootstrap-servers env + Spring SASL/TLS security props (not declared "
                            + "today); admin-bff degrades to in-memory when absent."),
            new BackingService("clickhouse", KIND_ANALYTICS, TIER_EASY,
                    "ClickHouse analytics warehouse", "ClickHouse Cloud", "ClickHouse Cloud",
                    "Three endpoint literals + a TLS delta (8123/9000 -> 8443/9440); no AWS/Azure "
                            + "first-party ClickHouse."),
            new BackingService("federation-bundles", KIND_OBJECT_STORAGE, TIER_EASY,
                    "Federation bundle store", "S3", "Blob Storage",
                    "APP_BUNDLES_STORAGE=s3 already exists (BundleStorageConfig) — a config flag, "
                            + "no manifest surgery."),
            new BackingService("postgres-admin-bff", KIND_POSTGRES, TIER_EASY,
                    "admin-bff database", "RDS / Aurora PostgreSQL", "Azure Database for PostgreSQL",
                    "Dual R2DBC + Liquibase URLs; delete the in-mesh DB app; role-split SQL "
                            + "out-of-band; TLS/truststore caveats."),
            new BackingService("postgres-mod-bff", KIND_POSTGRES, TIER_EASY,
                    "mod-bff database", "RDS / Aurora PostgreSQL", "Azure Database for PostgreSQL",
                    "Dual R2DBC + Liquibase URLs; delete the in-mesh DB app; role-split SQL "
                            + "out-of-band; TLS/truststore caveats."),
            new BackingService("postgres-user-bff", KIND_POSTGRES, TIER_EASY,
                    "user-bff database", "RDS / Aurora PostgreSQL", "Azure Database for PostgreSQL",
                    "Dual R2DBC + Liquibase URLs; delete the in-mesh DB app; role-split SQL "
                            + "out-of-band; TLS/truststore caveats."),
            new BackingService("postgres-forum-bff", KIND_POSTGRES, TIER_EASY,
                    "forum-bff database", "RDS / Aurora PostgreSQL", "Azure Database for PostgreSQL",
                    "Dual R2DBC + Liquibase URLs; delete the in-mesh DB app; role-split SQL "
                            + "out-of-band; TLS/truststore caveats."),
            new BackingService("postgres-wiki-bff", KIND_POSTGRES, TIER_EASY,
                    "wiki-bff database", "RDS / Aurora PostgreSQL", "Azure Database for PostgreSQL",
                    "Dual R2DBC + Liquibase URLs; delete the in-mesh DB app; role-split SQL "
                            + "out-of-band; TLS/truststore caveats."),
            new BackingService("postgres-casdoor", KIND_POSTGRES, TIER_EASY,
                    "Casdoor identity database", "RDS / Aurora PostgreSQL",
                    "Azure Database for PostgreSQL",
                    "Casdoor pins sslmode=disable in app-conf-configmap — needs a template knob; "
                            + "Citus (federation/route-access) is incompatible with vanilla RDS."),
            // ── Tier 3 (docs-only — mode change refused in v1) ────────────────────────────
            new BackingService("cassandra", KIND_CASSANDRA, TIER_DOCS_ONLY,
                    "Cassandra (gateway revocation / URL registry)", "Keyspaces",
                    "Cosmos DB (Cassandra API)",
                    "DOCS ONLY: auth/TLS knobs live only in the dark hardening overlay; "
                            + "SigV4/port-9142 + LWT/DC semantics need app-level work."),
            new BackingService("harbor", KIND_REGISTRY, TIER_DOCS_ONLY,
                    "Harbor container registry", "ECR", "ACR",
                    "DOCS ONLY: the host literal is in ~30 kustomizations; the robot-account "
                            + "provision Job has no analog; 12h ECR tokens break static pull "
                            + "secrets; loses the air-gap posture."),
            new BackingService("vault-kv", KIND_SECRETS, TIER_DOCS_ONLY,
                    "Vault KV (secrets store)", "Secrets Manager", "Key Vault",
                    "DOCS ONLY: broad but medium — one ClusterSecretStore swap + ~90 remoteRef "
                            + "renames + provision.sh token-seeding removal."),
            new BackingService("vault-pki", KIND_PKI, TIER_DOCS_ONLY,
                    "Vault PKI (internal mTLS issuance)", "ACM Private CA", "Key Vault certificates",
                    "DOCS ONLY: the hardest — VaultDynamicSecret is Vault-only; the USB CA-custody "
                            + "model has no managed analog; would need a cert-manager re-architecture."));

    /** Catalog lookup by stable id. */
    public static Optional<BackingService> find(String id) {
        if (id == null) {
            return Optional.empty();
        }
        return SERVICES.stream().filter(s -> s.id().equals(id)).findFirst();
    }

    /** The closed id set, in tier order. */
    public static List<String> ids() {
        return SERVICES.stream().map(BackingService::id).toList();
    }
}
