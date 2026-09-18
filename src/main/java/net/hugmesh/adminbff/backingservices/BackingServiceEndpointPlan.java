package net.hugmesh.adminbff.backingservices;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The PURE, TOTAL plan for one backing-service mode flip: which namespace's
 * {@code backing-service-endpoints} ConfigMap to merge-patch, which keys to write, and which
 * consumer Deployments to roll. No cluster is touched here — {@link Fabric8BackingServiceEffector}
 * is the only thing that dials one, and it can do nothing this class did not authorise.
 *
 * <h2>Operator DECISION 34a — one ConfigMap PER NAMESPACE</h2>
 * The recommendation put to the operator on 2026-09-17 was a SINGLE object in
 * {@code hugmesh-backend}. The operator DECLINED it and chose the per-namespace fan-out: the
 * same object NAME and the same KEY SCHEME in every namespace on the axis, accepting the cost
 * (this fan-out writer, plus one RBAC grant per namespace) deliberately. So
 * {@link Entry#namespace()} is DATA, per service — never a constant. A future edit that replaces
 * it with a hardcoded {@code "hugmesh-backend"} is the option that was turned down;
 * {@code BackingServiceEndpointPlanTest} goes red on it.
 *
 * <h2>Operator DECISION 34b — a TARGETED ROLLING RESTART, never "no restart"</h2>
 * A {@code configMapKeyRef} env var is resolved ONCE, when the kubelet creates the container.
 * Editing the ConfigMap changes nothing in a running pod, and ArgoCD still reports the Deployment
 * Synced because its spec did not move — the flip would be recorded, applied, reported green, and
 * every pod would keep talking to the old database. So every plan also carries
 * {@link Plan#consumerDeployments()}: the effector patches
 * {@value #GENERATION_ANNOTATION} onto exactly those pod templates and the Deployment controller
 * performs an ordinary rolling update. Flipping {@code postgres-wiki-bff} rolls ONE Deployment,
 * not forty. This is a targeted rolling restart. It is not a live re-dial, and it must never be
 * written down as "no restart".
 *
 * <h2>Two keys per service, never one</h2>
 * {@code SPRING_R2DBC_URL} is the runtime handle and {@code SPRING_LIQUIBASE_URL} is a SEPARATE
 * JDBC handle used once at startup. The generator registry states the trap in its own words —
 * "miss one and Liquibase or the runtime pool silently targets the wrong host". A key scheme that
 * offered one address per service would re-introduce exactly that.
 *
 * <h2>Byte-identical self-hosted default</h2>
 * {@code self-hosted} does NOT mean "restore whatever was there before" — it recomposes the
 * in-mesh literal from {@link Entry#selfHostedAuthority()} + {@link Entry#dbName()}, which are
 * character-for-character the values in
 * {@code specs/cluster/manifests/<svc>/deployment.yaml} and in the seeded ConfigMap. Remembering
 * a previous value would let one bad managed flip become the permanent "default".
 */
public final class BackingServiceEndpointPlan {

    private BackingServiceEndpointPlan() {
    }

    /** The ConfigMap name — IDENTICAL in every namespace on the axis (decision 34a). */
    public static final String CONFIGMAP_NAME = "backing-service-endpoints";

    /**
     * The pod-template annotation the effector stamps with the ledger row's {@code generation}
     * to trigger the targeted rolling restart (decision 34b). Carrying the generation rather
     * than a timestamp is what makes the {@code @Scheduled} reconcile loop idempotent: a tick
     * that finds this value already present rolls nothing.
     */
    public static final String GENERATION_ANNOTATION = "hugmesh.net/backing-service-generation";

    /** Key field for the runtime R2DBC handle. */
    public static final String FIELD_R2DBC_URL = "r2dbc-url";
    /** Key field for the startup-only Liquibase JDBC handle. */
    public static final String FIELD_LIQUIBASE_URL = "liquibase-url";

    /**
     * One namespace on the managed-Postgres axis — the census decision 34a fans out over.
     *
     * @param namespace  the namespace whose pods read a Postgres address
     * @param seeded     true iff the checked-in ConfigMap carries at least one key today
     * @param note       why it is or is not seeded (kept next to the fact, not in a wiki)
     */
    public record AxisNamespace(String namespace, boolean seeded, String note) {
    }

    /**
     * The SIX namespaces decision 34a names, re-measured against
     * {@code hugmesh-generator@88f70d99 specs/cluster} on 2026-09-17.
     *
     * <p>ALL SIX SHIP. Three of them (hugmesh-owncast, hugmesh-tube, hugmesh-forum) are created
     * by their own optional-service Applications, so their identical ConfigMap and grant ship
     * from that service's own manifests directory rather than from the always-on
     * {@code manifests/backing-service-endpoints/} bundle — an object applied from the always-on
     * bundle into a namespace that does not exist on a default mesh would leave that Application
     * permanently unable to sync. The generator guard
     * {@code tests/scripts/test-backing-service-endpoints-closure.sh} pins all six placements and
     * goes RED on the deletion of any one of them, which is what stops this axis and the shipped
     * manifests from drifting apart.
     *
     * <p>A seventh namespace holds a Postgres address and is deliberately NOT here:
     * {@code hugmesh-frontend}, whose fe-gateway reads
     * {@code r2dbc:postgresql://fe_gateway:$(ROUTE_ACCESS_DB_PASSWORD)@route-access-db…}. Every
     * Postgres address in that namespace is a route-access URL with the password interpolated
     * INTO it, and Kubernetes expands {@code $(VAR)} in a container's {@code env[].value} but NOT
     * inside ConfigMap {@code data} — so it cannot join this axis in its present shape, and a
     * ConfigMap is not a Secret. The same exclusion removes route-access from
     * {@code hugmesh-backend} and {@code hugmesh-pki} without removing those namespaces, which
     * carry other addresses.
     */
    public static final List<AxisNamespace> AXIS_NAMESPACES = List.of(
            new AxisNamespace("hugmesh-backend", true,
                    "8 Spring consumer Deployments; the 5 v1 tier-2 BFF Postgres ids are seeded "
                            + "here. mesh-bff, character-forge and federation have no "
                            + "backing-services.yaml id (federation is Citus-blocked)."),
            new AxisNamespace("hugmesh-pki", false,
                    "casdoor holds host=casdoor-pg inside a libpq dataSourceName TEMPLATE with "
                            + "credential placeholders substituted by an init container — no "
                            + "configMapKeyRef seam. headwind's SQL_HOST is a bare host in its "
                            + "own envFrom ConfigMap and has no registry id. route-access is "
                            + "excluded twice (credential in the address; Citus)."),
            new AxisNamespace("hugmesh-games", false,
                    "casdoor-games has no backing-services.yaml id AND holds its address inside "
                            + "the same dataSourceName template shape as casdoor."),
            new AxisNamespace("hugmesh-owncast", false,
                    "owncast HAS a real SPRING_R2DBC_URL/SPRING_LIQUIBASE_URL env seam but no "
                            + "backing-services.yaml id. Its namespace only exists when the "
                            + "optional service is installed, so its ConfigMap + grant ship "
                            + "from manifests/owncast/backing-service-endpoints.yaml, not from "
                            + "the always-on manifests/backing-service-endpoints/ bundle."),
            new AxisNamespace("hugmesh-tube", false,
                    "tube HAS a real SPRING_R2DBC_URL/SPRING_LIQUIBASE_URL env seam but no "
                            + "backing-services.yaml id. Its namespace only exists when the "
                            + "optional service is installed, so its ConfigMap + grant ship "
                            + "from manifests/tube/backing-service-endpoints.yaml."),
            new AxisNamespace("hugmesh-forum", false,
                    "phpbb carries PHPBB_DB_HOST (a bare host, not a URL) and has no registry "
                            + "id. Its namespace only exists when the optional service is "
                            + "installed, so its ConfigMap + grant ship from "
                            + "manifests/forum/backing-service-endpoints.yaml."));

    /**
     * One actuatable service: the namespace whose ConfigMap holds its keys, the in-mesh authority
     * to restore on {@code self-hosted}, the database name, and the consumer Deployments to roll.
     *
     * @param serviceId             the {@code backing-services.yaml} id VERBATIM — also the ledger
     *                              {@code service_id} and the ConfigMap key prefix, so no
     *                              translation table can rot between them
     * @param namespace             decision 34a: per service, never a constant
     * @param selfHostedAuthority   {@code host:port} of the in-mesh database, byte-identical to
     *                              the literal in the consumer's Deployment manifest
     * @param dbName                the database name, appended to whichever authority is in force
     * @param consumerDeployments   the Deployments to roll — decision 34b's "1, not 40"
     */
    public record Entry(String serviceId, String namespace, String selfHostedAuthority,
                        String dbName, List<String> consumerDeployments) {
    }

    /**
     * The closed set of services this effector can actuate TODAY: exactly the ids that have BOTH
     * a {@code backing-services.yaml} tier-1/2 entry AND a checked-in ConfigMap key. An id outside
     * it is REFUSED, never silently skipped — which is also what keeps the
     * {@code object-store} / {@code velero-objectstore} id split (hugmesh-admin-bff-api#58) from
     * quietly writing a key nothing reads.
     */
    static final Map<String, Entry> ENTRIES = Map.of(
            "postgres-admin-bff", new Entry("postgres-admin-bff", "hugmesh-backend",
                    "admin-bff-db.hugmesh-backend.svc.cluster.local:5432", "adminbff",
                    List.of("hugmesh-admin-bff-api")),
            "postgres-user-bff", new Entry("postgres-user-bff", "hugmesh-backend",
                    "user-bff-db.hugmesh-backend.svc.cluster.local:5432", "userbff",
                    List.of("hugmesh-user-bff-api")),
            "postgres-mod-bff", new Entry("postgres-mod-bff", "hugmesh-backend",
                    "mod-bff-db.hugmesh-backend.svc.cluster.local:5432", "modbff",
                    List.of("hugmesh-mod-bff-api")),
            "postgres-forum-bff", new Entry("postgres-forum-bff", "hugmesh-backend",
                    "forum-bff-db.hugmesh-backend.svc.cluster.local:5432", "forumbff",
                    List.of("hugmesh-forum-bff-api")),
            "postgres-wiki-bff", new Entry("postgres-wiki-bff", "hugmesh-backend",
                    "wiki-bff-db.hugmesh-backend.svc.cluster.local:5432", "wikibff",
                    List.of("hugmesh-wiki-bff-api")));

    /** The actuatable ids, for honest logging and for the tests' closure assertions. */
    public static List<String> actuatableServiceIds() {
        return ENTRIES.keySet().stream().sorted().toList();
    }

    /** The entry for an id, or empty when this effector cannot actuate it. */
    public static Optional<Entry> entry(String serviceId) {
        return serviceId == null ? Optional.empty() : Optional.ofNullable(ENTRIES.get(serviceId));
    }

    /**
     * A resolved plan.
     *
     * @param serviceId           the id being flipped
     * @param namespace           the namespace whose ConfigMap to patch (decision 34a)
     * @param data                EXACTLY the keys this service owns — never a whole-object replace,
     *                            which would clobber a concurrent flip and fight the build-time
     *                            baseline of every other key
     * @param consumerDeployments the Deployments to annotate (decision 34b)
     * @param generation          the ledger row's generation, stamped as the annotation value
     */
    public record Plan(String serviceId, String namespace, Map<String, String> data,
                       List<String> consumerDeployments, long generation) {

        /** The ConfigMap name — the same in every namespace (decision 34a). */
        public String configMapName() {
            return CONFIGMAP_NAME;
        }

        /** The annotation value that makes the reconcile loop idempotent. */
        public String generationAnnotationValue() {
            return Long.toString(generation);
        }
    }

    /**
     * Resolve a recorded intent into a plan, or empty when it must be REFUSED. Total: never
     * throws, never dials anything.
     *
     * <p>Refused, each for a stated reason:
     * <ul>
     *   <li>a null intent, or an id with no {@link #ENTRIES} entry — includes every tier-3
     *       docs-only service and every id whose consumer has no ConfigMap key yet;</li>
     *   <li>an unknown mode string (only {@code self-hosted} and {@code managed} exist);</li>
     *   <li>a managed intent with a blank endpoint, or one that is not the registry's
     *       {@code host:port} shape. {@code ://}, {@code @}, a path, whitespace or a quote are all
     *       rejected — an endpoint carrying a credential must never reach a ConfigMap, which is
     *       world-readable in its namespace, committed to git, and in every ArgoCD diff.</li>
     * </ul>
     */
    public static Optional<Plan> forMode(BackingServiceMode desired) {
        if (desired == null) {
            return Optional.empty();
        }
        Entry e = ENTRIES.get(desired.serviceId());
        if (e == null) {
            return Optional.empty();
        }
        String authority;
        if (BackingServiceMode.MODE_SELF_HOSTED.equals(desired.mode())) {
            authority = e.selfHostedAuthority();
        } else if (BackingServiceMode.MODE_MANAGED.equals(desired.mode())) {
            String endpoint = desired.endpoint() == null ? "" : desired.endpoint().trim();
            if (!isPlainAuthority(endpoint)) {
                return Optional.empty();
            }
            authority = endpoint;
        } else {
            return Optional.empty();
        }
        Map<String, String> data = new LinkedHashMap<>();
        data.put(e.serviceId() + "." + FIELD_R2DBC_URL,
                "r2dbc:postgresql://" + authority + "/" + e.dbName());
        data.put(e.serviceId() + "." + FIELD_LIQUIBASE_URL,
                "jdbc:postgresql://" + authority + "/" + e.dbName());
        return Optional.of(new Plan(e.serviceId(), e.namespace(), Map.copyOf(data),
                e.consumerDeployments(), desired.generation()));
    }

    /**
     * {@code host:port} and nothing else — the registry's {@code endpointFormat} for every
     * {@code postgres-*} id. Fail-closed: anything that could smuggle a credential, a path, a
     * second URL or a YAML break into a git-committed ConfigMap is rejected rather than escaped.
     */
    static boolean isPlainAuthority(String endpoint) {
        if (endpoint == null || endpoint.isBlank()) {
            return false;
        }
        for (int i = 0; i < endpoint.length(); i++) {
            char c = endpoint.charAt(i);
            if (Character.isWhitespace(c) || c == '@' || c == '/' || c == '\\' || c == '?'
                    || c == '#' || c == '"' || c == '\'' || c == '$' || c == '%' || c == ',') {
                return false;
            }
        }
        return endpoint.indexOf(':') > 0 && endpoint.indexOf(':') == endpoint.lastIndexOf(':')
                && endpoint.indexOf(':') < endpoint.length() - 1;
    }
}
