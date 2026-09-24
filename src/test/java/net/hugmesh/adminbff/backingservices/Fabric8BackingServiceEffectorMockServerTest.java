package net.hugmesh.adminbff.backingservices;

import io.fabric8.kubernetes.api.model.ConfigMap;
import io.fabric8.kubernetes.api.model.ConfigMapBuilder;
import io.fabric8.kubernetes.api.model.apps.Deployment;
import io.fabric8.kubernetes.api.model.apps.DeploymentBuilder;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.server.mock.EnableKubernetesMockClient;
import io.fabric8.kubernetes.client.server.mock.KubernetesMockServer;
import io.fabric8.mockwebserver.http.RecordedRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The effector's real cluster contract, against the fabric8 CRUD mock server — no cluster, no
 * kubeconfig. This is where the two operator decisions of 2026-09-17 are pinned as BEHAVIOUR
 * rather than as data:
 *
 * <ul>
 *   <li><b>34b</b> — {@link #wikiFlip_patchesTwoKeysAndRollsExactlyOneDeployment} fails if the
 *       effector stops stamping the pod-template annotation (the ConfigMap-only write that
 *       silently changes nothing in a running pod) AND fails if it stamps more Deployments than
 *       the one whose address moved. "1 Deployment, not 40", measured.</li>
 *   <li><b>34a</b> — {@link #writesIntoTheServicesOwnNamespace_notAHardcodedOne} seeds the
 *       ConfigMap in a DIFFERENT namespace from the one the plan names and proves the write does
 *       not land there. A hardcoded namespace in the effector turns this red.</li>
 *   <li>The reconciler is a {@code @Scheduled} loop, so
 *       {@link #reRunAtTheSameGenerationRollsNothing} pins that a converged service is a no-op —
 *       without it every tick would restart every flipped consumer forever.</li>
 * </ul>
 */
@EnableKubernetesMockClient(crud = true)
class Fabric8BackingServiceEffectorMockServerTest {

    private static final String NS = "hugmesh-backend";
    private static final String CM = "backing-service-endpoints";
    private static final String ANN = "hugmesh.net/backing-service-generation";

    private static final List<String> CONSUMERS = List.of(
            "hugmesh-admin-bff-api", "hugmesh-user-bff-api", "hugmesh-mod-bff-api",
            "hugmesh-forum-bff-api", "hugmesh-wiki-bff-api");

    KubernetesMockServer server;
    KubernetesClient client;

    private Fabric8BackingServiceEffector effector() {
        // A fresh client per converge() — the effector closes its own (try-with-resources) and
        // the extension-injected `client` must stay open for the assertions.
        return new Fabric8BackingServiceEffector(() -> server.createClient());
    }

    private static BackingServiceMode mode(String id, String m, String endpoint, long gen) {
        return new BackingServiceMode("row-1", id, m, endpoint, "vault/x", "superadmin@x",
                Instant.EPOCH, gen);
    }

    /** The self-hosted seed, exactly as the generator ConfigMap ships it. */
    private static Map<String, String> seedData() {
        Map<String, String> d = new LinkedHashMap<>();
        d.put("postgres-admin-bff.r2dbc-url",
                "r2dbc:postgresql://admin-bff-db.hugmesh-backend.svc.cluster.local:5432/adminbff");
        d.put("postgres-admin-bff.liquibase-url",
                "jdbc:postgresql://admin-bff-db.hugmesh-backend.svc.cluster.local:5432/adminbff");
        d.put("postgres-user-bff.r2dbc-url",
                "r2dbc:postgresql://user-bff-db.hugmesh-backend.svc.cluster.local:5432/userbff");
        d.put("postgres-user-bff.liquibase-url",
                "jdbc:postgresql://user-bff-db.hugmesh-backend.svc.cluster.local:5432/userbff");
        d.put("postgres-mod-bff.r2dbc-url",
                "r2dbc:postgresql://mod-bff-db.hugmesh-backend.svc.cluster.local:5432/modbff");
        d.put("postgres-mod-bff.liquibase-url",
                "jdbc:postgresql://mod-bff-db.hugmesh-backend.svc.cluster.local:5432/modbff");
        d.put("postgres-forum-bff.r2dbc-url",
                "r2dbc:postgresql://forum-bff-db.hugmesh-backend.svc.cluster.local:5432/forumbff");
        d.put("postgres-forum-bff.liquibase-url",
                "jdbc:postgresql://forum-bff-db.hugmesh-backend.svc.cluster.local:5432/forumbff");
        d.put("postgres-wiki-bff.r2dbc-url",
                "r2dbc:postgresql://wiki-bff-db.hugmesh-backend.svc.cluster.local:5432/wikibff");
        d.put("postgres-wiki-bff.liquibase-url",
                "jdbc:postgresql://wiki-bff-db.hugmesh-backend.svc.cluster.local:5432/wikibff");
        return d;
    }

    private void seedConfigMap(String namespace) {
        client.configMaps().inNamespace(namespace).resource(new ConfigMapBuilder()
                .withNewMetadata().withName(CM).withNamespace(namespace).endMetadata()
                .withData(seedData())
                .build()).create();
    }

    private void seedConsumers() {
        for (String name : CONSUMERS) {
            client.apps().deployments().inNamespace(NS).resource(new DeploymentBuilder()
                    .withNewMetadata().withName(name).withNamespace(NS).endMetadata()
                    .withNewSpec()
                    .withReplicas(1)
                    .withNewSelector().addToMatchLabels("app", name).endSelector()
                    .withNewTemplate()
                    .withNewMetadata().addToLabels("app", name).endMetadata()
                    .withNewSpec().addNewContainer().withName("app").withImage("x:1").endContainer()
                    .endSpec()
                    .endTemplate()
                    .endSpec()
                    .build()).create();
        }
    }

    private String annotationOf(String deployment) {
        Deployment d = client.apps().deployments().inNamespace(NS).withName(deployment).get();
        var meta = d.getSpec().getTemplate().getMetadata();
        return meta == null || meta.getAnnotations() == null ? null : meta.getAnnotations().get(ANN);
    }

    private Map<String, String> configMapData(String namespace) {
        ConfigMap cm = client.configMaps().inNamespace(namespace).withName(CM).get();
        return cm == null ? null : cm.getData();
    }

    @BeforeEach
    void setUp() {
        seedConfigMap(NS);
        seedConsumers();
    }

    @Test
    void wikiFlip_patchesTwoKeysAndRollsExactlyOneDeployment() {
        effector().converge(mode("postgres-wiki-bff", BackingServiceMode.MODE_MANAGED,
                "wiki.abc123.eu-west-1.rds.amazonaws.com:5432", 7));

        Map<String, String> data = configMapData(NS);
        // exactly the two keys of the flipped service moved …
        assertThat(data.get("postgres-wiki-bff.r2dbc-url"))
                .isEqualTo("r2dbc:postgresql://wiki.abc123.eu-west-1.rds.amazonaws.com:5432/wikibff");
        assertThat(data.get("postgres-wiki-bff.liquibase-url"))
                .isEqualTo("jdbc:postgresql://wiki.abc123.eu-west-1.rds.amazonaws.com:5432/wikibff");
        // … and every other key is byte-identical to the seed (a merge-patch, not a replace)
        seedData().forEach((k, v) -> {
            if (!k.startsWith("postgres-wiki-bff.")) {
                assertThat(data.get(k)).as("untouched key %s", k).isEqualTo(v);
            }
        });
        assertThat(data).hasSize(seedData().size());

        // DECISION 34b, the whole point: ONE Deployment carries the generation, four do not.
        assertThat(annotationOf("hugmesh-wiki-bff-api"))
                .as("the flipped service's consumer must be rolled — a ConfigMap-only write "
                        + "changes NOTHING in a running pod (configMapKeyRef resolves once)")
                .isEqualTo("7");
        for (String other : CONSUMERS) {
            if (!other.equals("hugmesh-wiki-bff-api")) {
                assertThat(annotationOf(other))
                        .as("%s must NOT be rolled: 1 Deployment, not 40", other)
                        .isNull();
            }
        }
    }

    /** Drain every request the mock server has recorded so far, returning "METHOD path" lines. */
    private List<String> drainRequests() throws InterruptedException {
        List<String> seen = new java.util.ArrayList<>();
        for (RecordedRequest r = server.takeRequest(10, TimeUnit.MILLISECONDS); r != null;
                r = server.takeRequest(10, TimeUnit.MILLISECONDS)) {
            seen.add(r.getMethod() + " " + r.getPath());
        }
        return seen;
    }

    @Test
    void reRunAtTheSameGenerationWritesNothing() throws InterruptedException {
        BackingServiceMode desired = mode("postgres-wiki-bff", BackingServiceMode.MODE_MANAGED,
                "wiki.abc123.eu-west-1.rds.amazonaws.com:5432", 7);
        effector().converge(desired);
        drainRequests();

        effector().converge(desired);
        List<String> second = drainRequests();

        // The reconciler is a @Scheduled loop over every recorded row. A converged service must
        // issue NO write at all, or every flipped consumer restarts on every tick, forever.
        // Asserted on the wire, not on resourceVersion: the CRUD mock server does not bump
        // resourceVersion for an edit that produces identical bytes, so a resourceVersion
        // comparison passes even when the effector re-patches on every pass.
        assertThat(second)
                .as("a second converge at the same generation must read, and write nothing")
                .isNotEmpty()
                .allSatisfy(line -> assertThat(line).startsWith("GET "));
        assertThat(annotationOf("hugmesh-wiki-bff-api")).isEqualTo("7");
    }

    @Test
    void aLaterGenerationRollsAgain() {
        effector().converge(mode("postgres-wiki-bff", BackingServiceMode.MODE_MANAGED,
                "wiki.abc123.eu-west-1.rds.amazonaws.com:5432", 7));
        effector().converge(mode("postgres-wiki-bff", BackingServiceMode.MODE_SELF_HOSTED, null, 8));

        assertThat(annotationOf("hugmesh-wiki-bff-api")).isEqualTo("8");
        // self-hosted recomposes the byte-identical in-mesh literal rather than remembering one
        assertThat(configMapData(NS).get("postgres-wiki-bff.r2dbc-url"))
                .isEqualTo(seedData().get("postgres-wiki-bff.r2dbc-url"));
    }

    @Test
    void writesIntoTheServicesOwnNamespace_notAHardcodedOne() {
        // Decision 34a's fan-out: the namespace is DATA on the plan, and the object NAME is the
        // same in every namespace. Every id that is actuatable TODAY happens to live in
        // hugmesh-backend, so the ONLY way to prove the writer is not hardcoded to it is to hand
        // it a plan in another namespace on the axis. A `hugmesh-backend` constant in the effector
        // turns this red — and that constant is exactly the single-object design the operator
        // declined.
        seedConfigMap("hugmesh-pki");
        client.apps().deployments().inNamespace("hugmesh-pki").resource(new DeploymentBuilder()
                .withNewMetadata().withName("casdoor").withNamespace("hugmesh-pki").endMetadata()
                .withNewSpec()
                .withReplicas(1)
                .withNewSelector().addToMatchLabels("app", "casdoor").endSelector()
                .withNewTemplate()
                .withNewMetadata().addToLabels("app", "casdoor").endMetadata()
                .withNewSpec().addNewContainer().withName("app").withImage("x:1").endContainer()
                .endSpec()
                .endTemplate()
                .endSpec()
                .build()).create();

        BackingServiceEndpointPlan.Plan pkiPlan = new BackingServiceEndpointPlan.Plan(
                "postgres-casdoor", "hugmesh-pki",
                Map.of("postgres-casdoor.r2dbc-url", "r2dbc:postgresql://pg.example.net:5432/casdoor"),
                List.of("casdoor"), 5);

        effector().converge(pkiPlan);

        assertThat(configMapData("hugmesh-pki").get("postgres-casdoor.r2dbc-url"))
                .as("the fan-out writer must patch the namespace the PLAN names")
                .isEqualTo("r2dbc:postgresql://pg.example.net:5432/casdoor");
        assertThat(configMapData(NS))
                .as("and must not touch hugmesh-backend's object")
                .isEqualTo(seedData());
        assertThat(client.apps().deployments().inNamespace("hugmesh-pki").withName("casdoor").get()
                .getSpec().getTemplate().getMetadata().getAnnotations().get(ANN))
                .as("the rolling restart follows the plan's namespace too")
                .isEqualTo("5");
        for (String c : CONSUMERS) {
            assertThat(annotationOf(c)).isNull();
        }
    }

    @Test
    void theRealServicesResolveToTheirOwnNamespace() {
        // The data half of the same decision: every actuatable id names a namespace that is on
        // the 34a axis, and its plan carries it through to the writer.
        BackingServiceEndpointPlan.Plan plan = BackingServiceEndpointPlan.forMode(
                mode("postgres-mod-bff", BackingServiceMode.MODE_MANAGED,
                        "mod.abc123.eu-west-1.rds.amazonaws.com:5432", 4)).orElseThrow();
        assertThat(plan.namespace()).isEqualTo(NS);

        effector().converge(plan);

        assertThat(configMapData(NS).get("postgres-mod-bff.r2dbc-url"))
                .isEqualTo("r2dbc:postgresql://mod.abc123.eu-west-1.rds.amazonaws.com:5432/modbff");
        assertThat(annotationOf("hugmesh-mod-bff-api")).isEqualTo("4");
    }

    @Test
    void refusedIntent_writesNothingAndRollsNothing() {
        // velero-objectstore is a real catalog id (hugmesh-admin-bff-api#58) with no ConfigMap
        // key; object-store is the retired id. Neither may write or roll anything.
        effector().converge(mode("velero-objectstore", BackingServiceMode.MODE_MANAGED,
                "s3.example.net:443", 9));
        effector().converge(mode("object-store", BackingServiceMode.MODE_MANAGED,
                "s3.example.net:443", 9));
        effector().converge(mode("postgres-wiki-bff", BackingServiceMode.MODE_MANAGED,
                "u:p@wiki.example.net:5432", 9));

        assertThat(configMapData(NS)).isEqualTo(seedData());
        for (String c : CONSUMERS) {
            assertThat(annotationOf(c)).isNull();
        }
    }

    @Test
    void missingConfigMap_rollsNothing_andDoesNotCreateTheObject() {
        client.configMaps().inNamespace(NS).withName(CM).delete();

        effector().converge(mode("postgres-wiki-bff", BackingServiceMode.MODE_MANAGED,
                "wiki.abc123.eu-west-1.rds.amazonaws.com:5432", 7));

        // The object is git-owned: a miss means the Application has not synced yet. Creating it
        // here would put an unmanaged object in the cluster and hide the real fault — and rolling
        // the consumer anyway would restart it against the address it already had.
        assertThat(configMapData(NS)).isNull();
        assertThat(annotationOf("hugmesh-wiki-bff-api")).isNull();
    }

    @Test
    void isReal_isTrue_soTheReconcilerLogsHonestly() {
        assertThat(effector().isReal()).isTrue();
        assertThat(new NoopBackingServiceEffector().isReal()).isFalse();
    }
}
