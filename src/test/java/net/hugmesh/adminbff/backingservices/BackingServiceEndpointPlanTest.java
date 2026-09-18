package net.hugmesh.adminbff.backingservices;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pins the two operator decisions of 2026-09-17 that this lane implemented, so a later agent
 * cannot drift off them by "simplifying".
 *
 * <ul>
 *   <li><b>34a — one ConfigMap PER NAMESPACE</b>, which the operator chose OVER the recommended
 *       single {@code hugmesh-backend} object. {@link #decision34a_theAxisIsSixNamespaces_notOne}
 *       and {@link #decision34a_namespaceIsPerService_notAConstant} go RED the moment the axis is
 *       collapsed back to one namespace or the namespace becomes a constant.</li>
 *   <li><b>34b — a TARGETED ROLLING RESTART</b>.
 *       {@link #decision34b_flippingWikiRollsExactlyOneDeployment} pins "1 Deployment, not 40" and
 *       {@link #decision34b_everyPlanCarriesAConsumerToRoll} pins that the restart half cannot be
 *       dropped — a plan with no consumer is the silent-no-op flip the decision exists to
 *       prevent.</li>
 * </ul>
 *
 * <p>Nothing here touches a cluster: {@link BackingServiceEndpointPlan} is a total pure function.
 */
class BackingServiceEndpointPlanTest {

    private static BackingServiceMode mode(String serviceId, String m, String endpoint, long gen) {
        return new BackingServiceMode("row-1", serviceId, m, endpoint, "vault/x", "superadmin@x",
                Instant.EPOCH, gen);
    }

    // ── DECISION 34a — the per-namespace fan-out ────────────────────────────────────────────

    @Test
    void decision34a_theAxisIsSixNamespaces_notOne() {
        List<String> axis = BackingServiceEndpointPlan.AXIS_NAMESPACES.stream()
                .map(BackingServiceEndpointPlan.AxisNamespace::namespace).toList();

        // The operator DECLINED "one shared object in hugmesh-backend". If someone re-scopes the
        // axis to a single namespace, this is the assertion that fails.
        assertThat(axis)
                .as("decision 34a: one ConfigMap PER NAMESPACE — the axis is not hugmesh-backend alone")
                .containsExactly("hugmesh-backend", "hugmesh-pki", "hugmesh-games",
                        "hugmesh-owncast", "hugmesh-tube", "hugmesh-forum");
        assertThat(axis).doesNotHaveDuplicates().hasSize(6);

        // hugmesh-frontend holds a Postgres address too (fe-gateway's route-access URL) and is
        // deliberately NOT on the axis: that URL carries the password inside it and Kubernetes
        // does not expand $(VAR) inside ConfigMap data. Pinned so the omission reads as a
        // decision rather than a miss.
        assertThat(axis).doesNotContain("hugmesh-frontend");

        // Exactly one namespace carries keys today; every other one records WHY it does not.
        assertThat(BackingServiceEndpointPlan.AXIS_NAMESPACES)
                .filteredOn(BackingServiceEndpointPlan.AxisNamespace::seeded)
                .extracting(BackingServiceEndpointPlan.AxisNamespace::namespace)
                .containsExactly("hugmesh-backend");
        assertThat(BackingServiceEndpointPlan.AXIS_NAMESPACES)
                .allSatisfy(ns -> assertThat(ns.note()).isNotBlank());
    }

    @Test
    void decision34a_namespaceIsPerService_notAConstant() {
        // Every actuatable id resolves its namespace from its own entry. The fan-out writer reads
        // Plan#namespace(); a hardcoded namespace in the effector would make this class's data
        // meaningless, and Fabric8BackingServiceEffectorMockServerTest is what catches that.
        for (String id : BackingServiceEndpointPlan.actuatableServiceIds()) {
            BackingServiceEndpointPlan.Entry e = BackingServiceEndpointPlan.entry(id).orElseThrow();
            assertThat(e.namespace())
                    .as("%s must name a namespace that is on the 34a axis", id)
                    .isIn(BackingServiceEndpointPlan.AXIS_NAMESPACES.stream()
                            .map(BackingServiceEndpointPlan.AxisNamespace::namespace).toList());
        }
        // And the object NAME is identical in every namespace — "same name and key scheme in each".
        assertThat(BackingServiceEndpointPlan.forMode(
                        mode("postgres-wiki-bff", BackingServiceMode.MODE_SELF_HOSTED, null, 1))
                .orElseThrow().configMapName())
                .isEqualTo("backing-service-endpoints");
    }

    // ── DECISION 34b — the targeted rolling restart ─────────────────────────────────────────

    @Test
    void decision34b_flippingWikiRollsExactlyOneDeployment() {
        BackingServiceEndpointPlan.Plan plan = BackingServiceEndpointPlan.forMode(
                        mode("postgres-wiki-bff", BackingServiceMode.MODE_MANAGED,
                                "wiki.abc123.eu-west-1.rds.amazonaws.com:5432", 7))
                .orElseThrow();

        assertThat(plan.consumerDeployments())
                .as("decision 34b: flipping postgres-wiki-bff restarts 1 Deployment, not 40")
                .containsExactly("hugmesh-wiki-bff-api");
        assertThat(plan.namespace()).isEqualTo("hugmesh-backend");
        assertThat(plan.generationAnnotationValue()).isEqualTo("7");
    }

    @Test
    void decision34b_everyPlanCarriesAConsumerToRoll() {
        // The ConfigMap-only flip is the silent no-op 34b exists to prevent: configMapKeyRef env
        // is resolved once at container creation, so a plan with nothing to roll would be
        // recorded, applied, reported green, and change nothing in any running pod.
        for (String id : BackingServiceEndpointPlan.actuatableServiceIds()) {
            BackingServiceEndpointPlan.Plan plan = BackingServiceEndpointPlan.forMode(
                    mode(id, BackingServiceMode.MODE_SELF_HOSTED, null, 1)).orElseThrow();
            assertThat(plan.consumerDeployments())
                    .as("%s must name at least one consumer Deployment to roll", id)
                    .isNotEmpty();
        }
        // No service may name another service's consumer: a flip that rolled a neighbour would be
        // a fleet restart wearing a targeted restart's name.
        List<String> all = BackingServiceEndpointPlan.actuatableServiceIds().stream()
                .flatMap(id -> BackingServiceEndpointPlan.entry(id).orElseThrow()
                        .consumerDeployments().stream())
                .toList();
        assertThat(all).doesNotHaveDuplicates().hasSize(5);
    }

    // ── The key scheme and the byte-identical self-hosted default ───────────────────────────

    @Test
    void twoKeysPerService_prefixedByTheRegistryIdVerbatim() {
        BackingServiceEndpointPlan.Plan plan = BackingServiceEndpointPlan.forMode(
                mode("postgres-admin-bff", BackingServiceMode.MODE_SELF_HOSTED, null, 3))
                .orElseThrow();
        assertThat(plan.data()).containsOnlyKeys(
                "postgres-admin-bff.r2dbc-url", "postgres-admin-bff.liquibase-url");
    }

    @Test
    void selfHostedRestoresTheByteIdenticalInMeshLiterals() {
        // These are character-for-character the literals in
        // hugmesh-generator specs/cluster/manifests/<svc>/deployment.yaml and the values seeded
        // into manifests/backing-service-endpoints/endpoints-hugmesh-backend.yaml. Recomposed
        // from the registry, never remembered — otherwise one bad managed flip becomes the
        // permanent "default".
        Map<String, String> expected = Map.of(
                "postgres-admin-bff", "admin-bff-db.hugmesh-backend.svc.cluster.local:5432/adminbff",
                "postgres-user-bff", "user-bff-db.hugmesh-backend.svc.cluster.local:5432/userbff",
                "postgres-mod-bff", "mod-bff-db.hugmesh-backend.svc.cluster.local:5432/modbff",
                "postgres-forum-bff", "forum-bff-db.hugmesh-backend.svc.cluster.local:5432/forumbff",
                "postgres-wiki-bff", "wiki-bff-db.hugmesh-backend.svc.cluster.local:5432/wikibff");
        assertThat(BackingServiceEndpointPlan.actuatableServiceIds())
                .containsExactlyInAnyOrderElementsOf(expected.keySet());
        expected.forEach((id, tail) -> {
            Map<String, String> data = BackingServiceEndpointPlan.forMode(
                    mode(id, BackingServiceMode.MODE_SELF_HOSTED, null, 1)).orElseThrow().data();
            assertThat(data.get(id + ".r2dbc-url")).isEqualTo("r2dbc:postgresql://" + tail);
            assertThat(data.get(id + ".liquibase-url")).isEqualTo("jdbc:postgresql://" + tail);
        });
    }

    @Test
    void managedComposesBothHandlesFromTheSameEndpoint() {
        Map<String, String> data = BackingServiceEndpointPlan.forMode(
                mode("postgres-mod-bff", BackingServiceMode.MODE_MANAGED,
                        "mod.abc123.eu-west-1.rds.amazonaws.com:5432", 12)).orElseThrow().data();
        assertThat(data.get("postgres-mod-bff.r2dbc-url"))
                .isEqualTo("r2dbc:postgresql://mod.abc123.eu-west-1.rds.amazonaws.com:5432/modbff");
        assertThat(data.get("postgres-mod-bff.liquibase-url"))
                .isEqualTo("jdbc:postgresql://mod.abc123.eu-west-1.rds.amazonaws.com:5432/modbff");
    }

    // ── Refusals — every one fail-closed ───────────────────────────────────────────────────

    @Test
    void refusesUnknownAndNonActuatableIds() {
        assertThat(BackingServiceEndpointPlan.forMode(null)).isEmpty();
        assertThat(BackingServiceEndpointPlan.forMode(
                mode("nope", BackingServiceMode.MODE_SELF_HOSTED, null, 1))).isEmpty();
        // tier-3 docs-only: refused because it has no entry, not by a separate branch that could rot
        assertThat(BackingServiceEndpointPlan.forMode(
                mode("vault-pki", BackingServiceMode.MODE_MANAGED, "v.example.net:8200", 1)))
                .isEmpty();
        // The catalog/registry id split (hugmesh-admin-bff-api#58): the admin catalog says
        // `object-store`, the generator registry says `velero-objectstore`. Neither is actuatable
        // here, so a recorded intent for either is refused rather than writing a key nothing reads.
        assertThat(BackingServiceEndpointPlan.forMode(
                mode("object-store", BackingServiceMode.MODE_MANAGED, "s3.example.net:443", 1)))
                .isEmpty();
        assertThat(BackingServiceEndpointPlan.forMode(
                mode("velero-objectstore", BackingServiceMode.MODE_MANAGED, "s3.example.net:443", 1)))
                .isEmpty();
    }

    @Test
    void refusesAnythingThatIsNotABareHostPort() {
        String id = "postgres-admin-bff";
        // A credential must never reach a ConfigMap: it is world-readable in its namespace,
        // committed to git, and in every ArgoCD diff.
        assertThat(BackingServiceEndpointPlan.forMode(
                mode(id, BackingServiceMode.MODE_MANAGED, "u:p@db.example.net:5432", 1))).isEmpty();
        assertThat(BackingServiceEndpointPlan.forMode(
                mode(id, BackingServiceMode.MODE_MANAGED,
                        "r2dbc:postgresql://db.example.net:5432", 1))).isEmpty();
        assertThat(BackingServiceEndpointPlan.forMode(
                mode(id, BackingServiceMode.MODE_MANAGED, "db.example.net:5432/other", 1))).isEmpty();
        assertThat(BackingServiceEndpointPlan.forMode(
                mode(id, BackingServiceMode.MODE_MANAGED, "db.example.net", 1))).isEmpty();
        assertThat(BackingServiceEndpointPlan.forMode(
                mode(id, BackingServiceMode.MODE_MANAGED, "db.example.net:", 1))).isEmpty();
        assertThat(BackingServiceEndpointPlan.forMode(
                mode(id, BackingServiceMode.MODE_MANAGED, "db.example.net:5432 x", 1))).isEmpty();
        assertThat(BackingServiceEndpointPlan.forMode(
                mode(id, BackingServiceMode.MODE_MANAGED, "  ", 1))).isEmpty();
        assertThat(BackingServiceEndpointPlan.forMode(
                mode(id, BackingServiceMode.MODE_MANAGED, null, 1))).isEmpty();
        // an unknown mode string is refused, not treated as self-hosted
        assertThat(BackingServiceEndpointPlan.forMode(
                mode(id, "hybrid", "db.example.net:5432", 1))).isEmpty();
        // the accepted shape
        assertThat(BackingServiceEndpointPlan.forMode(
                mode(id, BackingServiceMode.MODE_MANAGED, "db.example.net:5432", 1))).isPresent();
    }
}
