package systems.hugmesh.adminbff.backingservices;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * One recorded BACKING-SERVICE MODE intent — a superadmin's request to run a
 * {@link BackingServiceCatalog} service {@code self-hosted} (the default, in-mesh) or
 * {@code managed} (a hosted cloud equivalent at {@code endpoint}, creds referenced by
 * {@code credsRef}). The durable shape of a {@code backing_service_mode} row (Liquibase 310).
 *
 * <p><b>INTENT, not effect.</b> Recording a managed mode does NOT itself prune the in-mesh
 * workload or re-point any consumer endpoint — that is a build-time / reconciler act (the
 * generator {@code gate_backing_services} at image time; the ships-dark
 * {@link BackingServiceModeReconciler} skeleton at runtime, which logs-only in v1). This row
 * is the recorded desired state the effector leg converges toward.
 *
 * <p><b>Self-hosted is the byte-identical default.</b> No recorded row (or a {@code self-hosted}
 * row) means the in-mesh service is used unchanged — the #1 invariant of the whole axis.
 *
 * <p><b>NO SECRETS.</b> {@code endpoint} is a non-secret coordinate (a host/URL) and
 * {@code credsRef} is a REFERENCE only (an ESO/Vault path name), never credential bytes. The
 * operator-supplied managed-cloud credentials route to the generator side (env -> keys-file ->
 * ESO/Vault), never this DB and never this export.
 */
public record BackingServiceMode(
        String id,
        String serviceId,
        String mode,
        String endpoint,
        String credsRef,
        String requestedBySubject,
        Instant createdAt,
        long generation) {

    /** The in-mesh, self-hosted default (byte-identical — no managed swap). */
    public static final String MODE_SELF_HOSTED = "self-hosted";
    /** A hosted cloud equivalent at {@code endpoint}, creds referenced by {@code credsRef}. */
    public static final String MODE_MANAGED = "managed";

    /** True iff this intent selects a managed (hosted) backing service. */
    public boolean managed() {
        return MODE_MANAGED.equals(mode);
    }

    /** The wire map the admin UI renders for a recorded mode intent (no secret bytes). */
    public Map<String, Object> toMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", id);
        m.put("serviceId", serviceId);
        m.put("mode", mode);
        m.put("endpoint", endpoint);
        m.put("credsRef", credsRef);
        m.put("requestedBySubject", requestedBySubject);
        m.put("createdAt", createdAt);
        m.put("generation", generation);
        return m;
    }
}
