package systems.hugmesh.adminbff.sshterminal;

import java.time.Instant;

/**
 * A single {@code image_build} row — one requested image build for the in-UI
 * image-generation feature (schema in Liquibase {@code db/changelog/171-image-build.xml}).
 *
 * <p>SHIPS DARK: a request records a {@code QUEUED} catalog row; the generator Job effector
 * is a LATER PR, so nothing emits a real build yet. {@code jobName} / {@code imageRef} /
 * {@code keysRef} are REFERENCES only — never secret bytes ({@code keysRef} points at a
 * build-artifacts location, never keys themselves).
 *
 * <ul>
 *   <li>{@code requestedBy} — the JWT SUBJECT that asked; {@code targetUser} — the subject
 *       the image is FOR (owner == subject enforced in the service later).</li>
 *   <li>{@code domain} — the validated-issuer brand the build belongs to.</li>
 *   <li>{@code imageType} — {@code primary} / {@code mesh-extension} / {@code client} (the
 *       same closed vocabulary as {@code device_registry.image_type}, CHECK-constrained).</li>
 *   <li>{@code hardwareClass} — the optional target hardware; {@code deviceId} — the device
 *       this image is bound to, if any.</li>
 *   <li>{@code status} — {@code QUEUED} / {@code RUNNING} / {@code COMPLETED} /
 *       {@code FAILED} / {@code ERROR} (the 070 lifecycle vocabulary). Starts
 *       {@code QUEUED}.</li>
 *   <li>{@code sshKeysAllowed} — whether the build may emit a downloadable SSH-keys bundle.
 *       Defaults {@code false} = fail-closed.</li>
 *   <li>{@code imageSpecJson} — the MATERIALIZED flat per-image ImageConfig spec (secrets
 *       blanked) for the FULL IMAGE_SPEC_JSON channel (changelog 280), or {@code null} for
 *       the legacy 6-env manifest path. Written to a per-build ConfigMap by the orchestrator;
 *       must have passed the worklist.v1 envelope validator (spec-injection gate) first.</li>
 * </ul>
 */
public record ImageBuild(
        String id,
        Instant createdAt,
        String requestedBy,
        String targetUser,
        String domain,
        String imageType,
        String hardwareClass,
        String deviceId,
        String status,
        boolean sshKeysAllowed,
        String jobName,
        String imageRef,
        String keysRef,
        Instant startedAt,
        Instant finishedAt,
        String error,
        String imageSpecJson) {

    /**
     * Back-compat 16-arg constructor (no spec) — every legacy call site that built an
     * {@link ImageBuild} before the 280 IMAGE_SPEC_JSON channel keeps compiling unchanged,
     * defaulting {@code imageSpecJson} to {@code null} (the legacy 6-env manifest path).
     */
    public ImageBuild(String id, Instant createdAt, String requestedBy, String targetUser,
                      String domain, String imageType, String hardwareClass, String deviceId,
                      String status, boolean sshKeysAllowed, String jobName, String imageRef,
                      String keysRef, Instant startedAt, Instant finishedAt, String error) {
        this(id, createdAt, requestedBy, targetUser, domain, imageType, hardwareClass, deviceId,
                status, sshKeysAllowed, jobName, imageRef, keysRef, startedAt, finishedAt, error, null);
    }

    public static final String STATUS_QUEUED = "QUEUED";
    public static final String STATUS_RUNNING = "RUNNING";
    public static final String STATUS_COMPLETED = "COMPLETED";
    public static final String STATUS_FAILED = "FAILED";
    public static final String STATUS_ERROR = "ERROR";

    public static final String IMAGE_PRIMARY = "primary";
    public static final String IMAGE_MESH_EXTENSION = "mesh-extension";
    public static final String IMAGE_CLIENT = "client";
}
