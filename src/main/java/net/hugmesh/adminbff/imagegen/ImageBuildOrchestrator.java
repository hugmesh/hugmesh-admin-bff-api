package net.hugmesh.adminbff.imagegen;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.publisher.Sinks;
import reactor.core.scheduler.Schedulers;
import net.hugmesh.adminbff.sshterminal.ImageBuild;
import net.hugmesh.adminbff.sshterminal.ImageBuildRepository;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Orchestrates an image-generation build: render the image-gen Job manifest, apply it via the
 * {@link ImageJobLauncher} (fabric8 when {@code imagegen.launch.enabled=true}, no-op
 * otherwise — SHIPS DARK), hold the per-build SSE event bus, and ingest the terminal event the
 * in-cluster Job POSTs back — persisting the {@code image_build} row terminally AND fanning the
 * event to live subscribers.
 *
 * <p>Logic-mirror of {@link net.hugmesh.adminbff.testreports.TestRunOrchestrator}: same
 * {@code Sinks.many().replay().limit(N)} bounded SSE bus (so a long build cannot grow the
 * per-pod buffer without limit), same {@code subscribeOn(boundedElastic)} launch, same
 * fail-closed {@code onErrorResume} that ERRORs the build instead of crashing the request.
 *
 * <p>SECURITY: nothing in this orchestrator ever touches secret bytes. The Job manifest carries
 * NO private key (the dial private key reaches the Job pod only via an ESO-synced k8s Secret
 * mount, never the manifest); {@code imageRef} / {@code keysRef} are non-secret pointers.
 */
@Component
@SuppressFBWarnings(value = "EI_EXPOSE_REP2",
        justification = "Spring constructor injection: the container owns this singleton collaborator and it is never mutated by this class after construction; a defensive copy of a bean is meaningless (not caller-owned mutable data).")
public class ImageBuildOrchestrator {

    private static final Logger log = LoggerFactory.getLogger(ImageBuildOrchestrator.class);

    private final ImageBuildRepository repo;
    private final ImageJobLauncher launcher;
    private final int replayBuffer;

    /** Per-build hot event bus. Replay(N) so a late SSE subscriber still sees the last N events
     *  (a build may have started before the admin-ui connected). */
    private final Map<String, Sinks.Many<ImageBuildEvent>> sinks = new ConcurrentHashMap<>();

    public ImageBuildOrchestrator(
            ImageBuildRepository repo,
            ImageJobLauncher launcher,
            @Value("${imagegen.sse.replay-buffer:256}") int replayBuffer) {
        this.repo = repo;
        this.launcher = launcher;
        this.replayBuffer = Math.max(1, replayBuffer);
    }

    /** True when the launcher actually applies Jobs to a cluster (the dark-shipping seam signal). */
    public boolean launchIsReal() {
        return launcher.isReal();
    }

    /**
     * Launch the image-gen Job for an already-persisted QUEUED {@link ImageBuild}. Renders +
     * applies the Job, records the Job name + RUNNING status, and registers the SSE sink.
     * Returns when the launch is submitted; the terminal result arrives via {@link #ingest}.
     */
    public Mono<Void> launch(ImageBuild build) {
        sinks.computeIfAbsent(build.id(),
                k -> Sinks.many().replay().limit(replayBuffer));
        // renderManifest is NOT pure string templating: it re-reads jobs/image-gen-job.yaml
        // out of the app jar on EVERY call (ClassPathResource#getInputStream, uncached), which
        // is blocking I/O. launch() is composed downstream of an R2DBC insert
        // (ImageBuildService: builds.insert(...).flatMap(b -> orchestrator.launch(b)...)), so
        // the subscribing thread is an R2DBC/Netty event loop — the render MUST keep its own
        // boundedElastic offload. The launcher seam carries a SECOND, independent offload for
        // the blocking fabric8 round-trip (Mono.usingWhen inside Fabric8ImageJobLauncher);
        // neither substitutes for the other.
        return Mono.fromCallable(() -> renderManifest(build))
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(manifest -> launcher.apply(manifest, build.id()))
                .flatMap(jobName -> repo.updateStatus(build.id(), ImageBuild.STATUS_RUNNING)
                        .doOnSuccess(v -> emit(build.id(), ImageBuildEvent.progress(build.id(), 0,
                                "image-gen Job '" + jobName + "' launched (type=" + build.imageType()
                                        + ", hardware=" + nz(build.hardwareClass()) + ")"))))
                .then()
                .onErrorResume(e -> {
                    log.warn("[imagegen] launch of build {} failed: {}", build.id(), e.toString());
                    emit(build.id(), ImageBuildEvent.failed(build.id(), e.getMessage()));
                    completeSink(build.id());
                    return repo.updateStatus(build.id(), ImageBuild.STATUS_ERROR).then();
                });
    }

    /**
     * Ingest the terminal event the in-cluster image-gen Job POSTed for {@code buildId}: close
     * out the {@code image_build} row ({@code COMPLETED} / {@code FAILED} / {@code ERROR}),
     * recording ONLY the non-secret {@code imageRef} / {@code keysRef} pointers, then fan the
     * terminal SSE event to live subscribers and complete the sink. Returns the freshly-updated
     * {@link ImageBuild}.
     *
     * <p>SECURITY: this method writes only the lifecycle status — the persistence of the
     * (non-secret) artifact pointers + device/dial fingerprints is done by the service BEFORE
     * this call; no private key ever reaches here.
     */
    public Mono<ImageBuild> ingest(String buildId, String status, String imageRef, String keysRef,
                                   String message, String error) {
        return repo.updateStatus(buildId, status)
                // Fan out the terminal SSE event and complete the sink after persisting status.
                .then(Mono.defer(() -> emitTerminalEventAndFetch(buildId, status, imageRef, keysRef, message, error)));
    }

    /** Emit the COMPLETED or FAILED terminal SSE event, close the sink, then return the updated build row. */
    private Mono<ImageBuild> emitTerminalEventAndFetch(String buildId, String status,
                                                        String imageRef, String keysRef,
                                                        String message, String error) {
        if (ImageBuild.STATUS_COMPLETED.equals(status)) {
            emit(buildId, ImageBuildEvent.complete(buildId, imageRef, keysRef,
                    message == null ? "image build completed" : message));
        } else {
            emit(buildId, ImageBuildEvent.failed(buildId,
                    error == null ? "image build " + status.toLowerCase() : error));
        }
        completeSink(buildId);
        return repo.findById(buildId);
    }

    /**
     * Emit a NON-TERMINAL progress event for a running build (worklist redesign item 8): the
     * in-cluster Job POSTs 0..N of these to {@code /bff/internal/image-builds/{id}/progress}
     * while a build runs. Fans an SSE {@code progress} frame ({@code done=false}) to live
     * subscribers WITHOUT completing the sink — the single terminal {@link #ingest} still closes
     * it. Unknown/reaped build → a no-op (the emit finds no sink). Never stamps {@code finished_at}.
     */
    public Mono<Void> progress(String buildId, int percent, String phase, String message) {
        String text = message == null ? (phase == null ? "building" : phase) : message;
        emit(buildId, new ImageBuildEvent(buildId, phase == null ? ImageBuildEvent.PHASE_RUNNING : phase,
                percent, text, null, null, false, null));
        return Mono.empty();
    }

    /** The SSE stream for a build id. Unknown / reaped build → an empty completed stream (the
     *  admin-ui then falls back to the durable DB row), never a hang/error. */
    public Flux<ImageBuildEvent> events(String buildId) {
        Sinks.Many<ImageBuildEvent> sink = sinks.get(buildId);
        return sink == null ? Flux.empty() : sink.asFlux();
    }

    // ── manifest templating (TestRunOrchestrator.renderManifest style) ───────

    /** Where the per-build spec ConfigMap is mounted inside the builder pod (matches the
     *  {@code image-spec} volumeMount in {@code jobs/image-gen-job.yaml}). */
    static final String SPEC_MOUNT_PATH = "/image-spec/spec.json";

    String renderManifest(ImageBuild build) {
        String template;
        try {
            byte[] bytes = new ClassPathResource("jobs/image-gen-job.yaml").getInputStream().readAllBytes();
            template = new String(bytes, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new IllegalStateException("image-gen job template missing: jobs/image-gen-job.yaml", e);
        }
        // Only NON-SECRET, server-derived values are substituted. The private dial key is NEVER
        // templated in — it reaches the Job pod via an ESO-synced k8s Secret mount referenced in
        // the manifest, read from the mount at run time.
        //
        // DEFENCE-IN-DEPTH: the client-supplied placeholders are already @Pattern-locked on the
        // request DTO (TriggerImageBuildRequest), but we re-check at render time so a value that
        // ever reached the DB by another path cannot break out of a YAML scalar and inject sibling
        // Job keys. A value carrying a YAML-breaking char (quote/newline/control) THROWS here,
        // before client.load(), failing the build closed rather than applying a poisoned manifest.
        //
        // NOTE the tenancy invariant: ${DOMAIN} is substituted from build.domain() — the
        // SERVER-derived validated-issuer domain — NEVER from the spec's cluster_domain (which the
        // worker treats as a last-wins overlay it overwrites). A client tenancy domain is never honoured.
        String spec = build.imageSpecJson();
        boolean hasSpec = spec != null && !spec.isBlank();
        // Decisions 73b/73c (hugmesh-admin-bff-api#53): the BFF is the source of the device's
        // stable id and of the Vault path of its dial key. Both are SERVER-derived from the build
        // id (DeviceDialIdentity — the same helpers seedDial checks the Job's report against), the
        // Job receives them as DEVICE_ID / VAULT_REF, and the dial-key volume mounts the
        // per-device Secret device-ssh-<DEVICE_ID>. yamlSafe is belt-and-braces: the values are
        // [a-z0-9-/] by construction.
        String deviceId = yamlSafe("deviceId", DeviceDialIdentity.mintDeviceId(build.id()));
        String vaultRef = yamlSafe("vaultRef", DeviceDialIdentity.vaultRefFor(deviceId));
        String jobDoc = template
                .replace("${DEVICE_ID}", deviceId)
                .replace("${VAULT_REF}", vaultRef)
                .replace("${BUILD_ID}", build.id())
                .replace("${TARGET_USER}", yamlSafe("targetUser", nz(build.targetUser())))
                .replace("${DOMAIN}", nz(build.domain()))
                .replace("${IMAGE_TYPE}", nz(build.imageType()))
                .replace("${HARDWARE_CLASS}", yamlSafe("hardwareClass", nz(build.hardwareClass())))
                .replace("${SSH_KEYS_ALLOWED}", Boolean.toString(build.sshKeysAllowed()))
                // PER-BUILD spec-channel switch (the legacy seam fix): the worker
                // (build-image.sh) branches on IMAGE_SPEC_JSON being NON-EMPTY and then
                // HARD-FAILS if the file is missing, while a MISSING optional ConfigMap volume
                // still mounts as an EMPTY dir — so a constant path would kill every legacy
                // build at [ -f ] instead of falling back to BUILD_MODE=legacy. Legacy build =>
                // "" (worker takes the 6-env path); spec build => the mount path (a
                // somehow-missing file still fails CLOSED worker-side).
                .replace("${IMAGE_SPEC_PATH}", hasSpec ? SPEC_MOUNT_PATH : "");

        // FULL IMAGE_SPEC_JSON channel (item 1b): when a MATERIALIZED spec is persisted on the
        // row, PREPEND a per-build ConfigMap (spec.json) as a second YAML doc — the fabric8
        // launcher creates the ConfigMap FIRST, then the Job, and patches the ConfigMap with an
        // ownerReference to the Job (see Fabric8ImageJobLauncher). When the spec is null the
        // LEGACY single-doc 6-env manifest is emitted unchanged with an EMPTY IMAGE_SPEC_JSON
        // env (the worker falls back to BUILD_MODE=legacy). The spec is ALREADY fenced by the
        // worklist envelope validator (no SECRET_FIELDS / valid atoms / valid domain names)
        // BEFORE it reached the row — but yamlSafe() only guards the substituted scalars, NOT
        // this ConfigMap body, so we re-assert the spec is a single-line document (compact JSON
        // has no literal CR/LF) as a final backstop before embedding it in the block scalar.
        if (!hasSpec) {
            return jobDoc;
        }
        for (int i = 0; i < spec.length(); i++) {
            char c = spec.charAt(i);
            if (c == '\n' || c == '\r') {
                throw new IllegalArgumentException(
                        "image_spec_json must be a single-line document (no raw newlines)");
            }
        }
        String configMapDoc = ""
                + "apiVersion: v1\n"
                + "kind: ConfigMap\n"
                + "metadata:\n"
                + "  name: hugmesh-image-spec-" + build.id() + "\n"
                + "  namespace: hugmesh-backend\n"
                + "  labels:\n"
                + "    app.kubernetes.io/part-of: hugmesh\n"
                + "    app.kubernetes.io/component: image-gen\n"
                + "    hugmesh.net/image-build-id: \"" + build.id() + "\"\n"
                + "data:\n"
                + "  spec.json: |\n"
                + "    " + spec + "\n"
                + "---\n";
        return configMapDoc + jobDoc;
    }

    /**
     * Render-time guard: reject (throw) if a value to be substituted into a quoted YAML scalar
     * still carries a YAML-breaking character — a double/single quote, backslash, CR, LF or any
     * other ISO control character. This is the defence-in-depth backstop to the DTO {@code @Pattern}
     * allowlists; it runs BEFORE the manifest is parsed/applied, so an injection attempt fails the
     * build closed instead of producing a poisoned Job. Returns the value unchanged when safe.
     */
    static String yamlSafe(String field, String value) {
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '"' || c == '\'' || c == '\\' || Character.isISOControl(c)) {
                throw new IllegalArgumentException(
                        "image-gen manifest value '" + field + "' contains an illegal character");
            }
        }
        return value;
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private void emit(String buildId, ImageBuildEvent ev) {
        Sinks.Many<ImageBuildEvent> sink = sinks.get(buildId);
        if (sink != null) sink.tryEmitNext(ev);
    }

    private void completeSink(String buildId) {
        Sinks.Many<ImageBuildEvent> sink = sinks.get(buildId);
        if (sink != null) sink.tryEmitComplete();
    }

    private static String nz(String s) {
        return s == null ? "" : s;
    }
}
