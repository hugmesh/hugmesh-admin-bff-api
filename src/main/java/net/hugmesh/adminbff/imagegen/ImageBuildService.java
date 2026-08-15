package net.hugmesh.adminbff.imagegen;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.authcore.casdoor.MfaStepUpService;
import net.hugmesh.adminbff.device.DeviceRegistryRepository;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.Roles;
import net.hugmesh.adminbff.sshterminal.DeviceSshDial;
import net.hugmesh.adminbff.sshterminal.DeviceSshDialRepository;
import net.hugmesh.adminbff.sshterminal.ImageBuild;
import net.hugmesh.adminbff.sshterminal.ImageBuildRepository;
import net.hugmesh.commons.web.ApiException;
import net.hugmesh.adminbff.web.StepUpRequiredException;
import net.hugmesh.adminbff.web.dto.BatchImageSpec;
import net.hugmesh.adminbff.web.dto.BatchTriggerImageBuildRequest;
import net.hugmesh.adminbff.web.dto.ImageBuildIngestRequest;
import net.hugmesh.adminbff.web.dto.ImageBuildProgressRequest;
import net.hugmesh.adminbff.web.dto.MeshManifest;
import net.hugmesh.adminbff.web.dto.TriggerImageBuildRequest;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Image-generation application service (reactive). Owns the rules the controller must not
 * duplicate — the fail-closed AUTHZ being the security-critical core:
 *
 * <ul>
 *   <li><b>Own-domain wall.</b> The build {@code domain} is ALWAYS derived from the caller's
 *       CRYPTOGRAPHICALLY-VALIDATED issuer (never a client field). A non-SUPERADMIN ADMIN may
 *       only build for a {@code targetUser} in their OWN domain: if {@code targetUser} carries
 *       an explicit org qualifier ({@code <org>/<name>}, the Casdoor subject shape) that does
 *       not equal the caller's issuer-derived domain, the trigger is DENIED (403). A SUPERADMIN
 *       may build cross-domain (the qualifier, when present, selects the target brand).</li>
 *   <li><b>Role floor.</b> Only ADMIN / SUPERADMIN reach the trigger (also enforced by the
 *       route rule + {@code @PreAuthorize}); a principal that is neither is denied here too.</li>
 *   <li><b>Step-up.</b> The trigger and the keys-download require a valid step-up token (the
 *       controller presents it; this service validates via {@link ImageGenStepUpGate}).</li>
 *   <li><b>Keys fail-closed.</b> A keys download is refused unless the build's
 *       {@code ssh_keys_allowed} is true AND a {@code keys_ref} exists.</li>
 * </ul>
 *
 * <p>SECURITY: a private dial key never flows through this service. The ingest path persists
 * ONLY non-secret rows (device_registry identity + device_ssh_dial fingerprints / public keys /
 * Vault POINTERS); the artifact download streams build-artifacts files by contained path.
 */
@Service
public class ImageBuildService {

    private static final Logger log = LoggerFactory.getLogger(ImageBuildService.class);

    private final ImageBuildRepository builds;
    private final DeviceSshDialRepository dials;
    private final DeviceRegistryRepository devices;
    private final ImageBuildOrchestrator orchestrator;
    private final ImageArtifactStore artifacts;
    private final ImageGenStepUpGate stepUp;
    private final MfaStepUpService mfaStepUp;
    private final DomainRegistry domainRegistry;
    private final WorklistEnvelopeValidator envelopeValidator;
    private final ImageGenConfig imageGenConfig;

    public ImageBuildService(ImageBuildRepository builds,
                             DeviceSshDialRepository dials,
                             DeviceRegistryRepository devices,
                             ImageBuildOrchestrator orchestrator,
                             ImageArtifactStore artifacts,
                             ImageGenStepUpGate stepUp,
                             MfaStepUpService mfaStepUp,
                             DomainRegistry domainRegistry,
                             WorklistEnvelopeValidator envelopeValidator,
                             ImageGenConfig imageGenConfig) {
        this.builds = builds;
        this.dials = dials;
        this.devices = devices;
        this.orchestrator = orchestrator;
        this.artifacts = artifacts;
        this.stepUp = stepUp;
        this.mfaStepUp = mfaStepUp;
        this.domainRegistry = domainRegistry;
        this.envelopeValidator = envelopeValidator;
        this.imageGenConfig = imageGenConfig;
    }

    public boolean launchIsReal() {
        return orchestrator.launchIsReal();
    }

    /**
     * Newest-first build history (admin console list), TENANT-SCOPED on the own-domain wall:
     * a non-superadmin admin sees ONLY their own validated-issuer domain's builds; a superadmin
     * sees every brand's. Fail-CLOSED — a non-superadmin whose domain cannot be resolved sees
     * nothing (never the global list). Closes the cross-tenant IDOR where the unscoped
     * {@code listRecent} leaked every brand's build inventory (operator/target identities,
     * device bindings, artifact pointers) to any tenant admin.
     */
    public Flux<ImageBuild> history(Authentication auth, int limit) {
        Jwt jwt = jwtOf(auth);
        if (jwt != null && Roles.isSuperadmin(jwt)) {
            return builds.listRecent(limit);
        }
        String callerDomain = jwt == null ? null : Roles.domainOf(jwt, domainRegistry);
        if (callerDomain == null) {
            return Flux.empty();
        }
        return builds.listRecentForDomain(callerDomain, limit);
    }

    /**
     * One build's row, TENANT-SCOPED: a non-superadmin may read only a build in their own
     * validated-issuer domain — a cross-domain id yields 404 (never leak another brand's
     * build existence), exactly like the image/keys download paths. 404 when absent.
     */
    public Mono<ImageBuild> detail(Authentication auth, String id) {
        return scopedBuild(auth, id);
    }

    /**
     * Trigger a build. Enforces the role floor + the own-domain wall + step-up, persists the
     * QUEUED row stamped with the issuer-derived domain, then hands it to the orchestrator
     * (which is a no-op/dark launcher unless imagegen.launch.enabled=true).
     */
    public Mono<ImageBuild> trigger(Authentication auth, TriggerImageBuildRequest req,
                                    String stepUpToken, String sessionToken) {
        Jwt jwt = jwtOf(auth);
        if (jwt == null) {
            return Mono.error(ApiException.unauthorized("authentication required"));
        }
        boolean superadmin = Roles.isSuperadmin(jwt);
        boolean admin = Roles.isAdmin(jwt);
        if (!superadmin && !admin) {
            return Mono.error(ApiException.forbidden("image build requires ADMIN or SUPERADMIN"));
        }

        String subject = jwt.getSubject();
        String callerDomain = Roles.domainOf(jwt, domainRegistry);
        if (callerDomain == null || callerDomain.isBlank()) {
            // unknown issuer in multi-brand mode — fail closed (the decoder would already 401).
            return Mono.error(ApiException.forbidden("no resolvable tenant for this token"));
        }

        // Own-domain wall. The build domain is ALWAYS server-derived. A non-superadmin may
        // only build for a target user in their OWN domain.
        final String buildDomain;
        String qualifier = orgQualifier(req.targetUser());
        if (superadmin) {
            // superadmin may build cross-domain: an explicit qualifier selects the target brand,
            // otherwise the superadmin's home domain is used.
            buildDomain = qualifier != null ? qualifier : callerDomain;
        } else {
            if (qualifier != null && !qualifier.equals(callerDomain)) {
                log.warn("[imagegen] DENY cross-domain trigger by {} (caller domain {}, target qualifier {})",
                        subject, callerDomain, qualifier);
                return Mono.error(ApiException.forbidden(
                        "an admin may only build for a target user in their own domain"));
            }
            buildDomain = callerDomain;
        }

        // A5 UNIFIED step-up (ADMIN-scoped widening — flagged for security review in
        // ImageGenStepUpGate): the workload step-up token OR a FRESH Casdoor-MFA stamp on the
        // caller's opaque session. The MFA leg satisfies ONLY the step-up re-confirmation; the
        // own-domain wall above is enforced regardless, so a fresh MFA stamp never widens which
        // domain an admin may build for. mfaStepUp.isFresh() is flag-gated + fail-closed
        // (app.casdoor.mfa.enabled=false by default -> only the token leg works). When the MFA
        // leg satisfied, the freshness is consumed single-use so a second privileged trigger
        // needs a fresh MFA challenge. Mirrors BackupAdminController#restore.
        // Check step-up (token OR fresh MFA), consume MFA single-use, then insert and launch.
        return mfaStepUp.isFresh(sessionToken)
                .flatMap(mfaFresh -> launchBuildIfStepUpSatisfied(
                        mfaFresh, subject, stepUpToken, sessionToken, req, buildDomain));
    }

    /** The result of a worklist batch trigger: a correlation id + the N persisted QUEUED rows. */
    public record BatchResult(String batchId, List<ImageBuild> builds) { }

    /**
     * Trigger a WORKLIST BATCH (worklist redesign item 1). The wire input is the frozen worklist
     * v1 ENVELOPE ({@code {schema, base, entries}}). This mirrors {@link #trigger} but for up to
     * {@value BatchTriggerImageBuildRequest#MAX_ENTRIES} images, with the security invariants of a
     * bounded batch:
     *
     * <ul>
     *   <li><b>FAIL-CLOSED spec-injection gate FIRST.</b> The whole envelope is validated by
     *       {@link WorklistEnvelopeValidator} (no SECRET_FIELDS, valid platforms/atoms/domain
     *       names) BEFORE any authz-content read or write — the {@code image_spec_json} it persists
     *       bypasses the renderManifest {@code yamlSafe} scalar guard, so this is where it is fenced.</li>
     *   <li><b>Hard N&le;16 re-assert.</b> ONE step-up authorizes up to 16 real device images —
     *       re-checked here, not just at the DTO {@code @Size}.</li>
     *   <li><b>Own-domain wall, TWICE.</b> Per-entry on {@code targetUser} (as {@link #trigger}),
     *       AND on manifest CONTENT ({@code base.domains[].name} / {@code base.users[].domain} /
     *       {@code superdomain}) for a non-superadmin — the cross-tenant escalation seam items 4 &amp; 6
     *       flagged. The build domain is ALWAYS server-derived; tenancy is never a body field.</li>
     *   <li><b>Superdomain (item 5).</b> Server-derived {@code <brand>.<suffix>} unless a SUPERADMIN
     *       supplied an in-brand override — NON_ARGV, carried only on the assembled mesh manifest.</li>
     *   <li><b>ONE MFA consume for the whole batch.</b> Step-up is validated once and
     *       {@code mfaStepUp.consume()} runs EXACTLY once (contrast the per-build consume of the
     *       single trigger) — one fresh MFA stamp authorizes the bounded batch.</li>
     *   <li><b>Bounded launch.</b> N QUEUED rows persist, then launch with {@code maxConcurrent}
     *       concurrency (default 1 = sequential). Real k8s apply stays behind the Noop/dark seam.</li>
     * </ul>
     */
    public Mono<BatchResult> triggerBatch(Authentication auth, BatchTriggerImageBuildRequest req,
                                          String stepUpToken, String sessionToken) {
        Jwt jwt = jwtOf(auth);
        if (jwt == null) {
            return Mono.error(ApiException.unauthorized("authentication required"));
        }
        boolean superadmin = Roles.isSuperadmin(jwt);
        boolean admin = Roles.isAdmin(jwt);
        if (!superadmin && !admin) {
            return Mono.error(ApiException.forbidden("image build requires ADMIN or SUPERADMIN"));
        }
        String subject = jwt.getSubject();
        String callerDomain = Roles.domainOf(jwt, domainRegistry);
        if (callerDomain == null || callerDomain.isBlank()) {
            return Mono.error(ApiException.forbidden("no resolvable tenant for this token"));
        }

        final List<ImageBuild> queuedRows;
        final MeshManifest manifest;
        try {
            // 1) FAIL-CLOSED spec-injection gate — BEFORE any content read / persist / launch.
            envelopeValidator.validate(req);
            List<BatchImageSpec> entries = req.entries();
            // 2) HARD N<=16 re-assert (defence beyond the DTO @Size + the validator).
            if (entries.size() > BatchTriggerImageBuildRequest.MAX_ENTRIES) {
                throw ApiException.forbidden(
                        "a batch may build at most " + BatchTriggerImageBuildRequest.MAX_ENTRIES + " images");
            }
            // 3) Own-domain wall on manifest CONTENT (items 4 & 6) — a non-superadmin may reference
            //    only their own brand's domains/users; the cross-tenant steps (cross-brand content,
            //    superdomain override) are SUPERADMIN-only INSIDE the wizard.
            if (!superadmin) {
                assertContentWithinBrand(req.base(), callerDomain, subject);
            }
            // 4) Per-entry own-domain wall on targetUser + build the SERVER-derived QUEUED rows.
            queuedRows = new ArrayList<>();
            for (BatchImageSpec e : entries) {
                String buildDomain = resolveBuildDomain(superadmin, callerDomain, subject, e.targetUser());
                queuedRows.add(new ImageBuild(
                        null, null, subject, e.targetUser(), buildDomain,
                        e.imageType(), e.hardwareClass(), null,
                        ImageBuild.STATUS_QUEUED, e.sshKeysAllowedOrFalse(),
                        null, null, null, null, null, null, e.imageSpecJson()));
            }
            // 5) Server-derived mesh manifest (item 6) + superdomain (item 5). Assembled here so the
            //    own-domain-walled content + server brand/org/superdomain are pinned. Its real
            //    Casdoor-seed / KEYS MagicDNS delivery is STRUCTURAL/deferred (mesh/live), but the
            //    assembly + the own-domain wall it depends on are fully unit-verifiable.
            String brand = callerDomain;
            String superdomain = effectiveSuperdomain(superadmin, brand, req.base());
            manifest = MeshManifest.from(req.base(), entries, brand,
                    brandTitle(req.base(), brand), brand, clusterDomain(req.base()), superdomain);
        } catch (RuntimeException e) {
            return Mono.error(e);
        }

        // Structural: the real per-batch ConfigMap / Casdoor seeder delivery of the manifest is
        // deferred (mesh/live). Assembled + logged here; nothing is faked.
        log.info("[imagegen] batch mesh manifest assembled for brand {} (superdomain {}, {} domains, "
                        + "{} users, {} images) — Casdoor-seed delivery deferred (structural)",
                manifest.brand(), manifest.superdomain(), manifest.domains().size(),
                manifest.users().size(), manifest.images().size());

        String batchId = UUID.randomUUID().toString();
        int maxConcurrent = req.maxConcurrentOrDefault();

        // 6) ONE step-up authorizes the WHOLE batch; consume the MFA freshness EXACTLY ONCE
        //    (contrast the per-build consume of the single trigger). Then persist N QUEUED rows and
        //    launch with bounded concurrency (Noop/dark unless imagegen.launch.enabled=true).
        return mfaStepUp.isFresh(sessionToken).flatMap(mfaFresh -> {
            if (!stepUp.isSatisfied(subject, stepUpToken, mfaFresh)) {
                return Mono.error(StepUpRequiredException.forRetryHeader(
                        ImageGenStepUpGate.STEP_UP_HEADER, "image build"));
            }
            Mono<Void> consume = mfaFresh ? mfaStepUp.consume(sessionToken) : Mono.empty();
            return consume
                    .thenMany(Flux.fromIterable(queuedRows).concatMap(builds::insert))
                    .collectList()
                    .flatMap(inserted -> launchAll(inserted, maxConcurrent)
                            .thenReturn(new BatchResult(batchId, inserted)));
        });
    }

    /**
     * Emit a NON-TERMINAL progress event for a running build (worklist redesign item 8). The
     * in-cluster Job POSTs 0..N of these before the single terminal {@link #ingest}. No AUTHZ here
     * — this is the internal (mTLS + internal-token) ingest surface, same boundary as {@link #ingest}.
     * Never closes the sink; never stamps {@code finished_at}.
     *
     * <p>Maps the worker's phaseIndex/phaseCount/phaseLabel/percent(nullable) wire shape (see
     * {@link ImageBuildProgressRequest}) onto the orchestrator's existing
     * {@code (percent:int, phase:String, message:String)} SSE contract: a {@code null}
     * (INDETERMINATE) percent becomes the honest lower bound {@code 0} (never fabricated, and
     * consistent with the {@code launch()}-time initial frame already emitted at 0), and
     * {@code phaseLabel} (falling back to {@link ImageBuildEvent#PHASE_RUNNING} before the first
     * banner, when the label is still {@code ""}) drives the SSE {@code phase} field. The
     * {@code message} passed to the orchestrator is a short "phase i/N: label" aria-live string
     * once a phase is known, else just the fallback label.
     */
    public Mono<Void> progress(String buildId, ImageBuildProgressRequest req) {
        int percent = req.percent() == null ? 0 : req.percent();
        String label = (req.phaseLabel() == null || req.phaseLabel().isBlank())
                ? ImageBuildEvent.PHASE_RUNNING : req.phaseLabel();
        String message = req.phaseCount() > 0 && req.phaseIndex() >= 0
                ? "phase " + (req.phaseIndex() + 1) + "/" + req.phaseCount() + ": " + label
                : label;
        return orchestrator.progress(buildId, percent, label, message);
    }

    /**
     * The live SSE event stream for a build, TENANT-SCOPED: a non-superadmin may subscribe
     * only to a build in their own validated-issuer domain (cross-domain id → 404, no
     * existence leak), then the orchestrator's progress stream is attached.
     */
    public Flux<ImageBuildEvent> events(Authentication auth, String buildId) {
        return scopedBuild(auth, buildId).flatMapMany(b -> orchestrator.events(buildId));
    }

    /**
     * Resolve a build for the IMAGE download, scoping a non-superadmin to their own domain
     * (404 — never leak existence of another brand's build), then stream the image artifact.
     */
    public Flux<DataBuffer> downloadImage(Authentication auth, String buildId) {
        return scopedBuild(auth, buildId)
                .flatMapMany(b -> artifacts.stream(b.imageRef()));
    }

    /**
     * Resolve a build for the KEYS download. Fail-closed: refused unless ssh_keys_allowed AND a
     * keys_ref exists, AND a valid step-up token is presented (ADMIN-scoped widening — flagged).
     * Own-domain scoped exactly like the image download.
     */
    public Flux<DataBuffer> downloadKeys(Authentication auth, String buildId, String stepUpToken,
                                         String sessionToken) {
        Jwt jwt = jwtOf(auth);
        String subject = jwt == null ? null : jwt.getSubject();
        // A5 UNIFIED step-up: the workload step-up token OR a FRESH Casdoor-MFA stamp (co-equal,
        // license-INDEPENDENT). The keys fail-closed gates (ssh_keys_allowed + keys_ref) and the
        // own-domain scoping below are enforced regardless — the MFA leg only satisfies the
        // step-up re-confirmation. Flag-gated + fail-closed via mfaStepUp.isFresh().
        // Check step-up, consume MFA single-use, then scope the build and stream keys.
        return mfaStepUp.isFresh(sessionToken)
                .flatMapMany(mfaFresh -> streamKeysIfStepUpSatisfied(
                        mfaFresh, subject, stepUpToken, sessionToken, auth, buildId));
    }

    /**
     * Ingest the terminal report the IN-CLUSTER Job POSTs. NON-SECRET ONLY: persists the
     * device_registry identity + device_ssh_dial fingerprints/public-keys/Vault-pointer rows
     * (when supplied), records the (non-secret) artifact pointers + terminal status, and fans
     * the SSE event. NEVER accepts or persists a private key — the DTO has no such field and
     * this method reads none.
     */
    public Mono<ImageBuild> ingest(String buildId, ImageBuildIngestRequest in) {
        return builds.findById(buildId)
                .switchIfEmpty(Mono.error(ApiException.notFound("image build '" + buildId + "' not found")))
                .flatMap(b -> {
                    // TERMINAL-INGEST IDEMPOTENCY (worklist redesign item 8): once a build reached a
                    // terminal state (its sink already closed by the first terminal ingest), a SECOND
                    // terminal POST is a 200 no-op — it must NOT re-stamp finished_at, re-seed the
                    // dial registry, or re-fan a terminal SSE event onto a completed sink. Mirrors
                    // GoLiveInternalController's idempotent applied-ack CAS. 0..N non-terminal
                    // /progress posts still precede the single terminal /ingest that closes.
                    if (isTerminal(b.status())) {
                        log.info("[imagegen] terminal ingest for build {} ignored — already {} (idempotent no-op)",
                                buildId, b.status());
                        return Mono.just(b);
                    }
                    return seedNonSecretRegistry(buildId, b, in)
                            // record the non-secret artifact pointers on the build row first
                            .then(builds.recordArtifacts(buildId, in.imageRef(), in.keysRef(), in.error()))
                            .then(orchestrator.ingest(buildId, in.status(), in.imageRef(), in.keysRef(),
                                    in.message(), in.error()));
                });
    }

    /** Validate step-up then consume MFA single-use and insert + launch the queued build. */
    private Mono<ImageBuild> launchBuildIfStepUpSatisfied(boolean mfaFresh, String subject,
                                                           String stepUpToken, String sessionToken,
                                                           TriggerImageBuildRequest req,
                                                           String buildDomain) {
        if (!stepUp.isSatisfied(subject, stepUpToken, mfaFresh)) {
            return Mono.error(StepUpRequiredException.forRetryHeader(
                    ImageGenStepUpGate.STEP_UP_HEADER, "image build"));
        }
        ImageBuild queued = new ImageBuild(
                null, null, subject, req.targetUser(), buildDomain,
                req.imageType(), blankToNull(req.hardwareClass()), null,
                ImageBuild.STATUS_QUEUED, req.sshKeysAllowedOrFalse(),
                null, null, null, null, null, null);
        Mono<Void> consume = mfaFresh ? mfaStepUp.consume(sessionToken) : Mono.empty();
        return consume.then(builds.insert(queued))
                .flatMap(b -> orchestrator.launch(b).thenReturn(b));
    }

    /** Validate step-up then consume MFA single-use, resolve the build, and stream its keys. */
    private Flux<DataBuffer> streamKeysIfStepUpSatisfied(boolean mfaFresh, String subject,
                                                          String stepUpToken, String sessionToken,
                                                          Authentication auth, String buildId) {
        if (!stepUp.isSatisfied(subject, stepUpToken, mfaFresh)) {
            return Flux.error(StepUpRequiredException.forRetryHeader(
                    ImageGenStepUpGate.STEP_UP_HEADER, "keys download"));
        }
        Mono<Void> consume = mfaFresh ? mfaStepUp.consume(sessionToken) : Mono.empty();
        return consume.thenMany(scopedBuild(auth, buildId).flatMapMany(this::streamKeys));
    }

    /** Gate the keys download on the build's ssh_keys_allowed flag and keysRef presence. */
    private Flux<DataBuffer> streamKeys(ImageBuild b) {
        if (!b.sshKeysAllowed()) {
            return Flux.error(ApiException.forbidden("ssh keys were not enabled for this build"));
        }
        if (b.keysRef() == null || b.keysRef().isBlank()) {
            return Flux.error(ApiException.notFound("no keys bundle is stored for this build"));
        }
        return artifacts.stream(b.keysRef());
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    /**
     * Seed (idempotently) the NON-SECRET {@code device_ssh_dial} row the in-cluster build
     * reported, when the build COMPLETED and the device + dial public material was supplied. This
     * writes ONLY non-secret columns — the device's PUBLIC host key, the dial PUBLIC-key
     * fingerprint, and the Vault/Secret POINTERS — NEVER a private key (there is no field for
     * one). Device enrollment itself (the {@code device_registry} row, which needs a mesh id +
     * machine-key) remains the headscale enrollment flow's job; the ingest only attaches the
     * dial pointer to that device once it exists. Best-effort: a benign seed failure (e.g. a
     * duplicate, or the device not yet enrolled) does not fail the ingest — the terminal status
     * still lands.
     *
     * <p><b>TENANT CROSS-CHECK (fail-closed, defence-in-depth).</b> The {@code deviceId} is taken
     * from the ingest BODY, and the ingest boundary is the in-cluster Job (mTLS + internal token).
     * Should that boundary ever be defeated, a forged ingest must NOT be able to attach a dial
     * pointer to ANOTHER tenant's device row. So BEFORE seeding we assert the build's domain — the
     * SERVER-DERIVED domain stamped on the image_build row from the validated issuer, NEVER a
     * client field — equals the TARGET device's residency domain (read from its device_registry
     * row). On mismatch we REFUSE outright: no dial row, no device row, a generic non-leaky error
     * that propagates (this is a security-boundary breach, not a benign skip, so it is NOT swept
     * up by the best-effort resume below). The domain is never trusted from the ingest body.
     */
    private Mono<Void> seedNonSecretRegistry(String buildId, ImageBuild build, ImageBuildIngestRequest in) {
        if (!in.isCompleted() || in.deviceId() == null
                || in.dialUser() == null || in.dialPubFp() == null) {
            return Mono.empty();
        }
        return devices.findById(in.deviceId())
                .flatMap(device -> {
                    if (build.domain() == null || !build.domain().equals(device.domain())) {
                        // Cross-tenant attach attempt — fail closed. Do NOT leak the device's brand.
                        log.warn("[imagegen] DENY cross-tenant dial seed for build {} (build domain {}, "
                                + "target device residency differs)", buildId, build.domain());
                        return Mono.<Void>error(ApiException.forbidden(
                                "ingest device does not belong to this build's tenant"));
                    }
                    return seedDial(buildId, in);
                });
        // NB: when the device is not yet enrolled (no registry row) findById is empty and the
        // switchIfEmpty-less chain completes empty — the dial seed is simply skipped, exactly as
        // before. We can only attach a dial to a device whose residency we can verify.
    }

    /** The (idempotent, best-effort) NON-SECRET dial insert — only reached after the tenant
     *  cross-check has confirmed the target device is resident in the build's domain. */
    private Mono<Void> seedDial(String buildId, ImageBuildIngestRequest in) {
        DeviceSshDial dial = new DeviceSshDial(
                null, in.deviceId(), in.dialUser(),
                blankToNull(in.hostKeyPub()), blankToNull(in.hostKeyFp()),
                in.dialPubFp(), blankToNull(in.vaultRef()), blankToNull(in.k8sSecretName()),
                buildId, DeviceSshDial.STATUS_PENDING, 1L, null, null);
        return dials.findByDeviceId(in.deviceId())
                .flatMap(existing -> Mono.<DeviceSshDial>empty())   // already present -> skip
                .switchIfEmpty(dials.insert(dial))
                .then()
                .onErrorResume(e -> {
                    log.warn("[imagegen] non-secret dial seed for build {} skipped: {}",
                            buildId, e.toString());
                    return Mono.empty();
                });
    }

    /** Resolve a build, scoping a non-superadmin to their own validated-issuer domain (404 on a
     *  cross-domain id — no existence leak). */
    private Mono<ImageBuild> scopedBuild(Authentication auth, String buildId) {
        Jwt jwt = jwtOf(auth);
        boolean superadmin = jwt != null && Roles.isSuperadmin(jwt);
        String callerDomain = jwt == null ? null : Roles.domainOf(jwt, domainRegistry);
        return builds.findById(buildId)
                .switchIfEmpty(Mono.error(ApiException.notFound("image build '" + buildId + "' not found")))
                .flatMap(b -> {
                    if (!superadmin && (callerDomain == null || !callerDomain.equals(b.domain()))) {
                        return Mono.error(ApiException.notFound("image build '" + buildId + "' not found"));
                    }
                    return Mono.just(b);
                });
    }

    private static Jwt jwtOf(Authentication auth) {
        if (auth != null && auth.getPrincipal() instanceof Jwt jwt) {
            return jwt;
        }
        return null;
    }

    /** Whether a build is in a terminal lifecycle state (its SSE sink is closed). */
    private static boolean isTerminal(String status) {
        return ImageBuild.STATUS_COMPLETED.equals(status)
                || ImageBuild.STATUS_FAILED.equals(status)
                || ImageBuild.STATUS_ERROR.equals(status);
    }

    /**
     * The SERVER-derived build domain for one batch entry — identical own-domain wall to
     * {@link #trigger}: a non-superadmin whose {@code targetUser} carries a foreign org qualifier
     * is DENIED (403, throws); a superadmin's qualifier selects the target brand.
     */
    private String resolveBuildDomain(boolean superadmin, String callerDomain, String subject,
                                      String targetUser) {
        String qualifier = orgQualifier(targetUser);
        if (superadmin) {
            return qualifier != null ? qualifier : callerDomain;
        }
        if (qualifier != null && !qualifier.equals(callerDomain)) {
            log.warn("[imagegen] DENY cross-domain batch entry by {} (caller domain {}, target qualifier {})",
                    subject, callerDomain, qualifier);
            throw ApiException.forbidden(
                    "an admin may only build for a target user in their own domain");
        }
        return callerDomain;
    }

    /**
     * Own-domain wall on manifest CONTENT (items 4 &amp; 6): a NON-superadmin may reference ONLY
     * their own brand's {@code base.domains[].name}, {@code base.users[].domain}, and (if set)
     * {@code superdomain}. A referenced domain "belongs" to the brand iff the brand is one of its
     * dot-separated labels (e.g. {@code brandx}, {@code brandx.example}, {@code app.brandx.internal}
     * all belong to {@code brandx}; {@code brandy.example} does not). Throws 403 on the first
     * cross-tenant reference — closing the escalation seam where the pre-batch wall checked only
     * {@code targetUser}. (A SUPERADMIN skips this — they may compose cross-brand meshes.)
     */
    private void assertContentWithinBrand(JsonNode base, String brand, String subject) {
        if (base == null || !base.isObject()) {
            return;
        }
        JsonNode domains = base.get("domains");
        if (domains != null && domains.isArray()) {
            for (JsonNode d : domains) {
                JsonNode name = d.get("name");
                if (name != null && name.isTextual() && !name.asText().isBlank()
                        && !belongsToBrand(name.asText(), brand)) {
                    log.warn("[imagegen] DENY cross-tenant batch content by {}: domain '{}' outside brand '{}'",
                            subject, name.asText(), brand);
                    throw ApiException.forbidden(
                            "a non-superadmin may only reference their own brand's domains");
                }
            }
        }
        JsonNode users = base.get("users");
        if (users != null && users.isArray()) {
            for (JsonNode u : users) {
                JsonNode dom = u.get("domain");
                if (dom != null && dom.isTextual() && !dom.asText().isBlank()
                        && !belongsToBrand(dom.asText(), brand)) {
                    log.warn("[imagegen] DENY cross-tenant batch content by {}: user domain '{}' outside brand '{}'",
                            subject, dom.asText(), brand);
                    throw ApiException.forbidden(
                            "a non-superadmin may only reference their own brand's user domains");
                }
            }
        }
        JsonNode sd = base.get("superdomain");
        if (sd != null && sd.isTextual() && !sd.asText().isBlank()
                && !belongsToBrand(sd.asText(), brand)) {
            log.warn("[imagegen] DENY cross-tenant superdomain by {}: '{}' outside brand '{}'",
                    subject, sd.asText(), brand);
            throw ApiException.forbidden(
                    "a non-superadmin may not set a cross-brand superdomain");
        }
    }

    /** True iff {@code brand} is one of the dot-separated labels of {@code name} (or equals it). */
    private static boolean belongsToBrand(String name, String brand) {
        if (name == null || brand == null) {
            return false;
        }
        String n = name.trim().toLowerCase();
        String b = brand.trim().toLowerCase();
        if (b.isEmpty()) {
            return false;
        }
        if (n.equals(b)) {
            return true;
        }
        for (String label : n.split("\\.")) {
            if (label.equals(b)) {
                return true;
            }
        }
        return false;
    }

    /**
     * The effective mesh superdomain (item 5): a SUPERADMIN's non-blank in-brand {@code superdomain}
     * override is honoured; everyone else gets the SERVER-derived {@code <brand>.<suffix>} — byte-for-
     * byte with the generator's {@code effective_superdomain} (default {@code <brand>.internal}).
     * NON_ARGV: carried only on the mesh manifest, never a Job env / builder flag.
     */
    private String effectiveSuperdomain(boolean superadmin, String brand, JsonNode base) {
        JsonNode sd = base == null ? null : base.get("superdomain");
        String override = (sd != null && sd.isTextual()) ? sd.asText().trim() : "";
        if (superadmin && !override.isBlank()) {
            return override;
        }
        return brand + "." + imageGenConfig.superdomainSuffix();
    }

    /** The cosmetic brand title from the worklist base CONTENT, or the brand as a fallback. */
    private static String brandTitle(JsonNode base, String fallback) {
        if (base != null) {
            JsonNode t = base.get("brand_title");
            if (t != null && t.isTextual() && !t.asText().isBlank()) {
                return t.asText();
            }
        }
        return fallback;
    }

    /** The cluster domain from the worklist base CONTENT (advisory on the mesh manifest seed). */
    private static String clusterDomain(JsonNode base) {
        if (base != null) {
            JsonNode c = base.get("cluster_domain");
            if (c != null && c.isTextual()) {
                return c.asText();
            }
        }
        return "";
    }

    /** Persist-then-launch fan-out with bounded concurrency: {@code maxConcurrent==1} launches the
     *  inserted builds sequentially (concatMap), otherwise up to {@code maxConcurrent} at once. Each
     *  launch is fail-closed inside the orchestrator (a failed launch ERRORs that build, not the batch). */
    private Mono<Void> launchAll(List<ImageBuild> inserted, int maxConcurrent) {
        if (maxConcurrent <= 1) {
            return Flux.fromIterable(inserted).concatMap(orchestrator::launch).then();
        }
        return Flux.fromIterable(inserted).flatMap(orchestrator::launch, maxConcurrent).then();
    }

    /** The org qualifier of a Casdoor subject of the form {@code <org>/<name>}, or null when the
     *  subject carries no explicit org. The org is the brand discriminator. */
    private static String orgQualifier(String targetUser) {
        if (targetUser == null) return null;
        int slash = targetUser.indexOf('/');
        if (slash <= 0) return null;
        String org = targetUser.substring(0, slash).trim().toLowerCase();
        return org.isEmpty() ? null : org;
    }

    private static String blankToNull(String s) {
        return (s == null || s.isBlank()) ? null : s;
    }
}
