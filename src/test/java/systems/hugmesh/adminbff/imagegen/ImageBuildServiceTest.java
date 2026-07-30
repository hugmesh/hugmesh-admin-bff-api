package systems.hugmesh.adminbff.imagegen;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import systems.hugmesh.adminbff.device.DeviceRegistryRepository;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.adminbff.sshterminal.DeviceSshDialRepository;
import systems.hugmesh.adminbff.sshterminal.ImageBuild;
import systems.hugmesh.adminbff.sshterminal.ImageBuildRepository;
import systems.hugmesh.commons.web.ApiException;
import systems.hugmesh.adminbff.web.dto.BatchImageSpec;
import systems.hugmesh.adminbff.web.dto.BatchTriggerImageBuildRequest;
import systems.hugmesh.adminbff.web.dto.ImageBuildIngestRequest;
import systems.hugmesh.adminbff.web.dto.TriggerImageBuildRequest;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.mockito.ArgumentCaptor;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The SECURITY-CRITICAL behaviour of the image-gen service — the fail-closed AUTHZ that the
 * mocked-service controller test cannot exercise:
 * <ul>
 *   <li>non-admin → DENIED;</li>
 *   <li>cross-domain ADMIN trigger (target user's org qualifier != caller's issuer-derived
 *       domain) → DENIED; the build is NEVER persisted;</li>
 *   <li>SUPERADMIN cross-domain trigger → ALLOWED, build stamped with the TARGET domain;</li>
 *   <li>an ADMIN's OWN-domain trigger → ALLOWED, build stamped with the caller's domain
 *       (never a client field);</li>
 *   <li>step-up missing/invalid → DENIED (trigger and keys);</li>
 *   <li>keys download with ssh_keys_allowed=false → DENIED.</li>
 * </ul>
 */
class ImageBuildServiceTest {

    private static final String BRANDX_ISSUER = "https://idp.brandx.example";
    private static final String BRANDY_ISSUER = "https://idp.brandy.example";

    private ImageBuildRepository builds;
    private DeviceSshDialRepository dials;
    private DeviceRegistryRepository devices;
    private ImageBuildOrchestrator orchestrator;
    private ImageArtifactStore artifacts;
    private ImageGenStepUpGate stepUp;
    private systems.hugmesh.authcore.casdoor.MfaStepUpService mfaStepUp;
    private DomainRegistry registry;
    private ImageBuildService service;

    @BeforeEach
    void setUp() {
        builds = mock(ImageBuildRepository.class);
        dials = mock(DeviceSshDialRepository.class);
        devices = mock(DeviceRegistryRepository.class);
        orchestrator = mock(ImageBuildOrchestrator.class);
        artifacts = mock(ImageArtifactStore.class);
        stepUp = mock(ImageGenStepUpGate.class);
        mfaStepUp = mock(systems.hugmesh.authcore.casdoor.MfaStepUpService.class);
        // two-brand registry: brandx + brandy are the trusted issuers/domains.
        registry = new DomainRegistry("",
                BRANDX_ISSUER + "=brandx," + BRANDY_ISSUER + "=brandy");
        service = new ImageBuildService(builds, dials, devices, orchestrator, artifacts, stepUp,
                mfaStepUp, registry, new WorklistEnvelopeValidator(), new ImageGenConfig());
        // A5 MFA leg ships DARK by default: no fresh stamp, nothing to consume — so ONLY the
        // workload step-up token leg satisfies (today's behaviour). The 3-arg unified gate then
        // delegates to the 2-arg token leg the individual tests stub.
        when(mfaStepUp.isFresh(any())).thenReturn(Mono.just(false));
        when(mfaStepUp.consume(any())).thenReturn(Mono.empty());
        when(stepUp.isSatisfied(anyString(), any(), anyBoolean()))
                .thenAnswer(inv -> inv.<Boolean>getArgument(2)
                        || stepUp.isSatisfied(inv.getArgument(0), inv.getArgument(1)));
        // step-up satisfied by default; specific tests override.
        when(stepUp.isSatisfied(anyString(), any())).thenReturn(true);
        // orchestrator.launch is a no-op success by default.
        when(orchestrator.launch(any())).thenReturn(Mono.empty());
        // insert echoes a persisted row with an id.
        when(builds.insert(any())).thenAnswer(inv -> {
            ImageBuild b = inv.getArgument(0);
            return Mono.just(new ImageBuild("new-id", Instant.now(), b.requestedBy(), b.targetUser(),
                    b.domain(), b.imageType(), b.hardwareClass(), b.deviceId(), b.status(),
                    b.sshKeysAllowed(), b.jobName(), b.imageRef(), b.keysRef(), null, null, null));
        });
    }

    private static JwtAuthenticationToken auth(String issuer, String subject, List<String> roles,
                                               String... springAuthorities) {
        Jwt jwt = Jwt.withTokenValue("t").header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                .subject(subject).issuer(issuer)
                .claim("roles", roles).build();
        var auths = new java.util.ArrayList<SimpleGrantedAuthority>();
        for (String a : springAuthorities) auths.add(new SimpleGrantedAuthority(a));
        return new JwtAuthenticationToken(jwt, auths);
    }

    private static JwtAuthenticationToken adminOf(String issuer, String subject) {
        return auth(issuer, subject, List.of("admin"), "ROLE_USER", "ROLE_ADMIN");
    }

    private static JwtAuthenticationToken superadmin(String subject) {
        return auth(BRANDX_ISSUER, subject, List.of("superadmin"), "ROLE_USER", "ROLE_SUPERADMIN");
    }

    private static TriggerImageBuildRequest req(String targetUser, boolean keys) {
        return new TriggerImageBuildRequest(targetUser, "primary", "rpi5", keys);
    }

    // ── role floor ───────────────────────────────────────────────────────
    @Test
    void trigger_nonAdmin_denied_andNotPersisted() {
        var user = auth(BRANDX_ISSUER, "joe", List.of("user"), "ROLE_USER");
        StepVerifier.create(service.trigger(user, req("brandx/joe", false), "tok", null))
                .expectErrorSatisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(403))
                .verify();
        verify(builds, never()).insert(any());
    }

    // ── own-domain wall ────────────────────────────────────────────────────
    @Test
    void trigger_adminCrossDomain_denied_andNotPersisted() {
        // brandx admin tries to build for a brandy-qualified target user.
        var admin = adminOf(BRANDX_ISSUER, "admin-x");
        StepVerifier.create(service.trigger(admin, req("brandy/victim", false), "tok", null))
                .expectErrorSatisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(403))
                .verify();
        verify(builds, never()).insert(any());
    }

    @Test
    void trigger_adminOwnDomain_allowed_stampedWithCallerDomain() {
        var admin = adminOf(BRANDX_ISSUER, "admin-x");
        StepVerifier.create(service.trigger(admin, req("brandx/alice", false), "tok", null))
                .assertNext(b -> {
                    assertThat(b.domain()).isEqualTo("brandx");          // server-derived, not client
                    assertThat(b.status()).isEqualTo(ImageBuild.STATUS_QUEUED);
                })
                .verifyComplete();
        verify(orchestrator).launch(any());
    }

    @Test
    void trigger_superadminCrossDomain_allowed_stampedWithTargetDomain() {
        StepVerifier.create(service.trigger(superadmin("root"), req("brandy/bob", false), "tok", null))
                .assertNext(b -> assertThat(b.domain()).isEqualTo("brandy"))
                .verifyComplete();
    }

    // ── step-up ──────────────────────────────────────────────────────────
    @Test
    void trigger_missingStepUp_denied() {
        when(stepUp.isSatisfied(anyString(), any())).thenReturn(false);
        var admin = adminOf(BRANDX_ISSUER, "admin-x");
        StepVerifier.create(service.trigger(admin, req("brandx/alice", false), null, null))
                .expectErrorSatisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(403))
                .verify();
        verify(builds, never()).insert(any());
    }

    // ── A5 co-equal MFA step-up leg (U1) ───────────────────────────────────
    // (a) DARK is the default in setUp() (isFresh -> false) — every test above proves the
    //     workload-token leg is byte-identical to today. (b)+(c) below prove the fresh-MFA leg.

    @Test
    void trigger_freshMfa_noWorkloadToken_allowed_andConsumedSingleUse() {
        // A FRESH MFA stamp on the opaque session satisfies step-up with NO workload token:
        // the 2-arg token leg is unsatisfied (null token), so only the MFA leg can carry it.
        when(stepUp.isSatisfied(anyString(), any())).thenReturn(false);
        when(mfaStepUp.isFresh(eq("sess-1"))).thenReturn(Mono.just(true));
        var admin = adminOf(BRANDX_ISSUER, "admin-x");
        StepVerifier.create(service.trigger(admin, req("brandx/alice", false), null, "sess-1"))
                .assertNext(b -> assertThat(b.domain()).isEqualTo("brandx"))
                .verifyComplete();
        verify(builds).insert(any());
        // single-use: the MFA freshness is consumed exactly once when it was the satisfier.
        verify(mfaStepUp).consume(eq("sess-1"));
    }

    @Test
    void trigger_freshMfa_doesNotBypassOwnDomainWall() {
        // The MFA leg satisfies the STEP-UP only — it must NOT widen which domain an admin may
        // build for. A brandx admin with a fresh MFA stamp targeting a brandy user is STILL 403,
        // and nothing is persisted/consumed (the own-domain wall runs before the step-up leg).
        when(stepUp.isSatisfied(anyString(), any())).thenReturn(false);
        when(mfaStepUp.isFresh(eq("sess-1"))).thenReturn(Mono.just(true));
        var admin = adminOf(BRANDX_ISSUER, "admin-x");
        StepVerifier.create(service.trigger(admin, req("brandy/victim", false), null, "sess-1"))
                .expectErrorSatisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(403))
                .verify();
        verify(builds, never()).insert(any());
        verify(mfaStepUp, never()).consume(anyString());
    }

    @Test
    void downloadKeys_freshMfa_noWorkloadToken_streams_andConsumedSingleUse() {
        when(stepUp.isSatisfied(anyString(), any())).thenReturn(false);
        when(mfaStepUp.isFresh(eq("sess-1"))).thenReturn(Mono.just(true));
        ImageBuild withKeys = new ImageBuild("b1", Instant.now(), "admin-x", "brandx/alice", "brandx",
                "primary", "rpi5", null, ImageBuild.STATUS_COMPLETED, true,
                "job", "build-b1/image.img", "build-b1/keys.tar.gz", null, null, null);
        when(builds.findById("b1")).thenReturn(Mono.just(withKeys));
        when(artifacts.stream("build-b1/keys.tar.gz"))
                .thenReturn(Flux.just(new org.springframework.core.io.buffer.DefaultDataBufferFactory()
                        .wrap("keys".getBytes())));
        var admin = adminOf(BRANDX_ISSUER, "admin-x");
        StepVerifier.create(service.downloadKeys(admin, "b1", null, "sess-1"))
                .expectNextCount(1)
                .verifyComplete();
        verify(mfaStepUp).consume(eq("sess-1"));
    }

    @Test
    void downloadKeys_freshMfa_doesNotBypassKeysFailClosed() {
        // The keys fail-closed gate (ssh_keys_allowed=false) is enforced REGARDLESS of a fresh MFA
        // stamp — the MFA leg only satisfies the step-up re-confirmation.
        when(stepUp.isSatisfied(anyString(), any())).thenReturn(false);
        when(mfaStepUp.isFresh(eq("sess-1"))).thenReturn(Mono.just(true));
        ImageBuild noKeys = new ImageBuild("b1", Instant.now(), "admin-x", "brandx/alice", "brandx",
                "primary", "rpi5", null, ImageBuild.STATUS_COMPLETED, false,
                "job", "build-b1/image.img", null, null, null, null);
        when(builds.findById("b1")).thenReturn(Mono.just(noKeys));
        var admin = adminOf(BRANDX_ISSUER, "admin-x");
        StepVerifier.create(service.downloadKeys(admin, "b1", null, "sess-1"))
                .expectErrorSatisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(403))
                .verify();
        verify(artifacts, never()).stream(anyString());
    }

    // ── keys download fail-closed ──────────────────────────────────────────
    @Test
    void keysDownload_whenNotAllowed_denied() {
        ImageBuild noKeys = new ImageBuild("b1", Instant.now(), "admin-x", "brandx/alice", "brandx",
                "primary", "rpi5", null, ImageBuild.STATUS_COMPLETED, false,
                "job", "build-b1/image.img", null, null, null, null);
        when(builds.findById("b1")).thenReturn(Mono.just(noKeys));
        var admin = adminOf(BRANDX_ISSUER, "admin-x");
        StepVerifier.create(service.downloadKeys(admin, "b1", "tok", null))
                .expectErrorSatisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(403))
                .verify();
        verify(artifacts, never()).stream(anyString());
    }

    @Test
    void keysDownload_missingStepUp_denied() {
        when(stepUp.isSatisfied(anyString(), any())).thenReturn(false);
        var admin = adminOf(BRANDX_ISSUER, "admin-x");
        StepVerifier.create(service.downloadKeys(admin, "b1", null, null))
                .expectErrorSatisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(403))
                .verify();
        verify(builds, never()).findById(anyString());
    }

    @Test
    void keysDownload_allowedWithRef_streams() {
        ImageBuild withKeys = new ImageBuild("b1", Instant.now(), "admin-x", "brandx/alice", "brandx",
                "primary", "rpi5", null, ImageBuild.STATUS_COMPLETED, true,
                "job", "build-b1/image.img", "build-b1/keys.tar.gz", null, null, null);
        when(builds.findById("b1")).thenReturn(Mono.just(withKeys));
        when(artifacts.stream("build-b1/keys.tar.gz"))
                .thenReturn(Flux.just(new org.springframework.core.io.buffer.DefaultDataBufferFactory()
                        .wrap("keys".getBytes())));
        var admin = adminOf(BRANDX_ISSUER, "admin-x");
        StepVerifier.create(service.downloadKeys(admin, "b1", "tok", null))
                .expectNextCount(1)
                .verifyComplete();
    }

    // ── image download own-domain scoping (no cross-domain existence leak) ──
    @Test
    void imageDownload_crossDomainAdmin_404NotLeaked() {
        ImageBuild brandyBuild = new ImageBuild("b1", Instant.now(), "admin-y", "brandy/bob", "brandy",
                "primary", "rpi5", null, ImageBuild.STATUS_COMPLETED, false,
                "job", "build-b1/image.img", null, null, null, null);
        when(builds.findById("b1")).thenReturn(Mono.just(brandyBuild));
        var admin = adminOf(BRANDX_ISSUER, "admin-x");
        StepVerifier.create(service.downloadImage(admin, "b1"))
                .expectErrorSatisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(404))
                .verify();
        verify(artifacts, never()).stream(anyString());
    }

    // ── history / detail / events own-domain scoping (cross-tenant IDOR fix) ──

    private static ImageBuild buildIn(String domain) {
        return new ImageBuild("b1", Instant.now(), "admin-" + domain, domain + "/u", domain,
                "primary", "rpi5", null, ImageBuild.STATUS_COMPLETED, false, "job", null, null,
                null, null, null);
    }

    @Test
    void history_nonSuperadminAdmin_scopedToOwnDomain_neverGlobalList() {
        ImageBuild mine = buildIn("brandx");
        when(builds.listRecentForDomain(eq("brandx"), anyInt())).thenReturn(Flux.just(mine));
        StepVerifier.create(service.history(adminOf(BRANDX_ISSUER, "admin-x"), 100))
                .expectNext(mine).verifyComplete();
        verify(builds, never()).listRecent(anyInt());   // the unscoped, cross-tenant list is never used
    }

    @Test
    void history_superadmin_seesAllDomainsViaUnscopedList() {
        ImageBuild any = buildIn("brandy");
        when(builds.listRecent(anyInt())).thenReturn(Flux.just(any));
        StepVerifier.create(service.history(superadmin("root"), 100))
                .expectNext(any).verifyComplete();
        verify(builds, never()).listRecentForDomain(anyString(), anyInt());
    }

    @Test
    void history_unresolvableDomainAdmin_failsClosed_empty() {
        // an admin whose issuer is not in the domain registry -> no domain -> sees NOTHING
        var admin = auth("https://idp.unknown.example", "x", List.of("admin"), "ROLE_USER", "ROLE_ADMIN");
        StepVerifier.create(service.history(admin, 100)).verifyComplete();   // empty, not the global list
        verify(builds, never()).listRecent(anyInt());
        verify(builds, never()).listRecentForDomain(anyString(), anyInt());
    }

    @Test
    void detail_crossDomainAdmin_404NotLeaked() {
        when(builds.findById("b1")).thenReturn(Mono.just(buildIn("brandy")));
        StepVerifier.create(service.detail(adminOf(BRANDX_ISSUER, "admin-x"), "b1"))
                .expectErrorSatisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(404))
                .verify();
    }

    @Test
    void detail_ownDomainAdmin_returnsBuild() {
        ImageBuild mine = buildIn("brandx");
        when(builds.findById("b1")).thenReturn(Mono.just(mine));
        StepVerifier.create(service.detail(adminOf(BRANDX_ISSUER, "admin-x"), "b1"))
                .expectNext(mine).verifyComplete();
    }

    @Test
    void events_crossDomainAdmin_404NotLeaked() {
        when(builds.findById("b1")).thenReturn(Mono.just(buildIn("brandy")));
        StepVerifier.create(service.events(adminOf(BRANDX_ISSUER, "admin-x"), "b1"))
                .expectErrorSatisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(404))
                .verify();
    }

    // ── WORKLIST BATCH (item 1) — bounded batch, ONE step-up, own-domain wall on content ──

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static JsonNode json(String s) {
        try {
            return MAPPER.readTree(s);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static BatchImageSpec bspec(String targetUser, String platform, JsonNode spec) {
        return new BatchImageSpec(targetUser, "primary", platform, false, spec);
    }

    private static BatchTriggerImageBuildRequest batch(JsonNode base, List<BatchImageSpec> entries,
                                                       Integer maxConcurrent) {
        return new BatchTriggerImageBuildRequest("hugmesh-worklist/v1", base, entries, maxConcurrent);
    }

    @Test
    void triggerBatch_ownDomain_persistsAllEntries_singleMfaConsumeForBatch() {
        // A FRESH MFA stamp authorizes the WHOLE bounded batch — consumed EXACTLY ONCE for N=3
        // (contrast the single trigger's per-build consume).
        when(stepUp.isSatisfied(anyString(), any())).thenReturn(false);
        when(mfaStepUp.isFresh(eq("sess-1"))).thenReturn(Mono.just(true));
        var admin = adminOf(BRANDX_ISSUER, "admin-x");
        JsonNode base = json("{\"domains\":[{\"name\":\"brandx.example\"}],"
                + "\"users\":[{\"username\":\"u\",\"domain\":\"brandx.example\"}]}");
        var entries = List.of(
                bspec("brandx/alice", "rpi5", null),
                bspec("brandx/bob", "x86", null),
                bspec("brandx/carol", "jetson", null));

        StepVerifier.create(service.triggerBatch(admin, batch(base, entries, 1), null, "sess-1"))
                .assertNext(r -> {
                    assertThat(r.builds()).hasSize(3);
                    assertThat(r.builds()).allSatisfy(b -> assertThat(b.domain()).isEqualTo("brandx"));
                    assertThat(r.batchId()).isNotBlank();
                })
                .verifyComplete();
        verify(builds, times(3)).insert(any());
        verify(orchestrator, times(3)).launch(any());
        verify(mfaStepUp, times(1)).consume(eq("sess-1"));   // ONE consume for the whole batch
    }

    @Test
    void triggerBatch_crossDomainEntry_denied_nothingPersisted() {
        var admin = adminOf(BRANDX_ISSUER, "admin-x");
        var entries = List.of(
                bspec("brandx/alice", "rpi5", null),
                bspec("brandy/victim", "x86", null));   // foreign org qualifier

        StepVerifier.create(service.triggerBatch(admin, batch(null, entries, 1), "tok", null))
                .expectErrorSatisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(403))
                .verify();
        verify(builds, never()).insert(any());
        verify(mfaStepUp, never()).consume(anyString());
    }

    @Test
    void triggerBatch_crossTenantContentDomain_denied() {
        // The own-domain wall now extends to manifest CONTENT: a brandx admin referencing a
        // brandy domain name in base.domains[] is a cross-tenant escalation → 403, nothing persisted.
        var admin = adminOf(BRANDX_ISSUER, "admin-x");
        JsonNode base = json("{\"domains\":[{\"name\":\"brandy.example\"}]}");
        var entries = List.of(bspec("brandx/alice", "rpi5", null));

        StepVerifier.create(service.triggerBatch(admin, batch(base, entries, 1), "tok", null))
                .expectErrorSatisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(403))
                .verify();
        verify(builds, never()).insert(any());
    }

    @Test
    void triggerBatch_crossTenantUserDomain_denied() {
        var admin = adminOf(BRANDX_ISSUER, "admin-x");
        JsonNode base = json("{\"users\":[{\"username\":\"v\",\"domain\":\"brandy.example\"}]}");
        var entries = List.of(bspec("brandx/alice", "rpi5", null));

        StepVerifier.create(service.triggerBatch(admin, batch(base, entries, 1), "tok", null))
                .expectErrorSatisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(403))
                .verify();
        verify(builds, never()).insert(any());
    }

    @Test
    void triggerBatch_superadmin_mayReferenceCrossBrandContent() {
        // A SUPERADMIN composes cross-brand meshes — the content wall does NOT apply to them.
        JsonNode base = json("{\"domains\":[{\"name\":\"brandy.example\"},{\"name\":\"brandx.example\"}]}");
        var entries = List.of(bspec("brandy/bob", "rpi5", null));

        StepVerifier.create(service.triggerBatch(superadmin("root"), batch(base, entries, 1), "tok", null))
                .assertNext(r -> {
                    assertThat(r.builds()).hasSize(1);
                    assertThat(r.builds().get(0).domain()).isEqualTo("brandy");   // qualifier selects brand
                })
                .verifyComplete();
    }

    @Test
    void triggerBatch_persistsMaterializedImageSpecJson() {
        var admin = adminOf(BRANDX_ISSUER, "admin-x");
        JsonNode spec = json("{\"role\":\"gateway\",\"platform\":\"rpi5\"}");
        var entries = List.of(bspec("brandx/alice", "rpi5", spec));

        StepVerifier.create(service.triggerBatch(admin, batch(null, entries, 1), "tok", null))
                .expectNextCount(1).verifyComplete();

        ArgumentCaptor<ImageBuild> captor = ArgumentCaptor.forClass(ImageBuild.class);
        verify(builds).insert(captor.capture());
        ImageBuild queued = captor.getValue();
        assertThat(queued.domain()).isEqualTo("brandx");                 // server-derived
        assertThat(queued.imageSpecJson()).isNotNull().contains("\"role\":\"gateway\"");
        assertThat(queued.status()).isEqualTo(ImageBuild.STATUS_QUEUED);
    }

    @Test
    void triggerBatch_missingStepUp_denied_nothingPersisted() {
        when(stepUp.isSatisfied(anyString(), any())).thenReturn(false);
        var admin = adminOf(BRANDX_ISSUER, "admin-x");
        var entries = List.of(bspec("brandx/alice", "rpi5", null));

        StepVerifier.create(service.triggerBatch(admin, batch(null, entries, 1), null, null))
                .expectErrorSatisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(403))
                .verify();
        verify(builds, never()).insert(any());
    }

    @Test
    void triggerBatch_specInjection_secretField_400_nothingPersisted() {
        // The fail-closed envelope validator fences the IMAGE_SPEC_JSON channel BEFORE any write.
        var admin = adminOf(BRANDX_ISSUER, "admin-x");
        JsonNode spec = json("{\"role\":\"gateway\",\"user_password\":\"hunter2\"}");
        var entries = List.of(bspec("brandx/alice", "rpi5", spec));

        StepVerifier.create(service.triggerBatch(admin, batch(null, entries, 1), "tok", null))
                .expectErrorSatisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(400))
                .verify();
        verify(builds, never()).insert(any());
    }

    // ── terminal-ingest idempotency (item 8) ─────────────────────────────────
    @Test
    void ingest_alreadyTerminal_isIdempotentNoOp() {
        // A second terminal POST after the sink closed must NOT re-stamp / re-seed / re-fan — it is
        // a 200 no-op returning the row as-is (mirrors GoLiveInternalController's applied-ack CAS).
        ImageBuild done = new ImageBuild("b1", Instant.now(), "admin-x", "brandx/alice", "brandx",
                "primary", "rpi5", null, ImageBuild.STATUS_COMPLETED, false,
                "job", "build-b1/image.img", null, null, Instant.now(), null);
        when(builds.findById("b1")).thenReturn(Mono.just(done));
        ImageBuildIngestRequest second = new ImageBuildIngestRequest("FAILED", null, null, null,
                null, null, null, null, null, null, null, null, null, null);

        StepVerifier.create(service.ingest("b1", second))
                .expectNext(done).verifyComplete();
        verify(builds, never()).recordArtifacts(anyString(), any(), any(), any());
        verify(orchestrator, never()).ingest(anyString(), anyString(), any(), any(), any(), any());
    }
}
