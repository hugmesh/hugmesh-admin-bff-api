package net.hugmesh.adminbff.imagegen;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.test.context.ActiveProfiles;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import net.hugmesh.authcore.casdoor.MfaStepUpService;
import net.hugmesh.adminbff.device.DeviceRegistryRepository;
import net.hugmesh.adminbff.support.TestDatabaseConfig;
import net.hugmesh.adminbff.sshterminal.DeviceSshDialRepository;
import net.hugmesh.adminbff.sshterminal.ImageBuild;
import net.hugmesh.adminbff.sshterminal.ImageBuildR2dbcRepository;
import net.hugmesh.adminbff.sshterminal.ImageBuildRepository;
import net.hugmesh.adminbff.testutil.R2dbcRepos;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.web.ApiException;
import net.hugmesh.adminbff.web.dto.BatchImageSpec;
import net.hugmesh.adminbff.web.dto.BatchTriggerImageBuildRequest;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The WORKLIST BATCH service over a REAL Liquibase-applied Postgres (Testcontainers via
 * {@link TestDatabaseConfig} — the same real-PG wiring {@link ImageBuildOrchestratorTest} /
 * {@link net.hugmesh.adminbff.sshterminal.ImageBuildRepositoryTest} use). Proves the
 * durable legs the mocked {@link ImageBuildServiceTest} cannot:
 * <ul>
 *   <li>the 280 changelog applies (the new {@code image_spec_json} column exists) and the
 *       MATERIALIZED spec ROUND-TRIPS through the R2DBC insert/read;</li>
 *   <li>N QUEUED rows are genuinely persisted for a bounded batch;</li>
 *   <li>ONE {@code mfaStepUp.consume()} for the whole batch (single-use step-up);</li>
 *   <li>the own-domain wall on manifest CONTENT ({@code base.domains[].name}) denies a
 *       cross-tenant batch and persists NOTHING.</li>
 * </ul>
 *
 * <p>NB: this class deliberately does NOT declare a nested {@code @SpringBootConfiguration}
 * (the {@code @SpringBootTest(classes=Boot)} idiom) — one placed in this package would be
 * auto-discovered as the config root for the sibling {@code @WebFluxTest} controller slices and
 * break their handler-mapping scan. The {@code @DataR2dbcTest}+{@code TestDatabaseConfig} form
 * spins the same real Postgres + full changelog without polluting the package.
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
@ActiveProfiles("test")
class ImageBuildServiceBatchTest {

    private static final String BRANDX_ISSUER = "https://idp.brandx.example";
    private static final String BRANDY_ISSUER = "https://idp.brandy.example";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Autowired DatabaseClient db;

    private ImageBuildRepository builds;
    private MfaStepUpService mfaStepUp;
    private ImageGenStepUpGate stepUp;
    private ImageBuildService service;

    @BeforeEach
    void setUp() {
        db.sql("DELETE FROM image_build").fetch().rowsUpdated().block();

        builds = new ImageBuildRepository(R2dbcRepos.of(db, ImageBuildR2dbcRepository.class));
        ImageBuildOrchestrator orchestrator =
                new ImageBuildOrchestrator(builds, new NoopImageJobLauncher(), 64);
        DeviceSshDialRepository dials = mock(DeviceSshDialRepository.class);
        DeviceRegistryRepository devices = mock(DeviceRegistryRepository.class);
        ImageArtifactStore artifacts = mock(ImageArtifactStore.class);
        stepUp = mock(ImageGenStepUpGate.class);
        mfaStepUp = mock(MfaStepUpService.class);
        DomainRegistry registry = new DomainRegistry("",
                BRANDX_ISSUER + "=brandx," + BRANDY_ISSUER + "=brandy");

        // A fresh MFA stamp satisfies step-up; it is the consumable single-use signal.
        when(mfaStepUp.isFresh(any())).thenReturn(Mono.just(true));
        when(mfaStepUp.consume(any())).thenReturn(Mono.empty());
        when(stepUp.isSatisfied(anyString(), any(), anyBoolean())).thenReturn(true);

        service = new ImageBuildService(builds, dials, devices, orchestrator, artifacts, stepUp,
                mfaStepUp, registry, new WorklistEnvelopeValidator(), new ImageGenConfig());
    }

    private static JwtAuthenticationToken admin(String issuer, String subject) {
        Jwt jwt = Jwt.withTokenValue("t").header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                .subject(subject).issuer(issuer).claim("roles", List.of("admin")).build();
        return new JwtAuthenticationToken(jwt,
                List.of(new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    private static JsonNode json(String s) {
        try {
            return MAPPER.readTree(s);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static BatchImageSpec spec(String targetUser, String platform, JsonNode imageSpec) {
        return new BatchImageSpec(targetUser, "primary", platform, false, imageSpec);
    }

    private long rowCount() {
        Long c = db.sql("SELECT count(*) AS c FROM image_build")
                .map(row -> row.get("c", Long.class)).one().block();
        return c == null ? 0 : c;
    }

    @Test
    void batch_persistsNRows_singleConsume_andSpecRoundTrips() {
        JsonNode gatewaySpec = json("{\"role\":\"gateway\",\"platform\":\"rpi5\"}");
        var entries = List.of(
                spec("brandx/alice", "rpi5", gatewaySpec),      // has a materialized spec
                spec("brandx/bob", "x86", null),                // legacy 6-env (no spec)
                spec("brandx/carol", "jetson", json("{\"role\":\"edge_ai\",\"platform\":\"jetson\"}")));
        var req = new BatchTriggerImageBuildRequest("hugmesh-worklist/v1", null, entries, 1);

        ImageBuildService.BatchResult result =
                service.triggerBatch(admin(BRANDX_ISSUER, "admin-x"), req, null, "sess-1").block();

        assertThat(result).isNotNull();
        assertThat(result.builds()).hasSize(3);
        assertThat(rowCount()).isEqualTo(3);
        // ONE consume for the whole batch (single-use step-up).
        verify(mfaStepUp, times(1)).consume(any());

        // the MATERIALIZED spec round-trips through the 280 image_spec_json column…
        String id0 = result.builds().get(0).id();
        ImageBuild persisted0 = builds.findById(id0).block();
        assertThat(persisted0).isNotNull();
        assertThat(persisted0.domain()).isEqualTo("brandx");            // server-derived
        assertThat(persisted0.imageSpecJson()).isNotNull().contains("\"role\":\"gateway\"");

        // …and the legacy (no-spec) entry keeps a NULL spec (the 6-env fallback path).
        String id1 = result.builds().get(1).id();
        assertThat(builds.findById(id1).block().imageSpecJson()).isNull();
    }

    @Test
    void batch_crossTenantContentDomain_denied_persistsNothing() {
        JsonNode base = json("{\"domains\":[{\"name\":\"brandy.example\"}]}");
        var entries = List.of(spec("brandx/alice", "rpi5", null));
        var req = new BatchTriggerImageBuildRequest("hugmesh-worklist/v1", base, entries, 1);

        StepVerifier.create(service.triggerBatch(admin(BRANDX_ISSUER, "admin-x"), req, null, "sess-1"))
                .expectErrorSatisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(403))
                .verify();
        assertThat(rowCount()).isZero();
    }
}
