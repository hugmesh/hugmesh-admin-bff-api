package systems.hugmesh.adminbff.cloudbackup;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import systems.hugmesh.adminbff.notification.NotificationOutbox;
import systems.hugmesh.adminbff.notification.NotificationOutboxRepository;
import systems.hugmesh.commons.security.PrincipalDomain;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The {@link BackupService} authorization + orchestration unit tests — the logic that lives
 * BELOW the controller: the TOTAL-scope SUPERADMIN gate (defence-in-depth), the residency
 * domain stamping, the version allocation (MAX+1), and the destination domain resolution
 * (a scoped admin can never address another brand). Repositories + effector are mocked.
 */
class BackupServiceTest {

    private BackupSetRepository sets;
    private BackupArtifactRepository artifacts;
    private BackupDestinationRepository destinations;
    private RunningServiceProvider running;
    private BackupEffector effector;
    private NotificationOutboxRepository outbox;
    private BackupService service;

    @BeforeEach
    void setUp() {
        sets = mock(BackupSetRepository.class);
        artifacts = mock(BackupArtifactRepository.class);
        destinations = mock(BackupDestinationRepository.class);
        running = mock(RunningServiceProvider.class);
        effector = mock(BackupEffector.class);
        outbox = mock(NotificationOutboxRepository.class);
        // The transactional-outbox emission (PR: backup/restore notifications) is mocked at
        // the repo here — these are the AUTHZ/orchestration unit tests (repos + effector are
        // mocked); the REAL transactional-outbox behaviour (atomic row, domain stamp, coupled
        // rollback, ships-dark, neutral payload) is proven over a real Postgres in
        // BackupOutboxTransactionTest. A pass-through TransactionalOperator is sufficient here
        // because there is no real connection — the operator only needs to return the chain
        // unchanged so the mocked repos resolve.
        service = new BackupService(sets, artifacts, destinations, running, effector, outbox,
                passThroughTx());
        when(effector.startBackup(any())).thenReturn(Mono.empty());
        when(effector.startRestore(any())).thenReturn(Mono.empty());
        when(outbox.insert(anyString(), anyString(), anyString(), anyString(), any()))
                .thenReturn(Mono.just(1L));
        when(artifacts.insert(anyString(), anyString(), anyString()))
                .thenReturn(Mono.just(new BackupArtifact("a", "s", "svc", "config", null,
                        BackupArtifact.STATUS_PENDING, Instant.now(), null)));
    }

    /** A pass-through {@link org.springframework.transaction.reactive.TransactionalOperator}:
     *  {@code transactional(Mono/Flux)} returns the publisher UNCHANGED. These mocked-repo unit
     *  tests have no real connection, so no transaction can (or needs to) be opened; the real
     *  atomic-tx behaviour is proven in BackupOutboxTransactionTest over a real Postgres. */
    private static org.springframework.transaction.reactive.TransactionalOperator passThroughTx() {
        return new org.springframework.transaction.reactive.TransactionalOperator() {
            @Override
            public <T> reactor.core.publisher.Mono<T> transactional(reactor.core.publisher.Mono<T> mono) {
                return mono;
            }

            @Override
            public <T> reactor.core.publisher.Flux<T> transactional(reactor.core.publisher.Flux<T> flux) {
                return flux;
            }

            @Override
            public <T> reactor.core.publisher.Flux<T> execute(
                    org.springframework.transaction.reactive.TransactionCallback<T> action) {
                throw new UnsupportedOperationException("execute() is unused by BackupService");
            }
        };
    }

    // ── TOTAL scope: superadmin-only (defence-in-depth in the service) ───────────────────

    @Test
    void create_totalScope_byScopedAdmin_isDenied() {
        // a scoped admin (issuer-derived brandx, NOT superadmin) requesting TOTAL -> denied.
        PrincipalDomain scoped = brandScoped("brandx");
        StepVerifier.create(service.create("k", BackupCloudScope.TOTAL, List.of("postgres"),
                        BackupDestinationKind.OBJECT_STORE, "s3://b", null, "alice", scoped))
                .expectError(BackupService.TotalScopeDeniedException.class)
                .verify();
        verify(sets, never()).insert(any(), org.mockito.ArgumentMatchers.anyLong(), any(), any(),
                any(), any(), any(), any(), any());
    }

    @Test
    void create_totalScope_bySuperadmin_isAllowed_andStampsHomeDomain() {
        PrincipalDomain sa = PrincipalDomain.superadminFor("default");
        when(sets.maxVersion(eq("default"), anyString())).thenReturn(Mono.just(0L));
        captureInsertReturning("default", BackupCloudScope.TOTAL);
        BackupSet out = service.create("total-cloud", BackupCloudScope.TOTAL, List.of("postgres"),
                BackupDestinationKind.OBJECT_STORE, "s3://b", null, "root", sa).block();
        assertThat(out.scope()).isEqualTo(BackupCloudScope.TOTAL);
        assertThat(out.domain()).isEqualTo("default");
    }

    // ── DOMAIN scope: stamps the validated domain (never the body) + allocates version ───

    @Test
    void create_domainScope_stampsScopeDomain_andAllocatesNextVersion() {
        PrincipalDomain scoped = brandScoped("brandx");
        when(sets.maxVersion(eq("brandx"), anyString())).thenReturn(Mono.just(4L));
        ArgumentCaptor<Long> version = ArgumentCaptor.forClass(Long.class);
        ArgumentCaptor<String> domain = ArgumentCaptor.forClass(String.class);
        when(sets.insert(anyString(), version.capture(), eq(BackupCloudScope.DOMAIN),
                domain.capture(), eq("alice"), any(), any(), any(), any()))
                .thenAnswer(inv -> Mono.just(new BackupSet("set-1", inv.getArgument(0),
                        inv.getArgument(1), inv.getArgument(2), inv.getArgument(3),
                        inv.getArgument(4), inv.getArgument(5), inv.getArgument(6),
                        inv.getArgument(7), null, inv.getArgument(8), BackupSet.STATUS_PENDING,
                        Instant.now(), null, null)));
        service.create("k", BackupCloudScope.DOMAIN, List.of("postgres", "matrix"),
                BackupDestinationKind.OBJECT_STORE, "s3://b", null, "alice", scoped).block();
        assertThat(version.getValue()).isEqualTo(5L);             // MAX(4)+1
        assertThat(domain.getValue()).isEqualTo("brandx");        // stamped from scope
        // one artifact per selected service.
        verify(artifacts).insert(eq("set-1"), eq("postgres"), anyString());
        verify(artifacts).insert(eq("set-1"), eq("matrix"), anyString());
        verify(effector).startBackup(any());
    }

    @Test
    void create_emptyServices_isRejected() {
        StepVerifier.create(service.create("k", BackupCloudScope.DOMAIN, List.of(),
                        BackupDestinationKind.OBJECT_STORE, "s3://b", null, "alice", brandScoped("brandx")))
                .expectError(IllegalArgumentException.class).verify();
    }

    // ── restore: scoped re-resolve (out-of-scope id -> error) ────────────────────────────

    @Test
    void restore_outOfScopeId_errors() {
        when(sets.findScoped(eq("nope"), any())).thenReturn(Mono.empty());
        StepVerifier.create(service.restore("nope", "alice", brandScoped("brandx")))
                .expectError(IllegalArgumentException.class).verify();
        verify(effector, never()).startRestore(any());
    }

    @Test
    void restore_inScope_invokesEffector() {
        BackupSet s = new BackupSet("set-1", "k", 1L, BackupCloudScope.DOMAIN, "brandx", "alice",
                List.of("postgres"), BackupDestinationKind.OBJECT_STORE, "s3://b", null, null,
                BackupSet.STATUS_COMPLETE, Instant.now(), null, null);
        when(sets.findScoped(eq("set-1"), any())).thenReturn(Mono.just(s));
        service.restore("set-1", "alice", brandScoped("brandx")).block();
        verify(effector).startRestore(any());
    }

    // ── destination domain resolution (scoped admin can't address another brand) ─────────

    @Test
    void putDestination_scopedAdmin_ignoresTargetDomain_usesOwnBrand() {
        PrincipalDomain scoped = brandScoped("brandx");
        ArgumentCaptor<String> domain = ArgumentCaptor.forClass(String.class);
        when(destinations.upsert(any(), anyString(), any(), domain.capture(), anyString()))
                .thenReturn(Mono.just(new BackupDestination("d", BackupDestinationKind.OBJECT_STORE,
                        "s3://b", null, "brandx", "alice", Instant.now(), null)));
        // a scoped admin passes targetDomain=brandy, but it is IGNORED — own brand wins.
        service.putDestination(BackupDestinationKind.OBJECT_STORE, "s3://b", null, "alice",
                scoped, "brandy").block();
        assertThat(domain.getValue()).isEqualTo("brandx");
    }

    @Test
    void putDestination_superadmin_honoursTargetDomain() {
        PrincipalDomain sa = PrincipalDomain.superadminFor("default");
        ArgumentCaptor<String> domain = ArgumentCaptor.forClass(String.class);
        when(destinations.upsert(any(), anyString(), any(), domain.capture(), anyString()))
                .thenReturn(Mono.just(new BackupDestination("d", BackupDestinationKind.NODE_STORAGE,
                        "pool-1", null, "brandy", "root", Instant.now(), null)));
        service.putDestination(BackupDestinationKind.NODE_STORAGE, "pool-1", null, "root",
                sa, "brandy").block();
        assertThat(domain.getValue()).isEqualTo("brandy");        // superadmin targets a brand
    }

    @Test
    void list_superadmin_withFilterDomain_narrows() {
        PrincipalDomain sa = PrincipalDomain.superadminFor("default");
        when(sets.listForDomain(eq("brandy"))).thenReturn(Flux.empty());
        service.list(sa, "brandy").collectList().block();
        verify(sets).listForDomain("brandy");
        verify(sets, never()).list(any());
    }

    @Test
    void list_scopedAdmin_ignoresFilterDomain() {
        PrincipalDomain scoped = brandScoped("brandx");
        when(sets.list(any())).thenReturn(Flux.empty());
        // a scoped admin passing ?domain=brandy is ignored — they only ever see their own brand.
        service.list(scoped, "brandy").collectList().block();
        verify(sets).list(scoped);
        verify(sets, never()).listForDomain(anyString());
    }

    // ── helpers ──────────────────────────────────────────────────────────────────────────

    /** A scoped (non-superadmin) tenant homed at {@code domain}, built via a JWT so
     *  {@code scoped()} is true (mirrors the repository test's admin()). */
    private static PrincipalDomain brandScoped(String domain) {
        var registry = new systems.hugmesh.commons.security.DomainRegistry("",
                "https://idp." + domain + ".example=" + domain);
        var jwt = org.springframework.security.oauth2.jwt.Jwt.withTokenValue("t")
                .header("alg", "none").issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                .subject("u").issuer("https://idp." + domain + ".example")
                .claim("roles", List.of("admin")).build();
        var auth = new org.springframework.security.oauth2.server.resource.authentication
                .JwtAuthenticationToken(jwt, List.of(
                new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_USER"),
                new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_ADMIN")));
        return PrincipalDomain.of(auth, registry);
    }

    private void captureInsertReturning(String domain, BackupCloudScope scope) {
        when(sets.insert(anyString(), org.mockito.ArgumentMatchers.anyLong(), eq(scope),
                eq(domain), anyString(), any(), any(), any(), any()))
                .thenAnswer(inv -> Mono.just(new BackupSet("set-1", inv.getArgument(0),
                        inv.getArgument(1), inv.getArgument(2), inv.getArgument(3),
                        inv.getArgument(4), inv.getArgument(5), inv.getArgument(6),
                        inv.getArgument(7), null, inv.getArgument(8), BackupSet.STATUS_PENDING,
                        Instant.now(), null, null)));
    }
}
