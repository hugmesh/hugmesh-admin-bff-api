package net.hugmesh.adminbff.desktop;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import net.hugmesh.authcore.casdoor.CasdoorAdminClient;
import net.hugmesh.authcore.provision.GatewayRevocationClient;

import java.time.Instant;

import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * The REAL claim sync over a MOCKED {@link CasdoorAdminClient} + {@link GatewayRevocationClient}
 * + {@link DesktopSudoGrantRepository} (NEVER a real IdP). Pins the membership contract:
 * <ul>
 *   <li>ACTIVE grant -> {@code addUserToRole(desktop-sudo, org/subject)} + a best-effort
 *       {@code subject:<subject>} gateway revocation (the AdminController.grantRole parity)
 *       -> {@code applied};</li>
 *   <li>REVOKED grant, no other active grant -> {@code removeUserFromRole} + the revocation
 *       -> {@code applied}; ANOTHER active grant remains -> membership KEPT (no Casdoor
 *       write, no revocation) -> {@code applied};</li>
 *   <li>a Casdoor error -> {@code failed} (NEVER an error — the reconciler sweep retries);</li>
 *   <li>null Casdoor client (casdoor.admin.enabled=false) -> logged DRY-RUN, {@code pending},
 *       nothing dialed;</li>
 *   <li>an already {@code org/}-prefixed subject passes through un-double-prefixed.</li>
 * </ul>
 */
class CasdoorDesktopSudoClaimSyncTest {

    private final CasdoorAdminClient casdoor = mock(CasdoorAdminClient.class);
    private final DesktopSudoGrantRepository repo = mock(DesktopSudoGrantRepository.class);
    private final GatewayRevocationClient revocations = mock(GatewayRevocationClient.class);

    /** Distinct, non-default TTLs so a swap of the two at either call site is visible. */
    private static final long CUTOFF_TTL = 700_000L;
    private static final long GRANT_TTL = 1_800L;

    private final CasdoorDesktopSudoClaimSync sync =
            new CasdoorDesktopSudoClaimSync(casdoor, repo, revocations, CUTOFF_TTL, GRANT_TTL);

    private static DesktopSudoGrant grant(String subject, String state) {
        return new DesktopSudoGrant("g-1", subject, "dev-1", state, "root", Instant.now(),
                null, null, "brandx", DesktopSudoGrant.PROP_PENDING, 1L);
    }

    // ── ACTIVE -> add membership ─────────────────────────────────────────────────

    @Test
    void activeGrant_addsSubjectToSeededRole_andRevokesLiveJwt_applied() {
        when(casdoor.organization()).thenReturn("hugmesh");
        when(casdoor.addUserToRole(anyString(), anyString())).thenReturn(Mono.empty());
        when(revocations.revokeSubject(anyString(), anyString(), anyLong())).thenReturn(Mono.empty());

        StepVerifier.create(sync.propagate(grant("alice", DesktopSudoGrant.STATE_ACTIVE)))
                .expectNext(DesktopSudoGrant.PROP_APPLIED).verifyComplete();

        // the generator-seeded wire name + the org-qualified member id
        verify(casdoor).addUserToRole("desktop-sudo", "hugmesh/alice");
        // AdminController.grantRole parity: re-mint the live token with the new role, under the
        // SHORT grant TTL (the key locks the subject out while it lives; a grant cuts nothing off).
        verify(revocations).revokeSubject("alice", "desktop-sudo-grant", GRANT_TTL);
    }

    @Test
    void activeGrant_orgPrefixedSubject_passesThroughUnprefixed() {
        when(casdoor.addUserToRole(anyString(), anyString())).thenReturn(Mono.empty());
        when(revocations.revokeSubject(anyString(), anyString(), anyLong())).thenReturn(Mono.empty());

        StepVerifier.create(sync.propagate(grant("hugmesh/alice", DesktopSudoGrant.STATE_ACTIVE)))
                .expectNext(DesktopSudoGrant.PROP_APPLIED).verifyComplete();

        verify(casdoor).addUserToRole("desktop-sudo", "hugmesh/alice");
    }

    @Test
    void activeGrant_casdoorAddFails_returnsFailed_neverErrors() {
        when(casdoor.organization()).thenReturn("hugmesh");
        when(casdoor.addUserToRole(anyString(), anyString()))
                .thenReturn(Mono.error(new IllegalStateException("casdoor 503")));
        // `.then(revokeSubject(...))` ASSEMBLES the revocation Mono up front (the
        // AdminController idiom) — the POST only fires on SUBSCRIPTION, so track that.
        java.util.concurrent.atomic.AtomicBoolean revocationFired =
                new java.util.concurrent.atomic.AtomicBoolean();
        when(revocations.revokeSubject(anyString(), anyString(), anyLong()))
                .thenReturn(Mono.<Void>empty().doOnSubscribe(s -> revocationFired.set(true)));

        StepVerifier.create(sync.propagate(grant("alice", DesktopSudoGrant.STATE_ACTIVE)))
                .expectNext(DesktopSudoGrant.PROP_FAILED).verifyComplete();

        // the membership never landed, so the JWT re-mint leg is never subscribed (no POST).
        org.assertj.core.api.Assertions.assertThat(revocationFired).isFalse();
    }

    // ── REVOKED -> drop membership iff no other active grant remains ─────────────

    @Test
    void revokedGrant_noOtherActive_removesMembership_andRevokesLiveJwt_applied() {
        when(casdoor.organization()).thenReturn("hugmesh");
        when(repo.hasActiveForSubject("alice")).thenReturn(Mono.just(false));
        when(casdoor.removeUserFromRole(anyString(), anyString())).thenReturn(Mono.empty());
        when(revocations.revokeSubject(anyString(), anyString(), anyLong())).thenReturn(Mono.empty());

        StepVerifier.create(sync.propagate(grant("alice", DesktopSudoGrant.STATE_REVOKED)))
                .expectNext(DesktopSudoGrant.PROP_APPLIED).verifyComplete();

        verify(casdoor).removeUserFromRole("desktop-sudo", "hugmesh/alice");
        // AdminController.revokeRole parity: deny the stale sudo-bearing token for the CUT-OFF
        // TTL — hugmesh-desktop tokens live 168 h, so a 1 h key let the claim ride ~7 more days.
        verify(revocations).revokeSubject("alice", "desktop-sudo-revoke", CUTOFF_TTL);
    }

    @Test
    void revokedGrant_otherActiveRemains_keepsMembership_noCasdoorWrite_applied() {
        when(repo.hasActiveForSubject("alice")).thenReturn(Mono.just(true));

        StepVerifier.create(sync.propagate(grant("alice", DesktopSudoGrant.STATE_REVOKED)))
                .expectNext(DesktopSudoGrant.PROP_APPLIED).verifyComplete();

        // Removing would strip the OTHER device's claim — membership must stay put, and
        // nothing about the token changed, so no revocation is posted.
        verify(casdoor, never()).removeUserFromRole(anyString(), anyString());
        verifyNoInteractions(revocations);
    }

    @Test
    void revokedGrant_casdoorRemoveFails_returnsFailed_neverErrors() {
        when(casdoor.organization()).thenReturn("hugmesh");
        when(repo.hasActiveForSubject("alice")).thenReturn(Mono.just(false));
        when(casdoor.removeUserFromRole(anyString(), anyString()))
                .thenReturn(Mono.error(new IllegalStateException("casdoor 503")));
        java.util.concurrent.atomic.AtomicBoolean revocationFired =
                new java.util.concurrent.atomic.AtomicBoolean();
        when(revocations.revokeSubject(anyString(), anyString(), anyLong()))
                .thenReturn(Mono.<Void>empty().doOnSubscribe(s -> revocationFired.set(true)));

        StepVerifier.create(sync.propagate(grant("alice", DesktopSudoGrant.STATE_REVOKED)))
                .expectNext(DesktopSudoGrant.PROP_FAILED).verifyComplete();

        // the removal never landed -> the revocation leg is never subscribed (no POST).
        org.assertj.core.api.Assertions.assertThat(revocationFired).isFalse();
    }

    // ── DRY-RUN: Casdoor admin disabled ──────────────────────────────────────────

    @Test
    void nullCasdoorClient_isLoggedDryRun_staysPending_dialsNothing() {
        CasdoorDesktopSudoClaimSync dark =
                new CasdoorDesktopSudoClaimSync(null, repo, revocations, CUTOFF_TTL, GRANT_TTL);

        StepVerifier.create(dark.propagate(grant("alice", DesktopSudoGrant.STATE_ACTIVE)))
                .expectNext(DesktopSudoGrant.PROP_PENDING).verifyComplete();

        verifyNoInteractions(repo, revocations);
    }

    @Test
    void nonPositiveTtl_isRefusedAtConstruction() {
        // <= 0 would mean the gateway table's 30-day default: a month-long lock-out on a grant.
        org.assertj.core.api.Assertions.assertThatThrownBy(
                        () -> new CasdoorDesktopSudoClaimSync(casdoor, repo, revocations, CUTOFF_TTL, 0L))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("subject-grant-ttl-seconds");
        org.assertj.core.api.Assertions.assertThatThrownBy(
                        () -> new CasdoorDesktopSudoClaimSync(casdoor, repo, revocations, -1L, GRANT_TTL))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("subject-cutoff-ttl-seconds");
    }

    @Test
    void realSync_reportsReal_noopReportsDark() {
        org.assertj.core.api.Assertions.assertThat(sync.isReal()).isTrue();
        org.assertj.core.api.Assertions.assertThat(new NoopDesktopSudoClaimSync().isReal()).isFalse();
    }
}
