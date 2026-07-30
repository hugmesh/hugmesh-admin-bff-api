package systems.hugmesh.adminbff.workload;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import systems.hugmesh.authcore.account.AccountStatus;
import systems.hugmesh.adminbff.suspension.SuspensionService;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The CORE WORKLOAD CONSOLE security acceptance bar — the STEP 0..7 authorization predicate
 * matrix ({@link WorkloadAuthorizationService}). Exercises role ALLOW/DENY, cross-tier DENY,
 * read-only-bypass DENY, master-off DENY, the GLOBAL dangerous-tier kill (even for SA), the
 * log_access gate, and the step-up requirement — all through the real decision logic with
 * mocked repos.
 */
class WorkloadAuthorizationServiceTest {

    private WorkloadConsoleGrantRepository grants;
    private WorkloadConsoleConfigRepository configs;
    private SuspensionService suspensions;
    private WorkloadStepUpService stepUp;
    private WorkloadAuthorizationService authz;

    @BeforeEach
    void setup() {
        grants = mock(WorkloadConsoleGrantRepository.class);
        configs = mock(WorkloadConsoleConfigRepository.class);
        suspensions = mock(SuspensionService.class);
        stepUp = mock(WorkloadStepUpService.class);
        authz = new WorkloadAuthorizationService(grants, configs, suspensions,
                WorkloadScopeFixtures.REGISTRY, stepUp);
        // defaults: no grant, no per-domain row, GLOBAL absent (=> off)
        when(grants.findActive(anyString(), anyString())).thenReturn(Mono.empty());
        when(configs.find(anyString())).thenReturn(Mono.empty());
        when(suspensions.statusFor(anyString())).thenReturn(Mono.just(AccountStatus.active()));
        when(stepUp.validate(anyString(), any())).thenReturn(false);
    }

    private void globalAdmin(boolean adminEnabled, boolean dangerous) {
        when(configs.find(WorkloadConsoleConfig.GLOBAL_DOMAIN)).thenReturn(Mono.just(
                new WorkloadConsoleConfig("g", WorkloadConsoleConfig.GLOBAL_DOMAIN, adminEnabled,
                        dangerous, "root", Instant.now(), 1)));
    }

    private void perDomain(String domain, boolean adminEnabled) {
        when(configs.find(domain)).thenReturn(Mono.just(
                new WorkloadConsoleConfig("d", domain, adminEnabled, false, "root", Instant.now(), 1)));
    }

    private void activeGrant(String grantee, String domain, boolean logAccess) {
        when(grants.findActive(grantee, domain)).thenReturn(Mono.just(new WorkloadConsoleGrant(
                "id", grantee, domain, WorkloadConsoleGrant.ACCESS_READ_ONLY, logAccess,
                WorkloadConsoleGrant.STATE_ACTIVE, "root", Instant.now(),
                Instant.now().plus(24, ChronoUnit.HOURS), null, null, domain,
                WorkloadConsoleGrant.PROP_PENDING, 1)));
    }

    // ── STEP 1 — superadmin ──────────────────────────────────────────────────────

    @Test
    void superadmin_read_allow() {
        var d = authz.decide(WorkloadScopeFixtures.superadminAuth(), DangerTier.READ, false, true, null)
                .block();
        assertThat(d.allow()).isTrue();
        assertThat(d.superadmin()).isTrue();
    }

    @Test
    void superadmin_runtimeMutate_allow() {
        var d = authz.decide(WorkloadScopeFixtures.superadminAuth(), DangerTier.RUNTIME_MUTATE,
                false, true, null).block();
        assertThat(d.allow()).isTrue();
    }

    @Test
    void superadmin_dangerous_deniedWhenGlobalKillOff_evenForSuperadmin() {
        globalAdmin(true, false); // dangerous tier OFF
        var d = authz.decide(WorkloadScopeFixtures.superadminAuth(), DangerTier.DANGEROUS,
                false, true, "tok").block();
        assertThat(d.allow()).isFalse();
        assertThat(d.notFound()).isFalse(); // 403, explicit refusal
    }

    @Test
    void superadmin_dangerous_deniedWithoutStepUp_whenGlobalKillOn() {
        globalAdmin(true, true); // dangerous tier ON
        when(stepUp.validate(anyString(), any())).thenReturn(false);
        var d = authz.decide(WorkloadScopeFixtures.superadminAuth(), DangerTier.DANGEROUS,
                false, true, "bad").block();
        assertThat(d.allow()).isFalse();
    }

    @Test
    void superadmin_dangerous_allowedWithStepUp_whenGlobalKillOn() {
        globalAdmin(true, true);
        when(stepUp.validate(anyString(), any())).thenReturn(true);
        var d = authz.decide(WorkloadScopeFixtures.superadminAuth(), DangerTier.DANGEROUS,
                false, true, "good").block();
        assertThat(d.allow()).isTrue();
    }

    // ── STEP 1 — superadmin suspension key (A3: statusFor must key on the identity-claim
    //    handle suspension rows are stored under, NEVER the opaque Casdoor sub) ──────

    private static AccountStatus suspended() {
        return new AccountStatus(AccountStatus.SUSPENDED,
                Instant.now().plus(1, ChronoUnit.HOURS), "abuse");
    }

    @Test
    void superadmin_read_denied_whenSuspendedUnderTheEmailHandle() {
        // The suspension row is keyed on the person's handle (email) — the opaque Casdoor
        // sub matches no row. Pre-fix this failed OPEN (statusFor(sub) -> active -> allow).
        when(suspensions.statusFor(eq("root@brandx.example"))).thenReturn(Mono.just(suspended()));
        var d = authz.decide(WorkloadScopeFixtures.superadminEmailAuth(), DangerTier.READ,
                false, true, null).block();
        assertThat(d.allow()).isFalse();
        assertThat(d.notFound()).isFalse(); // 403 "superadmin session is suspended"
    }

    @Test
    void superadmin_suspensionCheck_keysOnTheEmailHandle_neverTheSub() {
        var d = authz.decide(WorkloadScopeFixtures.superadminEmailAuth(), DangerTier.READ,
                false, true, null).block();
        assertThat(d.allow()).isTrue(); // not suspended anywhere -> still allowed (no false-suspend)
        verify(suspensions).statusFor("root@brandx.example");
        verify(suspensions, never()).statusFor("casdoor-uuid-123");
    }

    @Test
    void superadmin_read_denied_whenSuspendedUnderThePreferredUsernameHandle() {
        // Discord shape: no email claim — preferred_username is the handle native login keys on.
        when(suspensions.statusFor(eq("root-discord"))).thenReturn(Mono.just(suspended()));
        var d = authz.decide(WorkloadScopeFixtures.superadminPreferredUsernameAuth(), DangerTier.READ,
                false, true, null).block();
        assertThat(d.allow()).isFalse();
        assertThat(d.notFound()).isFalse();
    }

    @Test
    void superadmin_suspensionCheck_fallsBackToTheSub_whenNoIdentityClaims() {
        // A claims-less JWT (the pre-native synthetic shape) behaves exactly as before: keyed
        // on the sub, both for the lookup and for a suspension row stored under it.
        var allowed = authz.decide(WorkloadScopeFixtures.superadminAuth(), DangerTier.READ,
                false, true, null).block();
        assertThat(allowed.allow()).isTrue();
        verify(suspensions).statusFor("root");

        when(suspensions.statusFor(eq("root"))).thenReturn(Mono.just(suspended()));
        var denied = authz.decide(WorkloadScopeFixtures.superadminAuth(), DangerTier.READ,
                false, true, null).block();
        assertThat(denied.allow()).isFalse();
        assertThat(denied.notFound()).isFalse();
    }

    @Test
    void superadmin_stepUp_staysKeyedOnTheSub_notTheEmailHandle() {
        // Step-up tokens are minted under jwt.getSubject() — the suspension-key fix must NOT
        // move this. The default anyString() stub returns false, so the allow proves the
        // validate call carried the sub.
        globalAdmin(true, true);
        when(stepUp.validate(eq("casdoor-uuid-123"), any())).thenReturn(true);
        var d = authz.decide(WorkloadScopeFixtures.superadminEmailAuth(), DangerTier.DANGEROUS,
                false, true, "good").block();
        assertThat(d.allow()).isTrue();
        verify(stepUp).validate("casdoor-uuid-123", "good");
    }

    // ── STEP 2 — non-admin ───────────────────────────────────────────────────────

    @Test
    void user_read_deniedNotFound() {
        var d = authz.decide(WorkloadScopeFixtures.userAuth("brandx"), DangerTier.READ, false, true, null)
                .block();
        assertThat(d.allow()).isFalse();
        assertThat(d.notFound()).isTrue();
    }

    // ── STEP 3 — non-SA can NEVER reach mutate/dangerous (tier, not verb) ──────────

    @Test
    void admin_runtimeMutate_deniedNotFound_evenWithGrant() {
        globalAdmin(true, false);
        activeGrant("admin-brandx", "brandx", true);
        var d = authz.decide(WorkloadScopeFixtures.adminAuth("brandx"), DangerTier.RUNTIME_MUTATE,
                false, true, null).block();
        assertThat(d.allow()).isFalse();
        assertThat(d.notFound()).isTrue();
    }

    @Test
    void admin_dangerous_deniedNotFound() {
        globalAdmin(true, true);
        activeGrant("admin-brandx", "brandx", true);
        var d = authz.decide(WorkloadScopeFixtures.adminAuth("brandx"), DangerTier.DANGEROUS,
                false, true, null).block();
        assertThat(d.allow()).isFalse();
        assertThat(d.notFound()).isTrue();
    }

    // ── STEP 4 — GLOBAL admin kill ─────────────────────────────────────────────────

    @Test
    void admin_read_deniedWhenGlobalAdminOff() {
        globalAdmin(false, false);
        activeGrant("admin-brandx", "brandx", false);
        var d = authz.decide(WorkloadScopeFixtures.adminAuth("brandx"), DangerTier.READ, false, true, null)
                .block();
        assertThat(d.allow()).isFalse();
        assertThat(d.notFound()).isTrue();
    }

    // ── STEP 5 — per-domain master ─────────────────────────────────────────────────

    @Test
    void admin_read_deniedWhenPerDomainOff() {
        globalAdmin(true, false);
        perDomain("brandx", false);
        activeGrant("admin-brandx", "brandx", false);
        var d = authz.decide(WorkloadScopeFixtures.adminAuth("brandx"), DangerTier.READ, false, true, null)
                .block();
        assertThat(d.allow()).isFalse();
        assertThat(d.notFound()).isTrue();
    }

    // ── STEP 6 — active grant ──────────────────────────────────────────────────────

    @Test
    void admin_read_allowedWithGlobalOnAndGrant() {
        globalAdmin(true, false);
        activeGrant("admin-brandx", "brandx", false);
        var d = authz.decide(WorkloadScopeFixtures.adminAuth("brandx"), DangerTier.READ, false, true, null)
                .block();
        assertThat(d.allow()).isTrue();
        assertThat(d.superadmin()).isFalse();
    }

    @Test
    void admin_read_grantMatch_staysKeyedOnTheSub_whenEmailClaimPresent() {
        // Grants are minted under jwt.getSubject(); an email claim on the JWT must not move
        // the STEP-6 grant match off the sub (the A3 fix rekeys ONLY the suspension lookup).
        globalAdmin(true, false);
        activeGrant("admin-brandx", "brandx", false);
        var d = authz.decide(WorkloadScopeFixtures.adminEmailAuth("brandx"), DangerTier.READ,
                false, true, null).block();
        assertThat(d.allow()).isTrue();
        verify(grants).findActive("admin-brandx", "brandx");
    }

    @Test
    void admin_read_deniedWithoutGrant_evenWhenGlobalOn() {
        globalAdmin(true, false);
        // no grant stubbed (default empty)
        var d = authz.decide(WorkloadScopeFixtures.adminAuth("brandx"), DangerTier.READ, false, true, null)
                .block();
        assertThat(d.allow()).isFalse();
        assertThat(d.notFound()).isTrue();
    }

    @Test
    void admin_logBody_deniedWhenGrantHasNoLogAccess() {
        globalAdmin(true, false);
        activeGrant("admin-brandx", "brandx", false); // log_access = false
        var d = authz.decide(WorkloadScopeFixtures.adminAuth("brandx"), DangerTier.READ,
                true /* logPath */, true, null).block();
        assertThat(d.allow()).isFalse();
        assertThat(d.notFound()).isTrue();
    }

    @Test
    void admin_logBody_allowedWhenGrantHasLogAccess() {
        globalAdmin(true, false);
        activeGrant("admin-brandx", "brandx", true); // log_access = true
        var d = authz.decide(WorkloadScopeFixtures.adminAuth("brandx"), DangerTier.READ,
                true, true, null).block();
        assertThat(d.allow()).isTrue();
    }

    // ── STEP 0b — namespace allowlist ──────────────────────────────────────────────

    @Test
    void anyTier_deniedWhenNamespaceNotAllowed() {
        globalAdmin(true, false);
        activeGrant("admin-brandx", "brandx", false);
        var d = authz.decide(WorkloadScopeFixtures.adminAuth("brandx"), DangerTier.READ,
                false, false /* namespace NOT ok */, null).block();
        assertThat(d.allow()).isFalse();
        assertThat(d.notFound()).isFalse(); // 403 probe
    }
}
