package net.hugmesh.adminbff.mfa;

import net.hugmesh.commons.web.ApiException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The resolver + floor semantics of {@link RoleMfaPolicyService}, in isolation from the store.
 *
 * <p>Three things are load-bearing and each is mutation-resistant against the obvious edit:
 * <ol>
 *   <li><b>Defaults</b> — with an EMPTY table the four canonical roles resolve exactly the
 *       issue's stated defaults (superadmin/admin true, mod/user false) and an unknown role is
 *       {@code false}. Flip any entry in {@code DEFAULT_REQUIRED} and a test goes red.</li>
 *   <li><b>The floor is not relaxable</b> — a row that says {@code admin required=false}
 *       still resolves {@code true}; a write that tries to set it is refused BEFORE the store
 *       is touched ({@code verify(repo, never()).upsert(...)}). Delete the floor branch in
 *       either place and the corresponding test goes red.</li>
 *   <li><b>{@code requiredForAny} is an OR</b> across the principal's roles, with a
 *       no-read short-circuit for floor roles and a {@code false} answer for an empty set.</li>
 * </ol>
 */
class RoleMfaPolicyServiceTest {

    RoleMfaPolicyR2dbcRepository repo;
    RoleMfaPolicyService service;

    @BeforeEach
    void setUp() {
        repo = mock(RoleMfaPolicyR2dbcRepository.class);
        service = new RoleMfaPolicyService(repo);
        // Empty table unless a test says otherwise.
        when(repo.findByDomainAndRole(anyString(), anyString())).thenReturn(Mono.empty());
        when(repo.findByDomainOrderByRole(anyString())).thenReturn(Flux.empty());
        when(repo.findByDomainAndRoleIn(anyString(), any())).thenReturn(Flux.empty());
        when(repo.upsert(anyString(), anyString(), anyString(), anyBoolean(), any(), anyLong(), any()))
                .thenReturn(Mono.just(1L));
    }

    private static RoleMfaPolicyRow row(String domain, String role, boolean required, String methods, long grace) {
        return new RoleMfaPolicyRow("id-" + role, domain, role, required, methods, grace, "alice", LocalDateTime.now());
    }

    // ── defaults ──────────────────────────────────────────────────────────────────

    @Test
    void emptyTable_resolvesTheIssueStatedDefaults() {
        assertThat(service.effectiveFor("brandx", "superadmin").block().required()).isTrue();
        assertThat(service.effectiveFor("brandx", "admin").block().required()).isTrue();
        assertThat(service.effectiveFor("brandx", "mod").block().required()).isFalse();
        assertThat(service.effectiveFor("brandx", "user").block().required()).isFalse();
        // An unknown role is the SAFER false (no lockout of a role nobody enrolled).
        assertThat(service.effectiveFor("brandx", "fleet_admin").block().required()).isFalse();
    }

    @Test
    void defaults_areMarkedAsDefaults_notRows_andCarryTheFloorFlag() {
        RoleMfaPolicy admin = service.effectiveFor("brandx", "admin").block();
        assertThat(admin.fromRow()).isFalse();
        assertThat(admin.floor()).isTrue();
        assertThat(admin.methods()).isEmpty();
        assertThat(admin.graceSeconds()).isZero();

        RoleMfaPolicy mod = service.effectiveFor("brandx", "mod").block();
        assertThat(mod.fromRow()).isFalse();
        assertThat(mod.floor()).isFalse();
    }

    @Test
    void listEffective_reportsTheFourCanonicalRoles_evenOnAnEmptyTable() {
        List<RoleMfaPolicy> list = service.listEffective("brandx").collectList().block();
        assertThat(list).extracting(RoleMfaPolicy::role)
                .containsExactly("superadmin", "admin", "mod", "user");
        assertThat(list).extracting(RoleMfaPolicy::required)
                .containsExactly(true, true, false, false);
    }

    @Test
    void listEffective_rowOverridesADefault_andExtraRolesAppendAfterTheCanonicalFour() {
        when(repo.findByDomainOrderByRole("brandx")).thenReturn(Flux.just(
                row("brandx", "fleet_admin", true, "webauthn", 60),
                row("brandx", "mod", true, "webauthn,otp", 300)));
        List<RoleMfaPolicy> list = service.listEffective("brandx").collectList().block();
        assertThat(list).extracting(RoleMfaPolicy::role)
                .containsExactly("superadmin", "admin", "mod", "user", "fleet_admin");
        RoleMfaPolicy mod = list.get(2);
        assertThat(mod.required()).isTrue();
        assertThat(mod.fromRow()).isTrue();
        assertThat(mod.methods()).containsExactly("webauthn", "otp");
        assertThat(mod.graceSeconds()).isEqualTo(300);
        assertThat(mod.updatedBy()).isEqualTo("alice");
    }

    // ── the floor ─────────────────────────────────────────────────────────────────

    @Test
    void floor_aRowRelaxingAdmin_stillResolvesRequired() {
        when(repo.findByDomainAndRole("brandx", "admin"))
                .thenReturn(Mono.just(row("brandx", "admin", false, null, 0)));
        RoleMfaPolicy admin = service.effectiveFor("brandx", "admin").block();
        assertThat(admin.required()).as("hand-edited row must not relax the floor").isTrue();
        assertThat(admin.fromRow()).isTrue();
        assertThat(admin.floor()).isTrue();
    }

    @Test
    void floor_aRowRelaxingSuperadmin_stillResolvesRequired() {
        when(repo.findByDomainAndRole("brandx", "superadmin"))
                .thenReturn(Mono.just(row("brandx", "superadmin", false, null, 0)));
        assertThat(service.effectiveFor("brandx", "superadmin").block().required()).isTrue();
    }

    @Test
    void upsert_relaxingAFloorRole_isRefusedBeforeAnyWrite() {
        StepVerifier.create(service.upsert("brandx", "admin", false, List.of(), 0, "alice"))
                .expectErrorSatisfies(e -> {
                    assertThat(e).isInstanceOf(ApiException.class);
                    assertThat(e.getMessage()).contains("privileged MFA floor");
                })
                .verify();
        verify(repo, never()).upsert(anyString(), anyString(), anyString(), anyBoolean(), any(), anyLong(), any());
    }

    @Test
    void upsert_aFloorRoleWithRequiredTrue_isAllowed_andMayCarryMethodsAndGrace() {
        when(repo.findByDomainAndRole("brandx", "admin"))
                .thenReturn(Mono.just(row("brandx", "admin", true, "webauthn", 120)));
        RoleMfaPolicy out = service.upsert("brandx", "admin", true, List.of("webauthn"), 120, "alice").block();
        verify(repo).upsert(anyString(), eq("brandx"), eq("admin"), eq(true), eq("webauthn"), eq(120L), eq("alice"));
        assertThat(out.required()).isTrue();
        assertThat(out.methods()).containsExactly("webauthn");
    }

    // ── the write path: validation ────────────────────────────────────────────────

    @Test
    void upsert_relaxableRole_writesNullMethodsForAny_andReadsBack() {
        when(repo.findByDomainAndRole("brandx", "mod"))
                .thenReturn(Mono.just(row("brandx", "mod", true, null, 0)));
        RoleMfaPolicy out = service.upsert("brandx", "mod", true, List.of(), 0, "alice").block();
        // empty methods -> NULL in the row (= any), never an empty string.
        verify(repo).upsert(anyString(), eq("brandx"), eq("mod"), eq(true), isNull(), eq(0L), eq("alice"));
        assertThat(out.required()).isTrue();
        assertThat(out.methods()).isEmpty();
    }

    @Test
    void upsert_unknownMethod_isRefused_failClosed() {
        StepVerifier.create(service.upsert("brandx", "mod", true, List.of("sms"), 0, "alice"))
                .expectErrorSatisfies(e -> assertThat(e.getMessage()).contains("unknown MFA method 'sms'"))
                .verify();
        verify(repo, never()).upsert(anyString(), anyString(), anyString(), anyBoolean(), any(), anyLong(), any());
    }

    @Test
    void upsert_methodsAreFoldedAndDeduplicated() {
        when(repo.findByDomainAndRole("brandx", "mod"))
                .thenReturn(Mono.just(row("brandx", "mod", true, "webauthn,otp", 0)));
        service.upsert("brandx", "mod", true, List.of("WebAuthn", "otp", "webauthn"), 0, "alice").block();
        verify(repo).upsert(anyString(), eq("brandx"), eq("mod"), eq(true), eq("webauthn,otp"), eq(0L), eq("alice"));
    }

    @Test
    void upsert_graceOutOfBounds_isRefused() {
        StepVerifier.create(service.upsert("brandx", "mod", true, List.of(), -1, "alice"))
                .expectError(ApiException.class).verify();
        StepVerifier.create(service.upsert("brandx", "mod", true, List.of(),
                        RoleMfaPolicyService.MAX_GRACE_SECONDS + 1, "alice"))
                .expectError(ApiException.class).verify();
        verify(repo, never()).upsert(anyString(), anyString(), anyString(), anyBoolean(), any(), anyLong(), any());
    }

    @Test
    void upsert_badRoleShape_isRefused() {
        StepVerifier.create(service.upsert("brandx", "Sp ace", true, List.of(), 0, "alice"))
                .expectError(ApiException.class).verify();
        verify(repo, never()).upsert(anyString(), anyString(), anyString(), anyBoolean(), any(), anyLong(), any());
    }

    @Test
    void roles_areNormalised_authorityPrefixAndCaseFold() {
        assertThat(RoleMfaPolicyService.normaliseRole("ROLE_ADMIN")).isEqualTo("admin");
        assertThat(RoleMfaPolicyService.normaliseRole("Mod")).isEqualTo("mod");
        assertThat(RoleMfaPolicyService.normaliseRole(" user ")).isEqualTo("user");
        assertThat(RoleMfaPolicyService.normaliseRole(null)).isEmpty();
    }

    // ── requiredForAny ────────────────────────────────────────────────────────────

    @Test
    void requiredForAny_emptyOrNullRoles_isFalse_withoutAStoreRead() {
        assertThat(service.requiredForAny("brandx", List.of()).block()).isFalse();
        assertThat(service.requiredForAny("brandx", null).block()).isFalse();
        verify(repo, never()).findByDomainAndRoleIn(anyString(), any());
    }

    @Test
    void requiredForAny_floorRole_shortCircuitsTrue_withoutAStoreRead() {
        assertThat(service.requiredForAny("brandx", List.of("user", "ROLE_ADMIN")).block()).isTrue();
        verify(repo, never()).findByDomainAndRoleIn(anyString(), any());
    }

    @Test
    void requiredForAny_isAnOrAcrossRoles_rowsOverrideDefaults() {
        // defaults only: user + mod -> false
        assertThat(service.requiredForAny("brandx", List.of("user", "mod")).block()).isFalse();
        // a row flips mod on -> true
        when(repo.findByDomainAndRoleIn(eq("brandx"), any()))
                .thenReturn(Flux.just(row("brandx", "mod", true, null, 0)));
        assertThat(service.requiredForAny("brandx", List.of("user", "mod")).block()).isTrue();
        // BOTH calls above read the store with exactly the normalised role set — never a
        // floor short-circuit, never a whole-table read. Two calls, so two identical reads.
        verify(repo, times(2)).findByDomainAndRoleIn(eq("brandx"), eq(Set.of("user", "mod")));
    }

    @Test
    void requiredForAny_aRowCannotRelaxADefaultTrueBelowTheFloor_becauseFloorNeverReads() {
        // Even a table full of required=false rows for admin cannot be consulted: the floor
        // answers first. (The store stub would return false rows if it were asked.)
        when(repo.findByDomainAndRoleIn(anyString(), any()))
                .thenReturn(Flux.just(row("brandx", "admin", false, null, 0)));
        assertThat(service.requiredForAny("brandx", List.of("admin")).block()).isTrue();
        verify(repo, never()).findByDomainAndRoleIn(anyString(), any());
    }
}
