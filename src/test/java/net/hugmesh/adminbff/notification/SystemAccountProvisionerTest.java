package net.hugmesh.adminbff.notification;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import reactor.core.publisher.Mono;
import net.hugmesh.authcore.casdoor.CasdoorAdminClient;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Unit coverage for {@link SystemAccountProvisioner} — the per-domain {@code @system}
 * infra-account provisioner (Notifications PR3). The provisioner delegates to the
 * already-verified {@link CasdoorAdminClient#ensureUser}, so these tests mock that client
 * and assert the EXACT arguments the provisioner passes (the load-bearing contract).
 *
 * <p>The acceptance bar:
 * <ul>
 *   <li><b>LEAST PRIVILEGE</b> — {@code ensureUser} is called with EXACTLY
 *       {@code [user, matrix, mastodon]} and NEVER {@code admin} / {@code superadmin} /
 *       {@code mod}. This is the key regression guard.</li>
 *   <li><b>IDEMPOTENT</b> — the delegate is the idempotent {@code ensureUser}; provisioning
 *       twice issues two no-op-equivalent calls and never errors.</li>
 *   <li><b>SHIPS DARK</b> — with no Casdoor client wired the provisioner no-ops, makes NO
 *       call, and {@link SystemAccountProvisioner#enabled()} is false.</li>
 *   <li><b>PER-DOMAIN</b> — the handle / email / provider are derived from the domain, so
 *       provisioning domain X never references domain Y.</li>
 * </ul>
 */
class SystemAccountProvisionerTest {

    // ── LEAST PRIVILEGE — the load-bearing assertion ────────────────────────────

    @Test
    void systemRoles_areExactlyUserMatrixMastodon_andNeverPrivileged() {
        assertThat(SystemAccountProvisioner.SYSTEM_ROLES)
                .containsExactly("user", "matrix", "mastodon");
        assertThat(SystemAccountProvisioner.SYSTEM_ROLES)
                .doesNotContain("admin", "superadmin", "mod");
        assertThat(SystemAccountProvisioner.FORBIDDEN_ROLES)
                .containsExactly("admin", "superadmin", "mod");
        // The two sets are disjoint — the shipped constant can never hold a privileged role.
        assertThat(SystemAccountProvisioner.SYSTEM_ROLES)
                .noneMatch(SystemAccountProvisioner.FORBIDDEN_ROLES::contains);
    }

    @Test
    @SuppressWarnings("unchecked")
    void provision_callsEnsureUser_withExactlyUserMatrixMastodon_neverAdminSuperadminMod() {
        CasdoorAdminClient casdoor = mock(CasdoorAdminClient.class);
        when(casdoor.ensureUser(anyString(), anyString(), anyString(), anyList()))
                .thenReturn(Mono.empty());
        SystemAccountProvisioner provisioner = new SystemAccountProvisioner(casdoor);

        provisioner.provision("acme.test").block();

        ArgumentCaptor<String> provider = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> handle = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> email = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<List<String>> roles = ArgumentCaptor.forClass(List.class);
        verify(casdoor).ensureUser(provider.capture(), handle.capture(), email.capture(), roles.capture());

        // The neutral sender handle + the per-domain provider/email.
        assertThat(handle.getValue()).isEqualTo("system");
        assertThat(email.getValue()).isEqualTo("system@acme.test");
        assertThat(provider.getValue()).isEqualTo("acme.test");
        // The KEY security property: EXACTLY the least-privilege role set, never privileged.
        assertThat(roles.getValue()).containsExactly("user", "matrix", "mastodon");
        assertThat(roles.getValue()).doesNotContain("admin", "superadmin", "mod");
    }

    // ── IDEMPOTENT ──────────────────────────────────────────────────────────────

    @Test
    void provision_twice_isNoOp_delegatesToIdempotentEnsureUser_noError() {
        CasdoorAdminClient casdoor = mock(CasdoorAdminClient.class);
        when(casdoor.ensureUser(anyString(), anyString(), anyString(), anyList()))
                .thenReturn(Mono.empty());
        SystemAccountProvisioner provisioner = new SystemAccountProvisioner(casdoor);

        provisioner.provision("acme.test").block();
        provisioner.provision("acme.test").block();   // must not throw

        // Each call delegates to the idempotent ensureUser with the SAME least-privilege
        // args (ensureUser itself is get-then-add, so the second is a no-op effect).
        verify(casdoor, times(2)).ensureUser(eq("acme.test"), eq("system"),
                eq("system@acme.test"), eq(List.of("user", "matrix", "mastodon")));
    }

    // ── SHIPS DARK ──────────────────────────────────────────────────────────────

    @Test
    void provision_shipsDark_whenNoCasdoorClient_noOpAndNoCall() {
        // casdoor.admin.enabled=false → the CasdoorAdminClient bean is absent → null here.
        SystemAccountProvisioner provisioner = new SystemAccountProvisioner(null);
        assertThat(provisioner.enabled()).isFalse();
        // Completes empty, issues no call, never throws.
        provisioner.provision("acme.test").block();
    }

    @Test
    void provision_enabled_isTrue_whenCasdoorClientWired() {
        SystemAccountProvisioner provisioner =
                new SystemAccountProvisioner(mock(CasdoorAdminClient.class));
        assertThat(provisioner.enabled()).isTrue();
    }

    @Test
    void provision_blankDomain_isRejected_andNeverCalls() {
        CasdoorAdminClient casdoor = mock(CasdoorAdminClient.class);
        SystemAccountProvisioner provisioner = new SystemAccountProvisioner(casdoor);
        assertThatThrownBy(() -> provisioner.provision("   ").block())
                .isInstanceOf(IllegalArgumentException.class);
        verifyNoInteractions(casdoor);
    }

    // ── PER-DOMAIN ──────────────────────────────────────────────────────────────

    @Test
    void systemEmail_isDerivedPerDomain() {
        assertThat(SystemAccountProvisioner.systemEmail("acme.test")).isEqualTo("system@acme.test");
        assertThat(SystemAccountProvisioner.systemEmail("beta.test")).isEqualTo("system@beta.test");
    }

    @Test
    void provision_domainX_doesNotReferenceDomainY() {
        CasdoorAdminClient casdoor = mock(CasdoorAdminClient.class);
        when(casdoor.ensureUser(anyString(), anyString(), anyString(), anyList()))
                .thenReturn(Mono.empty());
        SystemAccountProvisioner provisioner = new SystemAccountProvisioner(casdoor);

        provisioner.provision("acme.test").block();

        // Only acme.test was provisioned; no beta.test identity ever passed to ensureUser.
        verify(casdoor).ensureUser(eq("acme.test"), eq("system"), eq("system@acme.test"), anyList());
        verify(casdoor, never()).ensureUser(eq("beta.test"), anyString(), anyString(), anyList());
        verify(casdoor, never()).ensureUser(anyString(), anyString(), eq("system@beta.test"), anyList());
        // Defensive: no stray ensureUser calls beyond the one for acme.test.
        verify(casdoor, times(1)).ensureUser(anyString(), anyString(), anyString(), anyList());
    }
}
