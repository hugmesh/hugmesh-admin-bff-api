package net.hugmesh.adminbff.oidcprovider;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import net.hugmesh.authcore.casdoor.CasdoorAdminClient;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit test for {@link OidcFirstLoginController} — the "apply" half of the OIDC default-role
 * registration hook. Drives the controller directly with a mocked
 * {@link OidcProviderRoleRepository} and a mocked / {@code null} {@link CasdoorAdminClient}
 * (the dark-default dry-run), asserting the four behaviours that matter:
 * <ul>
 *   <li>DRY-RUN (Casdoor disabled): the map is read but NOTHING is written, {@code assignedRoles:[]};</li>
 *   <li>APPLY: each stored lowercase role is added under its {@code ROLE_}-prefixed Casdoor name,
 *       keyed {@code org/username}, and the stored names are reported back;</li>
 *   <li>EMPTY map: no Casdoor writes, {@code assignedRoles:[]};</li>
 *   <li>PER-ROLE isolation: one failing role is skipped, the rest still apply (additive, fail-safe).</li>
 * </ul>
 */
class OidcFirstLoginControllerTest {

    private final OidcProviderRoleRepository roles = mock(OidcProviderRoleRepository.class);

    private static OidcFirstLoginController.FirstLoginRequest req(String domain, String provider, String user) {
        return new OidcFirstLoginController.FirstLoginRequest(domain, provider, user);
    }

    @Test
    void dryRun_whenCasdoorDisabled_resolvesMapButWritesNothing() {
        when(roles.rolesFor("default", "google")).thenReturn(Flux.just("user", "mod"));
        OidcFirstLoginController controller = new OidcFirstLoginController(roles, null); // casdoor disabled

        StepVerifier.create(controller.firstLogin(req("default", "google", "alice")))
                .assertNext(resp -> assertThat(resp.assignedRoles()).isEmpty())
                .verifyComplete();

        verify(roles).rolesFor("default", "google"); // read path still exercised in dry-run
    }

    @Test
    void apply_addsEachStoredRole_underItsRolePrefixedCasdoorName() {
        CasdoorAdminClient casdoor = mock(CasdoorAdminClient.class);
        when(casdoor.organization()).thenReturn("hugmesh");
        when(casdoor.addUserToRole(anyString(), anyString())).thenReturn(Mono.empty());
        when(roles.rolesFor("default", "google")).thenReturn(Flux.just("user", "games_admin"));
        OidcFirstLoginController controller = new OidcFirstLoginController(roles, casdoor);

        // provider folded to lowercase ("GOOGLE" -> "google").
        StepVerifier.create(controller.firstLogin(req("default", "GOOGLE", "alice")))
                .assertNext(resp -> assertThat(resp.assignedRoles()).containsExactly("user", "games_admin"))
                .verifyComplete();

        // lowercase stored name -> ROLE_<UPPER>, keyed org/username.
        verify(casdoor).addUserToRole("ROLE_USER", "hugmesh/alice");
        verify(casdoor).addUserToRole("ROLE_GAMES_ADMIN", "hugmesh/alice");
    }

    @Test
    void apply_emptyMap_returnsEmpty_andWritesNothing() {
        CasdoorAdminClient casdoor = mock(CasdoorAdminClient.class);
        when(casdoor.organization()).thenReturn("hugmesh");
        when(roles.rolesFor("default", "github")).thenReturn(Flux.empty());
        OidcFirstLoginController controller = new OidcFirstLoginController(roles, casdoor);

        StepVerifier.create(controller.firstLogin(req("default", "github", "bob")))
                .assertNext(resp -> assertThat(resp.assignedRoles()).isEmpty())
                .verifyComplete();

        verify(casdoor, never()).addUserToRole(anyString(), anyString());
    }

    @Test
    void apply_reservedRolesSkipped_evenIfStaleRowCarriesThem_defenseInDepth() {
        // DEFENSE-IN-DEPTH (findings #1 / #8): a stale or directly-seeded row may carry a
        // reserved / bootstrap role that predates the write-path denylist. The first-login hook
        // must STILL refuse to apply it — superadmin + service/bootstrap roles are never granted
        // via this channel, while legitimate roles (user, plain admin) still apply.
        CasdoorAdminClient casdoor = mock(CasdoorAdminClient.class);
        when(casdoor.organization()).thenReturn("hugmesh");
        when(casdoor.addUserToRole(anyString(), anyString())).thenReturn(Mono.empty());
        when(roles.rolesFor("default", "google"))
                .thenReturn(Flux.just("user", "superadmin", "gateway", "admin-api", "admin"));
        OidcFirstLoginController controller = new OidcFirstLoginController(roles, casdoor);

        // only 'user' and 'admin' apply; the reserved roles are filtered before addUserToRole.
        StepVerifier.create(controller.firstLogin(req("default", "google", "alice")))
                .assertNext(resp -> assertThat(resp.assignedRoles()).containsExactly("user", "admin"))
                .verifyComplete();

        verify(casdoor).addUserToRole("ROLE_USER", "hugmesh/alice");
        verify(casdoor).addUserToRole("ROLE_ADMIN", "hugmesh/alice");
        // the reserved escalation roles must NEVER be sent to Casdoor.
        verify(casdoor, never()).addUserToRole(eq("ROLE_SUPERADMIN"), anyString());
        verify(casdoor, never()).addUserToRole(eq("ROLE_GATEWAY"), anyString());
        verify(casdoor, never()).addUserToRole(eq("ROLE_ADMIN_API"), anyString());
    }

    @Test
    void apply_oneRoleFails_othersStillApplied_failSafe() {
        CasdoorAdminClient casdoor = mock(CasdoorAdminClient.class);
        when(casdoor.organization()).thenReturn("hugmesh");
        when(casdoor.addUserToRole(eq("ROLE_USER"), anyString())).thenReturn(Mono.empty());
        when(casdoor.addUserToRole(eq("ROLE_MOD"), anyString()))
                .thenReturn(Mono.error(new RuntimeException("casdoor: role not found")));
        when(casdoor.addUserToRole(eq("ROLE_ADMIN"), anyString())).thenReturn(Mono.empty());
        when(roles.rolesFor("default", "google")).thenReturn(Flux.just("user", "mod", "admin"));
        OidcFirstLoginController controller = new OidcFirstLoginController(roles, casdoor);

        // 'mod' errors -> skipped; 'user' + 'admin' still applied, in order.
        StepVerifier.create(controller.firstLogin(req("default", "google", "alice")))
                .assertNext(resp -> assertThat(resp.assignedRoles()).containsExactly("user", "admin"))
                .verifyComplete();
    }
}
