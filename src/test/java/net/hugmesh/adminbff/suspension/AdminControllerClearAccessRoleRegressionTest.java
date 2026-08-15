package net.hugmesh.adminbff.suspension;

import io.r2dbc.spi.ConnectionFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.r2dbc.connection.R2dbcTransactionManager;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.AdminController;
import net.hugmesh.adminbff.notification.NotificationOutboxR2dbcRepository;
import net.hugmesh.adminbff.notification.NotificationOutboxRepository;
import net.hugmesh.adminbff.support.AdminBffPostgresTestSupport;
import net.hugmesh.adminbff.testutil.R2dbcRepos;
import net.hugmesh.authcore.account.AccountStore;
import net.hugmesh.authcore.casdoor.CasdoorAdminClient;
import net.hugmesh.adminbff.domainlock.DomainLockService;
import net.hugmesh.adminbff.federation.FederationApiClient;
import net.hugmesh.adminbff.iso.IsoRepository;
import net.hugmesh.adminbff.routeaccess.RouteAccessService;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.PrincipalDomain;
import net.hugmesh.adminbff.urlregistry.UrlRegistryService;
import net.hugmesh.adminbff.usage.UsageService;
import net.hugmesh.authcore.provision.GatewayRevocationClient;
import net.hugmesh.authcore.username.UsernameGate;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Regression coverage for the direct admin "lift ban" endpoint
 * ({@code DELETE /bff/admin/access-roles/{role}/{user}} — {@link AdminController#clearAccessRole})
 * against a REAL {@link SuspensionService} bound to a real Postgres store (mirrors the
 * {@link SuspensionServiceDomainScopeTest.ClearByHandle} pattern from PR #189, but drives the
 * actual controller method rather than the service directly — proving the WIRING is fixed,
 * not just the underlying {@code clearByHandle} primitive).
 *
 * <p>Pre-fix, {@link AdminController#clearAccessRole} called the exact-string
 * {@link SuspensionService#clear}: an admin lifting a ban by typing a DIFFERENT string form of
 * the user's identity than whatever string form the ban was originally set with would silently
 * no-op — the endpoint reports success (200, empty diff) while the ban stays active. This test
 * proves the fix: banning under one string form and lifting via
 * {@link AdminController#clearAccessRole} with a different string form of the SAME identity
 * actually clears the row.
 */
@SpringBootTest(classes = AdminControllerClearAccessRoleRegressionTest.Boot.class)
@ActiveProfiles("test")
class AdminControllerClearAccessRoleRegressionTest extends AdminBffPostgresTestSupport {

    @SpringBootConfiguration
    @EnableAutoConfiguration
    static class Boot { }

    @Autowired DatabaseClient db;
    @Autowired ConnectionFactory connectionFactory;

    @BeforeEach
    void clearTables() {
        db.sql("DELETE FROM access_suspension").fetch().rowsUpdated().block();
        db.sql("DELETE FROM notification_outbox").fetch().rowsUpdated().block();
    }

    private static final DomainRegistry REGISTRY =
            new DomainRegistry("", "https://idp.brandx.example=brandx");
    private static final String BRANDX = "https://idp.brandx.example";

    private SuspensionService realSuspensionService() {
        AccessSyncActions actions = mock(AccessSyncActions.class);
        when(actions.triggerTick()).thenReturn(Mono.empty());
        TransactionalOperator tx = TransactionalOperator.create(new R2dbcTransactionManager(connectionFactory));
        return new SuspensionService(
                new AccessSuspensionRepository(R2dbcRepos.of(db, AccessSuspensionRowRepository.class)),
                actions,
                new NotificationOutboxRepository(R2dbcRepos.of(db, NotificationOutboxR2dbcRepository.class)),
                tx);
    }

    private AdminController controller(SuspensionService suspensions) {
        UsageService usage = mock(UsageService.class);
        when(usage.record(anyString(), anyList(), anyString())).thenReturn(Mono.empty());
        return new AdminController(
                mock(AccountStore.class),
                mock(RouteAccessService.class),
                mock(UrlRegistryService.class),
                mock(IsoRepository.class),
                usage,
                suspensions,
                mock(DomainLockService.class),
                mock(UsernameGate.class),
                REGISTRY,
                mock(FederationApiClient.class),
                mock(GatewayRevocationClient.class),
                mock(net.hugmesh.adminbff.capability.DomainCapabilityService.class),
                mock(CasdoorAdminClient.class));
    }

    private static JwtAuthenticationToken adminAuth(String issuer) {
        Jwt jwt = Jwt.withTokenValue("t").header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                .subject("admin-x").issuer(issuer).claim("roles", List.of("admin")).build();
        return new JwtAuthenticationToken(jwt,
                List.of(new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    @Test
    void clearAccessRole_findsAndClears_evenWhenBannedUnderADifferentStringForm_thanWhatTheAdminTypesToLiftIt() {
        SuspensionService suspensions = realSuspensionService();
        AdminController controller = controller(suspensions);
        JwtAuthenticationToken auth = adminAuth(BRANDX);
        PrincipalDomain scope = PrincipalDomain.of(auth, REGISTRY);

        // Originally banned under the full "provider:handle" free-text form.
        suspensions.suspend(AccessSuspension.ROLE_PROFILE, "google:alice@x.com", null, "abuse", "admin", scope).block();

        // The admin now lifts the ban typing only the bare handle "alice@x.com" — a
        // DIFFERENT string form of the same identity than what was originally banned.
        var response = controller.clearAccessRole(AccessSuspension.ROLE_PROFILE, "alice@x.com", auth).block();

        assertThat(response).isNotNull();
        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        // The fix: this is NOT a cosmetic no-op — the row is ACTUALLY cleared.
        assertThat(suspensions.listActive(scope).collectList().block()).isEmpty();
    }
}
