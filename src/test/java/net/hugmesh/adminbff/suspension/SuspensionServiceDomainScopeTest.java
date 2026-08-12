package net.hugmesh.adminbff.suspension;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import io.r2dbc.spi.ConnectionFactory;
import org.springframework.r2dbc.connection.R2dbcTransactionManager;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.notification.NotificationOutboxRepository;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.PrincipalDomain;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import net.hugmesh.adminbff.support.AdminBffPostgresTestSupport;

/**
 * Service-layer tenant-isolation for {@link SuspensionService} over a REAL H2 repo
 * (the reconcile facade {@link AccessSyncActions} mocked). Proves the WHOLE
 * suspend/clear/list surface is domain-scoped. Delineated:
 * <ul>
 *   <li>CROSS-USER (positive) — a brand-X admin's suspend lands in brand X and is
 *       visible to that admin.</li>
 *   <li>CROSS-USER (negative) — a brand-X admin cannot CLEAR a brand-Y suspension
 *       (no-op); the brand-Y admin can; SUPERADMIN can.</li>
 * </ul>
 */
@SpringBootTest(classes = SuspensionServiceDomainScopeTest.Boot.class)
@ActiveProfiles("test")
class SuspensionServiceDomainScopeTest extends AdminBffPostgresTestSupport {

    @org.springframework.boot.SpringBootConfiguration
    @org.springframework.boot.autoconfigure.EnableAutoConfiguration
    static class Boot { }

    @Autowired DatabaseClient db;
    @Autowired ConnectionFactory connectionFactory;

    @org.junit.jupiter.api.BeforeEach
    void clear() {
        db.sql("DELETE FROM access_suspension").fetch().rowsUpdated().block();
        db.sql("DELETE FROM notification_outbox").fetch().rowsUpdated().block();
    }

    private static final DomainRegistry REGISTRY = new DomainRegistry("",
            "https://idp.brandx.example=brandx,https://idp.brandy.example=brandy");

    private SuspensionService svc() {
        AccessSyncActions actions = mock(AccessSyncActions.class);
        when(actions.triggerTick()).thenReturn(Mono.empty());
        TransactionalOperator tx = TransactionalOperator.create(
                new R2dbcTransactionManager(connectionFactory));
        return new SuspensionService(new AccessSuspensionRepository(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.adminbff.suspension.AccessSuspensionRowRepository.class)), actions,
                new NotificationOutboxRepository(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.adminbff.notification.NotificationOutboxR2dbcRepository.class)), tx);
    }

    private static PrincipalDomain admin(String issuer) {
        Jwt jwt = Jwt.withTokenValue("t").header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                .subject("u").issuer(issuer).claim("roles", List.of("admin")).build();
        var auth = new JwtAuthenticationToken(jwt,
                List.of(new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));
        return PrincipalDomain.of(auth, REGISTRY);
    }

    private static PrincipalDomain superadmin() {
        Jwt jwt = Jwt.withTokenValue("t").header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                .subject("u").issuer("https://idp.brandx.example")
                .claim("roles", List.of("superadmin")).build();
        var auth = new JwtAuthenticationToken(jwt,
                List.of(new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_SUPERADMIN")));
        return PrincipalDomain.of(auth, REGISTRY);
    }

    private static final String BRANDX = "https://idp.brandx.example";
    private static final String BRANDY = "https://idp.brandy.example";

    @Nested
    class CrossUser {

        @Test
        void suspend_landsInActingBrand_andIsVisibleToThatAdmin() {
            SuspensionService svc = svc();
            PrincipalDomain x = admin(BRANDX);
            AccessSuspension s = svc.suspend(AccessSuspension.ROLE_MATRIX, "alice", null, "abuse", "admin", x).block();
            assertThat(s.domain()).isEqualTo("brandx");

            assertThat(svc.listActive(x).collectList().block()).hasSize(1);
            // The other brand's admin sees nothing.
            assertThat(svc.listActive(admin(BRANDY)).collectList().block()).isEmpty();
        }

        @Test
        void brandXAdminCannotClearBrandYSuspension_butBrandYAdminAndSuperadminCan() {
            SuspensionService svc = svc();
            PrincipalDomain x = admin(BRANDX);
            PrincipalDomain y = admin(BRANDY);
            svc.suspend(AccessSuspension.ROLE_MASTODON, "bob", null, "abuse", "admin", y).block();

            // brand-X admin's clear is a no-op (the brand-Y row is invisible to it).
            svc.clear(AccessSuspension.ROLE_MASTODON, "bob", "x-admin", x).block();
            assertThat(svc.listActive(y).collectList().block()).hasSize(1);

            // brand-Y admin clears it.
            svc.clear(AccessSuspension.ROLE_MASTODON, "bob", "y-admin", y).block();
            assertThat(svc.listActive(y).collectList().block()).isEmpty();
        }

        @Test
        void superadminClearsAnyBrandsSuspension() {
            SuspensionService svc = svc();
            svc.suspend(AccessSuspension.ROLE_MATRIX, "carol", null, "abuse", "admin", admin(BRANDY)).block();
            svc.clear(AccessSuspension.ROLE_MATRIX, "carol", "root", superadmin()).block();
            assertThat(svc.listActive(superadmin()).collectList().block()).isEmpty();
        }
    }

    /**
     * {@link SuspensionService#clearByHandle} — the localpart-normalized restore path
     * the account-appeal APPROVE flow uses. Proves the exact real-world gap the
     * exact-string {@link SuspensionService#clear} has: an admin can free-type the ban
     * target in a DIFFERENT string form than the appellant's own bare handle, and the
     * two forms still resolve to the SAME homeserver localpart.
     */
    @Nested
    class ClearByHandle {

        @Test
        void findsAndClears_evenWhenBannedUnderADifferentStringForm_thanTheAppellantsBareHandle() {
            SuspensionService svc = svc();
            PrincipalDomain x = admin(BRANDX);
            // The admin's free-text ban target was the FULL "provider:handle" form...
            svc.suspend(AccessSuspension.ROLE_PROFILE, "google:alice@x.com", null, "abuse", "admin", x).block();

            // ...proof this is the real bug: an EXACT-STRING clear() using only the
            // appellant's bare handle finds nothing at all.
            svc.clear(AccessSuspension.ROLE_PROFILE, "alice@x.com", "admin", x).block();
            assertThat(svc.listActive(x).collectList().block()).hasSize(1);

            // ...but the appellant only ever knows their OWN bare handle "alice@x.com".
            // clearByHandle still finds and clears it via the shared localpart.
            Long cleared = svc.clearByHandle(AccessSuspension.ROLE_PROFILE, "alice@x.com", "admin", x).block();
            assertThat(cleared).isEqualTo(1L);
            assertThat(svc.listActive(x).collectList().block()).isEmpty();
        }

        @Test
        void returnsZero_whenNoActiveSuspensionMatchesTheLocalpart() {
            SuspensionService svc = svc();
            Long cleared = svc.clearByHandle(AccessSuspension.ROLE_PROFILE, "nobody@x.com", "admin", admin(BRANDX)).block();
            assertThat(cleared).isEqualTo(0L);
        }

        @Test
        void brandXAdminCannotClearBrandYsSuspensionByHandle_butBrandYAdminAndSuperadminCan() {
            SuspensionService svc = svc();
            PrincipalDomain x = admin(BRANDX);
            PrincipalDomain y = admin(BRANDY);
            svc.suspend(AccessSuspension.ROLE_PROFILE, "org/dave", null, "abuse", "admin", y).block();

            assertThat(svc.clearByHandle(AccessSuspension.ROLE_PROFILE, "dave", "x-admin", x).block()).isEqualTo(0L);
            assertThat(svc.listActive(y).collectList().block()).hasSize(1);

            assertThat(svc.clearByHandle(AccessSuspension.ROLE_PROFILE, "dave", "y-admin", y).block()).isEqualTo(1L);
            assertThat(svc.listActive(y).collectList().block()).isEmpty();
        }
    }
}
