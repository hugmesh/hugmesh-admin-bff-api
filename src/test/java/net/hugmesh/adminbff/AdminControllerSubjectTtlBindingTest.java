package net.hugmesh.adminbff;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;
import net.hugmesh.authcore.account.AccountStore;
import net.hugmesh.authcore.casdoor.CasdoorAdminClient;
import net.hugmesh.authcore.provision.GatewayRevocationClient;
import net.hugmesh.authcore.username.UsernameGate;
import net.hugmesh.adminbff.config.SecurityConfig;
import net.hugmesh.adminbff.domainlock.DomainLockService;
import net.hugmesh.adminbff.iso.IsoRepository;
import net.hugmesh.adminbff.routeaccess.RouteAccessService;
import net.hugmesh.adminbff.suspension.SuspensionService;
import net.hugmesh.adminbff.urlregistry.UrlRegistryService;
import net.hugmesh.adminbff.usage.UsageService;
import net.hugmesh.adminbff.web.ValidationExceptionHandler;
import net.hugmesh.commons.security.DomainRegistry;

import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * The two subject-key TTLs reach {@link AdminController} from THEIR OWN properties
 * ({@link SubjectRevocationTtl#CUTOFF_PROPERTY}, {@link SubjectRevocationTtl#GRANT_PROPERTY}).
 *
 * <p>The other controller tests run with the shipped defaults, and the Java fallback in
 * {@link SubjectRevocationTtl#CUTOFF_VALUE} equals the yml default, so a broken placeholder
 * (the property no longer bound, an operator override silently ignored) stayed green there.
 * Here both are set to values unlike either default and unlike each other.
 */
@WebFluxTest(controllers = AdminController.class, properties = {
        SubjectRevocationTtl.CUTOFF_PROPERTY + "=777001",
        SubjectRevocationTtl.GRANT_PROPERTY + "=1201"})
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class,
        net.hugmesh.adminbff.account.RegistrationDomainResolver.class})
class AdminControllerSubjectTtlBindingTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean RouteAccessService routeAccess;
    @MockitoBean UrlRegistryService urlRegistry;
    @MockitoBean IsoRepository isoRepo;
    @MockitoBean AccountStore store;
    @MockitoBean UsageService usage;
    @MockitoBean SuspensionService suspensions;
    @MockitoBean DomainLockService domainLocks;
    @MockitoBean net.hugmesh.adminbff.federation.FederationApiClient federation;
    @MockitoBean CasdoorAdminClient casdoor;
    @MockitoBean GatewayRevocationClient revocations;
    @MockitoBean UsernameGate usernameGate;
    @MockitoBean net.hugmesh.adminbff.capability.DomainCapabilityService domainCapabilities;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    private WebTestClient asAdmin() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    private void stubCollaborators() {
        when(casdoor.organization()).thenReturn("hugmesh");
        when(casdoor.addUserToRole(anyString(), anyString())).thenReturn(Mono.empty());
        when(casdoor.removeUserFromRole(anyString(), anyString())).thenReturn(Mono.empty());
        when(revocations.revokeSubject(anyString(), anyString(), anyLong())).thenReturn(Mono.empty());
        when(usage.record(anyString(), anyList(), anyString())).thenReturn(Mono.empty());
    }

    @Test
    void roleRevoke_usesTheConfiguredCutOffTtl() {
        stubCollaborators();
        asAdmin().delete().uri("/bff/admin/roles/ROLE_MATRIX/carol").exchange().expectStatus().isOk();
        verify(revocations).revokeSubject("carol", "role-revoke", 777_001L);
    }

    @Test
    void roleGrant_usesTheConfiguredGrantTtl() {
        stubCollaborators();
        asAdmin().post().uri("/bff/admin/roles/ROLE_MATRIX/dave").exchange().expectStatus().isOk();
        verify(revocations).revokeSubject("dave", "role-grant", 1_201L);
    }
}
