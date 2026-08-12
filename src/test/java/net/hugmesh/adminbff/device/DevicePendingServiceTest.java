package net.hugmesh.adminbff.device;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import reactor.core.publisher.Flux;
import reactor.test.StepVerifier;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.PrincipalDomain;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * {@link DevicePendingService} — the headscale-enrolled LEFT-JOIN device_registry pick-list.
 * Pure unit test (mocked {@link HeadscaleNodesClient} + {@link DeviceRegistryRepository}); no
 * live binary, no DB.
 *
 * <ul>
 *   <li>SUPERADMIN sees enrolled-AND-registered (registered=true) PLUS enrolled-only candidates
 *       (registered=false). The fingerprint is the OPAQUE token carried straight through.</li>
 *   <li>ADMIN (scoped) sees ONLY their own-domain registered rows — never an unregistered
 *       enrolled candidate (assignment is a superadmin act).</li>
 *   <li>A registered row headscale did NOT report (offline) still appears (registered=true).</li>
 *   <li>headscale disabled / empty → registry-only degradation (no candidates).</li>
 * </ul>
 */
class DevicePendingServiceTest {

    private static HeadscaleNode hs(String fp, String host) {
        return new HeadscaleNode(fp, host, "brandx", "tag:mesh_1");
    }

    private static Device dev(String fp, String domain) {
        return new Device("id-" + fp, fp, "reg-" + fp, "tn", Device.IMAGE_MESH_EXTENSION, "rpi5",
                Device.OWNER_ADMIN, "alice@" + domain, domain, "mesh-1", null, null);
    }

    @Test
    void superadmin_seesRegisteredAndUnregisteredCandidates_fpOpaque() {
        HeadscaleNodesClient hsClient = mock(HeadscaleNodesClient.class);
        when(hsClient.listNodes()).thenReturn(Flux.just(
                hs("nodekey:REGD", "n1"),       // enrolled + registered
                hs("nodekey:PENDING", "n2")));  // enrolled, NOT registered → candidate
        DeviceRegistryRepository repo = mock(DeviceRegistryRepository.class);
        // Superadmin scope is unscoped → repo.list returns all registered devices.
        when(repo.list(any())).thenReturn(Flux.just(dev("nodekey:REGD", "brandx")));

        List<PendingNode> nodes = new DevicePendingService(hsClient, repo)
                .pending(superadminScope()).collectList().block();

        assertThat(nodes).hasSize(2);
        PendingNode regd = byFp(nodes, "nodekey:REGD");
        PendingNode pend = byFp(nodes, "nodekey:PENDING");
        assertThat(regd.registered()).isTrue();
        assertThat(regd.domain()).isEqualTo("brandx");
        assertThat(pend.registered()).isFalse();          // a candidate
        assertThat(pend.domain()).isNull();
        assertThat(pend.machineKeyFp()).isEqualTo("nodekey:PENDING");   // opaque, unchanged
    }

    @Test
    void admin_seesOnlyOwnDomainRegistered_neverUnregisteredCandidates() {
        HeadscaleNodesClient hsClient = mock(HeadscaleNodesClient.class);
        when(hsClient.listNodes()).thenReturn(Flux.just(
                hs("nodekey:REGD", "n1"),
                hs("nodekey:PENDING", "n2")));
        DeviceRegistryRepository repo = mock(DeviceRegistryRepository.class);
        // A scoped admin's repo.list returns only their brand's registered rows.
        when(repo.list(any())).thenReturn(Flux.just(dev("nodekey:REGD", "brandx")));

        List<PendingNode> nodes = new DevicePendingService(hsClient, repo)
                .pending(scopedAdmin("brandx")).collectList().block();

        // Only the registered own-domain node — the unregistered candidate is SUPERADMIN-only.
        assertThat(nodes).hasSize(1);
        assertThat(nodes.get(0).machineKeyFp()).isEqualTo("nodekey:REGD");
        assertThat(nodes.get(0).registered()).isTrue();
    }

    @Test
    void registeredButHeadscaleOffline_stillSurfacedRegistered() {
        HeadscaleNodesClient hsClient = mock(HeadscaleNodesClient.class);
        when(hsClient.listNodes()).thenReturn(Flux.empty());   // headscale reports nothing
        DeviceRegistryRepository repo = mock(DeviceRegistryRepository.class);
        when(repo.list(any())).thenReturn(Flux.just(dev("nodekey:OFFLINE", "brandx")));

        List<PendingNode> nodes = new DevicePendingService(hsClient, repo)
                .pending(superadminScope()).collectList().block();

        assertThat(nodes).hasSize(1);
        assertThat(nodes.get(0).registered()).isTrue();
        assertThat(nodes.get(0).machineKeyFp()).isEqualTo("nodekey:OFFLINE");
    }

    @Test
    void headscaleEmpty_noRegistry_isEmpty_advisoryDegradation() {
        HeadscaleNodesClient hsClient = mock(HeadscaleNodesClient.class);
        when(hsClient.listNodes()).thenReturn(Flux.empty());
        DeviceRegistryRepository repo = mock(DeviceRegistryRepository.class);
        when(repo.list(any())).thenReturn(Flux.empty());

        StepVerifier.create(new DevicePendingService(hsClient, repo).pending(superadminScope()))
                .verifyComplete();
    }

    private static PendingNode byFp(List<PendingNode> nodes, String fp) {
        return nodes.stream().filter(n -> n.machineKeyFp().equals(fp)).findFirst().orElseThrow();
    }

    // PrincipalDomain is final + factory-only; build REAL scopes from a JWT via PrincipalDomain.of
    // (the established test idiom — PrincipalDomain cannot be Mockito-mocked).
    private static final DomainRegistry REGISTRY = new DomainRegistry("",
            "https://idp.brandx.example=brandx,https://idp.brandy.example=brandy");

    private static PrincipalDomain superadminScope() {
        Jwt jwt = Jwt.withTokenValue("t").header("alg", "none")
                .subject("u").issuer("https://idp.brandx.example")
                .claim("roles", List.of("superadmin")).build();
        var auth = new JwtAuthenticationToken(jwt, List.of(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_SUPERADMIN")));
        return PrincipalDomain.of(auth, REGISTRY);
    }

    private static PrincipalDomain scopedAdmin(String domain) {
        String issuer = "https://idp." + domain + ".example";
        Jwt jwt = Jwt.withTokenValue("t").header("alg", "none")
                .subject("u").issuer(issuer).claim("roles", List.of("admin")).build();
        var auth = new JwtAuthenticationToken(jwt, List.of(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));
        return PrincipalDomain.of(auth, REGISTRY);
    }
}
