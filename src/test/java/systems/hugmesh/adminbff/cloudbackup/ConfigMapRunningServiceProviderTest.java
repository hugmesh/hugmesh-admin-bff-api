package systems.hugmesh.adminbff.cloudbackup;

import io.fabric8.kubernetes.api.model.ConfigMap;
import io.fabric8.kubernetes.api.model.ConfigMapBuilder;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.KubernetesClientException;
import io.fabric8.kubernetes.client.dsl.MixedOperation;
import io.fabric8.kubernetes.client.dsl.NonNamespaceOperation;
import io.fabric8.kubernetes.client.dsl.Resource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.commons.security.PrincipalDomain;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * The REAL installed-services provider with a MOCKED fabric8 client — never a cluster. Asserts
 * the per-brand ConfigMap acts as a FILTER over the documented catalog (a scoped admin sees only
 * their brand's installed services), a SUPERADMIN sees the FULL catalog (no per-brand filter),
 * and the SAFE FALLBACK never empties the menu (absent ConfigMap / read error -> full catalog).
 */
class ConfigMapRunningServiceProviderTest {

    @SuppressWarnings("rawtypes")
    private MixedOperation cmOp;
    @SuppressWarnings("rawtypes")
    private NonNamespaceOperation nsOp;
    @SuppressWarnings("unchecked")
    private Resource<ConfigMap> cmResource = mock(Resource.class);
    private KubernetesClient client;
    private ConfigMapRunningServiceProvider provider;

    @BeforeEach
    @SuppressWarnings({"unchecked", "rawtypes"})
    void setUp() {
        client = mock(KubernetesClient.class);
        cmOp = mock(MixedOperation.class);
        nsOp = mock(NonNamespaceOperation.class);
        cmResource = mock(Resource.class);
        provider = new ConfigMapRunningServiceProvider(() -> client, "hugmesh-backend",
                new StubRunningServiceProvider());

        when(client.configMaps()).thenReturn(cmOp);
        when(cmOp.inNamespace(eq("hugmesh-backend"))).thenReturn(nsOp);
        when(nsOp.withName(anyString())).thenReturn(cmResource);
    }

    private static ConfigMap cmWith(String... keys) {
        Map<String, String> data = new LinkedHashMap<>();
        for (String k : keys) {
            data.put(k, "1");
        }
        return new ConfigMapBuilder().withNewMetadata().withName("x").endMetadata()
                .withData(data).build();
    }

    @Test
    void scopedAdmin_withConfigMap_seesOnlyInstalledServices() {
        // brandx has postgres + matrix installed -> menu filtered to those.
        when(cmResource.get()).thenReturn(cmWith("postgres", "matrix"));
        List<String> keys = provider.runningServices(brandScoped("brandx"))
                .map(RunningService::key).collectList().block();
        assertThat(keys).containsExactlyInAnyOrder("postgres", "matrix");
    }

    @Test
    void scopedAdmin_withNoConfigMap_fallsBackToFullCatalog() {
        when(cmResource.get()).thenReturn(null); // generator has not annotated this brand yet
        List<String> keys = provider.runningServices(brandScoped("brandx"))
                .map(RunningService::key).collectList().block();
        // full documented catalog (core + optional) — never an empty menu.
        assertThat(keys).contains("etcd", "postgres", "casdoor", "matrix", "akkoma", "owncast");
    }

    @Test
    void scopedAdmin_configMapReadError_fallsBackToFullCatalog() {
        when(cmResource.get()).thenThrow(new KubernetesClientException("api-server blip"));
        List<String> keys = provider.runningServices(brandScoped("brandx"))
                .map(RunningService::key).collectList().block();
        assertThat(keys).contains("postgres", "config");
    }

    @Test
    void superadmin_seesFullCatalog_withNoPerBrandFilter() {
        // superadmin is unscoped -> the ConfigMap filter is not applied at all.
        List<String> keys = provider.runningServices(PrincipalDomain.superadminFor("default"))
                .map(RunningService::key).collectList().block();
        assertThat(keys).contains("etcd", "postgres", "casdoor", "matrix", "games", "tube");
    }

    @Test
    void configMapName_isPerBrandSlug() {
        assertThat(ConfigMapRunningServiceProvider.configMapName("Brand.X"))
                .isEqualTo("hugmesh-installed-services-brand-x");
    }

    /** A scoped (non-superadmin) tenant homed at {@code domain}, built via a JWT so
     *  {@code scoped()} is true (the foundation BackupServiceTest brandScoped() idiom). */
    private static PrincipalDomain brandScoped(String domain) {
        DomainRegistry registry = new DomainRegistry("",
                "https://idp." + domain + ".example=" + domain);
        Jwt jwt = Jwt.withTokenValue("t").header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                .subject("u").issuer("https://idp." + domain + ".example")
                .claim("roles", List.of("admin")).build();
        JwtAuthenticationToken auth = new JwtAuthenticationToken(jwt, List.of(
                new SimpleGrantedAuthority("ROLE_USER"),
                new SimpleGrantedAuthority("ROLE_ADMIN")));
        return PrincipalDomain.of(auth, registry);
    }
}
