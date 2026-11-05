package net.hugmesh.adminbff.meshtoken;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.PropertySource;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.io.ClassPathResource;
import net.hugmesh.commons.security.PrincipalDomain;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * The COMMITTED {@code application.yml} {@code app.mesh-token} block, bound the way Spring Boot
 * binds it, with the env vars the local stack sets ({@code APP_MESH_TOKEN_*}): the placeholders
 * resolve, the nested {@code headscale} block binds, and an ENABLED service built from the result
 * boots with the issuer key and answers with its fingerprint. Without the env vars the block
 * binds dark.
 */
class MeshTokenPropertiesBindingTest {

    static MeshTokenProperties bind(Map<String, Object> env) throws Exception {
        StandardEnvironment e = new StandardEnvironment();
        e.getPropertySources().remove(StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME);
        e.getPropertySources().remove(StandardEnvironment.SYSTEM_PROPERTIES_PROPERTY_SOURCE_NAME);
        e.getPropertySources().addFirst(new MapPropertySource("stack-env", env));
        for (PropertySource<?> ps : new YamlPropertySourceLoader().load("application.yml",
                new ClassPathResource("application.yml"))) {
            e.getPropertySources().addLast(ps);
        }
        return Binder.get(e).bind("app.mesh-token", MeshTokenProperties.class).orElseGet(MeshTokenProperties::new);
    }

    @Test
    void defaults_bindDark() throws Exception {
        MeshTokenProperties p = bind(Map.of());
        assertThat(p.isEnabled()).isFalse();
        assertThat(p.getMesh()).isEqualTo("hugmesh-local");
        assertThat(p.getIssuerKeyPath()).isEmpty();
        assertThat(p.domains()).isEmpty();
        assertThat(p.getDefaultLifetimeSeconds()).isEqualTo(7L * 86400);
        assertThat(p.effectiveMaxLifetimeSeconds()).isEqualTo(90L * 86400);
        assertThat(p.getHeadscale().getBaseUrl()).isEqualTo("http://headscale.hugmesh-pki.svc.cluster.local:8080");
        assertThat(p.getHeadscale().getUser()).isEqualTo("hugmesh");
        assertThat(p.getHeadscale().getApiKeyPath()).isEmpty();
    }

    @Test
    void localStackEnv_bindsEnabled_andTheServiceBootsWithTheKey(@TempDir Path dir) throws Exception {
        Path key = dir.resolve("mesh_token_issuer");
        Files.writeString(key, MeshTokenFixtures.openSshPem(), StandardCharsets.US_ASCII);
        MeshTokenProperties p = bind(Map.of(
                "APP_MESH_TOKEN_ENABLED", "true",
                "APP_MESH_TOKEN_MESH", "hugmesh-local",
                "APP_MESH_TOKEN_ISSUER_KEY_PATH", key.toString(),
                "APP_MESH_TOKEN_LOGIN_SERVERS", "hugmesh.net=https://hs.hugmesh.net:8488",
                "APP_MESH_TOKEN_HEADSCALE_BASE_URL", "http://hugmesh-headscale:8080",
                "APP_MESH_TOKEN_HEADSCALE_API_KEY_PATH", "/run/hugmesh-headscale/admin-bff.apikey",
                "APP_MESH_TOKEN_HEADSCALE_USER", "hugmesh"));
        assertThat(p.isEnabled()).isTrue();
        assertThat(p.getHeadscale().getBaseUrl()).isEqualTo("http://hugmesh-headscale:8080");
        assertThat(p.getHeadscale().getApiKeyPath()).isEqualTo("/run/hugmesh-headscale/admin-bff.apikey");
        assertThat(p.domains()).containsExactly(
                new MeshTokenProperties.DomainEntry("hugmesh.net", "https://hs.hugmesh.net:8488", "default"));

        MeshTokenService s = new MeshTokenService(p, mock(HeadscalePreAuthKeyClient.class),
                mock(MeshTokenIssuedRowRepository.class));
        Map<String, Object> issuer = s.issuer(PrincipalDomain.forDomain("default"));
        assertThat(issuer.get("enabled")).isEqualTo(true);
        assertThat(issuer.get("fingerprint")).isEqualTo(MeshTokenFixtures.FINGERPRINT);
        assertThat(issuer.get("domains")).isEqualTo(List.of(
                Map.of("domain", "hugmesh.net", "loginServer", "https://hs.hugmesh.net:8488")));
    }
}
