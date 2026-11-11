package net.hugmesh.adminbff;

import org.junit.jupiter.api.Test;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.core.env.PropertySource;
import org.springframework.core.io.ClassPathResource;
import org.springframework.util.PropertyPlaceholderHelper;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The two {@code subject:<user>} gateway-revocation TTLs must be VISIBLE, overridable entries in
 * the shipped {@code application.yml}, with the env names the generator's cluster manifest sets.
 *
 * <p>The TTL is how long the gateway's {@code RevocationGatewayFilter} denies every token whose
 * subject matches, so it has to outlive the longest token Casdoor issues. The seeded Casdoor
 * apps (hugmesh-generator {@code specs/cluster/manifests/casdoor/init-job.yaml}: the
 * {@code app-*} clients and {@code hugmesh-desktop}) carry {@code expireInHours: 168}. Until
 * this entry existed every cut-off call passed a 1 h literal, so a revoked role, a disabled
 * account or a revoked desktop-sudo claim rode its raw JWT for up to ~7 more days once the key
 * lapsed. The generator end of the contract (TTL >= max expireInHours x 3600) is pinned by
 * hugmesh-generator {@code tests/scripts/test-subject-revocation-ttl.sh}.
 *
 * <p>This test loads the REAL file (the controller slices load it too, and assert the bound
 * value reaches the call), so deleting the entry, renaming its placeholder or lowering its
 * default below 168 h turns it red.
 */
class SubjectRevocationTtlYamlDefaultTest {

    /** 168 h — the longest {@code expireInHours} any seeded Casdoor app issues. */
    private static final long LONGEST_SEEDED_TOKEN_SECONDS = 168L * 3_600L;

    private static PropertySource<?> shippedYaml() throws Exception {
        List<PropertySource<?>> sources = new YamlPropertySourceLoader()
                .load("shipped-application-yml", new ClassPathResource("application.yml"));
        assertThat(sources).as("application.yml on the test classpath").isNotEmpty();
        return sources.get(0);
    }

    /** Resolve a {@code ${ENV:default}} entry with NO environment — the shipped default. */
    private static long shippedDefault(String raw) {
        String resolved = new PropertyPlaceholderHelper("${", "}", ":", null, true)
                .replacePlaceholders(raw, name -> null);
        return Long.parseLong(resolved.trim());
    }

    @Test
    void cutoffTtl_isDeclared_withItsEnvName_andOutlivesTheLongestSeededToken() throws Exception {
        Object raw = shippedYaml().getProperty("broker.gateway-revocation.subject-cutoff-ttl-seconds");
        assertThat(raw).as("broker.gateway-revocation.subject-cutoff-ttl-seconds in application.yml")
                .isNotNull();
        assertThat(raw.toString())
                .as("the env name hugmesh-generator's admin-bff Deployment sets")
                .startsWith("${BROKER_GATEWAY_REVOCATION_SUBJECT_CUTOFF_TTL_SECONDS:");
        assertThat(shippedDefault(raw.toString()))
                .as("shipped cut-off TTL must outlive a 168 h Casdoor token")
                .isGreaterThanOrEqualTo(LONGEST_SEEDED_TOKEN_SECONDS);
    }

    @Test
    void grantTtl_isDeclared_withItsEnvName_andStaysShort() throws Exception {
        Object raw = shippedYaml().getProperty("broker.gateway-revocation.subject-grant-ttl-seconds");
        assertThat(raw).as("broker.gateway-revocation.subject-grant-ttl-seconds in application.yml")
                .isNotNull();
        assertThat(raw.toString())
                .startsWith("${BROKER_GATEWAY_REVOCATION_SUBJECT_GRANT_TTL_SECONDS:");
        // A subject: key is a full lock-out for its lifetime (no iat comparison at the
        // gateway). On a GRANT nothing is being cut off, so the key must stay short or every
        // role grant would lock the grantee out of the platform for a week.
        assertThat(shippedDefault(raw.toString())).isEqualTo(3_600L);
    }
}
