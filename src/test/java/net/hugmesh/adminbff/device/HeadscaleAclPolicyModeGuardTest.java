package net.hugmesh.adminbff.device;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.web.reactive.function.client.WebClient;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * THE POLICY-MODE MISMATCH GUARD — the single most dangerous property of the Layer-A push leg.
 *
 * <p>The fleet's headscale runs {@code policy: mode: file} (hugmesh-generator
 * {@code specs/etc/headscale/config.yaml}) with the node-side {@code gen-headscale-policy.sh} as
 * the single writer of {@code /etc/headscale/policy.hujson}. This BFF's ONLY write is
 * {@code PUT /api/v1/policy}, which headscale answers with 4xx unless the policy is DB-owned.
 * Before this guard, flipping {@code enabled=true} on the fleet as shipped produced a PERMANENT
 * SILENT NO-OP — one WARN line per 60 s tick, nothing applied, and an operator convinced the
 * push was live.
 *
 * <p>These tests prove the mismatch now fails LOUDLY and EARLY (at wiring time, naming both
 * sides) and that the DARK default is untouched: with the push off nothing dials headscale and
 * no guard runs.
 */
class HeadscaleAclPolicyModeGuardTest {

    private final HeadscaleAclConfig config = new HeadscaleAclConfig();

    private static HeadscaleAclProperties props(boolean enabled, String policyMode) {
        HeadscaleAclProperties p = new HeadscaleAclProperties();
        p.setEnabled(enabled);
        p.setPolicyMode(policyMode);
        return p;
    }

    @Test
    void shippedDefaults_areFileMode_andPushDisabled() {
        HeadscaleAclProperties p = new HeadscaleAclProperties();
        // The dark contract: the push is OFF and the declared mode is the one the fleet ships.
        assertThat(p.isEnabled()).isFalse();
        assertThat(p.getPolicyMode()).isEqualTo("file");
        // ...and the base URL names the namespace headscale's Service is actually in.
        assertThat(p.getBaseUrl()).isEqualTo("http://headscale.hugmesh-pki.svc.cluster.local:8080");
        assertThat(p.getBaseUrl()).doesNotContain("headscale.headscale.svc");
        // ...and the ssh user matches provision.sh resolve_ssh_user's own fallback.
        assertThat(p.getSshUser()).isEqualTo("admin");
        assertThat(p.getApiKey()).isEmpty();
    }

    @Test
    void enabledInFileMode_refusesToWireThePushClient_namingTheMismatch() {
        assertThatThrownBy(() -> config.webClientHeadscalePolicyClient(
                WebClient.builder(), props(true, "file"), new ObjectMapper()))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("POLICY-MODE MISMATCH")
                .hasMessageContaining("policy-mode='file'")
                .hasMessageContaining("expected 'db'")
                .hasMessageContaining("DB-POLICY-MODE-ONLY")
                .hasMessageContaining("gen-headscale-policy.sh")
                .hasMessageContaining("specs/etc/headscale/config.yaml");
    }

    @Test
    void enabledWithAnyNonDbMode_alsoRefuses_includingBlankAndNull() {
        for (String mode : new String[] {"", "  ", "FILE-ish", "database", "dbb", "none"}) {
            assertThatThrownBy(() -> HeadscaleAclConfig.requireDbPolicyMode(props(true, mode)))
                    .as("mode=%s", mode)
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("POLICY-MODE MISMATCH");
        }
        assertThatThrownBy(() -> HeadscaleAclConfig.requireDbPolicyMode(props(true, null)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("POLICY-MODE MISMATCH");
    }

    @Test
    void declaredDbMode_isAccepted_caseAndWhitespaceInsensitive() {
        for (String mode : new String[] {"db", "DB", " db ", "Db"}) {
            assertThatCode(() -> HeadscaleAclConfig.requireDbPolicyMode(props(true, mode)))
                    .as("mode=%s", mode)
                    .doesNotThrowAnyException();
        }
    }

    @Test
    void darkDefault_wiresTheNoopClient_whichNeverDialsHeadscale() {
        HeadscalePolicyClient client = config.noopHeadscalePolicyClient();
        assertThat(client.isReal()).isFalse();
        assertThat(client).isInstanceOf(NoopHeadscalePolicyClient.class);
        // getPolicy() is empty and setPolicy() is a stubbed no-op — zero HTTP, zero mutation.
        assertThat(client.getPolicy().blockOptional()).isEmpty();
        assertThat(client.setPolicy("{\"ssh\":[]}").block().isStubbed()).isTrue();
    }
}
