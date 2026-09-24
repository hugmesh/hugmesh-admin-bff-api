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
 * <p>Decision 101 = B (2026-09-23): this BFF's {@code PUT /api/v1/policy} is the ONLY writer of
 * the tailnet policy, so the control node's headscale must keep that policy in its database —
 * {@code policy: mode: database}, headscale v0.23.0's own spelling. The node-side
 * {@code gen-headscale-policy.sh} (file mode, run by the {@code hugmesh-policy-sync} cron) is
 * retired as a writer. headscale answers {@code PUT /api/v1/policy} with 4xx in file mode, so
 * an enabled push against a file-mode headscale is a PERMANENT SILENT NO-OP — one WARN line per
 * 60 s tick, nothing applied, and an operator convinced the push was live.
 *
 * <p>These tests pin the decided DEFAULT ({@code database}), prove a file-mode (or the old,
 * non-headscale {@code db}) declaration still fails LOUDLY and EARLY at wiring time naming both
 * sides, and that the DARK default is untouched: with the push off nothing dials headscale and
 * no guard runs. {@link HeadscaleAclWiringTest} proves the same through a real Spring context
 * built from the shipped {@code application.yml}.
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
    void shippedDefaults_areDatabaseMode_andPushDisabled() {
        HeadscaleAclProperties p = new HeadscaleAclProperties();
        // The dark contract: the push is OFF, and the declared mode is decision 101 = B's
        // target, spelled the way headscale spells it ("database", never "file" or "db").
        assertThat(p.isEnabled()).isFalse();
        assertThat(p.getPolicyMode()).isEqualTo("database");
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
                .hasMessageContaining("expected 'database'")
                .hasMessageContaining("DATABASE-POLICY-MODE-ONLY")
                .hasMessageContaining("Decision 101 = B")
                .hasMessageContaining("hugmesh-policy-sync")
                .hasMessageContaining("gen-headscale-policy.sh")
                .hasMessageContaining("specs/etc/headscale/config.yaml");
    }

    @Test
    void enabledWithAnyNonDatabaseMode_alsoRefuses_includingBlankNullAndTheOldDbSpelling() {
        for (String mode : new String[] {"", "  ", "file", "FILE", "FILE-ish", "db", "DB", " db ",
                "dbb", "databases", "data base", "none", "sqlite"}) {
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
    void theOldDbSpelling_isRefused_withAHintThatHeadscaleOnlyKnowsDatabase() {
        // headscale v0.23.0 log.Fatal's on policy.mode=db ("Unknown ACL policy mode"), so a
        // declaration of "db" can never be true of a running control node.
        assertThatThrownBy(() -> HeadscaleAclConfig.requireDbPolicyMode(props(true, "db")))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("policy-mode='db'")
                .hasMessageContaining("'db' was this BFF's old spelling")
                .hasMessageContaining("Unknown ACL policy mode");
        // ...and the hint is specific to "db": a file-mode declaration does not get it.
        assertThatThrownBy(() -> HeadscaleAclConfig.requireDbPolicyMode(props(true, "file")))
                .isInstanceOf(IllegalStateException.class)
                .message().doesNotContain("old spelling");
    }

    @Test
    void declaredDatabaseMode_isAccepted_caseAndWhitespaceInsensitive() {
        for (String mode : new String[] {"database", "DATABASE", " database ", "Database"}) {
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
