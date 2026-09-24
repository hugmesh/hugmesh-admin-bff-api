package net.hugmesh.adminbff.tor;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link TorOnionRules} must accept exactly what the node agent
 * ({@code specs/usr/sbin/hugmesh-tor-reconcile} in hugmesh-generator, merged in #599) accepts,
 * so a value admin-bff stores is a value the node applies rather than one it logs and ignores.
 */
class TorOnionRulesTest {

    static final String ONION = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion";

    @Test
    void onion_isExactlyAV3Hostname() {
        assertThat(ONION).hasSize(62);
        assertThat(TorOnionRules.isOnionV3(ONION)).isTrue();
        // 55 / 57 base32 characters, uppercase, a non-base32 digit, a v2-length onion, no TLD.
        assertThat(TorOnionRules.isOnionV3(ONION.substring(1))).isFalse();
        assertThat(TorOnionRules.isOnionV3("a" + ONION)).isFalse();
        assertThat(TorOnionRules.isOnionV3(ONION.toUpperCase())).isFalse();
        assertThat(TorOnionRules.isOnionV3(ONION.replace('2', '1'))).isFalse();
        assertThat(TorOnionRules.isOnionV3("expyuzz4wqqyqhjn.onion")).isFalse();
        assertThat(TorOnionRules.isOnionV3(ONION.replace(".onion", ""))).isFalse();
        assertThat(TorOnionRules.isOnionV3(ONION + "\n")).isFalse();
        assertThat(TorOnionRules.isOnionV3(null)).isFalse();
    }

    @Test
    void slug_matchesTheAgentRule_noDotNoWhitespaceNoUpperCase() {
        assertThat(TorOnionRules.isSlug("brandb")).isTrue();
        assertThat(TorOnionRules.isSlug("0")).isTrue();
        assertThat(TorOnionRules.isSlug("brand-b")).isTrue();
        assertThat(TorOnionRules.isSlug("a" + "b".repeat(62))).isTrue();          // 63 chars
        assertThat(TorOnionRules.isSlug("a" + "b".repeat(63))).isFalse();         // 64 chars
        assertThat(TorOnionRules.isSlug("-brand")).isFalse();
        assertThat(TorOnionRules.isSlug("brand.b")).isFalse();
        assertThat(TorOnionRules.isSlug("my domain")).isFalse();
        assertThat(TorOnionRules.isSlug("BrandB")).isFalse();
        assertThat(TorOnionRules.isSlug(" global")).isFalse();                    // the capability sentinel
        assertThat(TorOnionRules.isSlug("")).isFalse();
        assertThat(TorOnionRules.isSlug(null)).isFalse();
    }

    @Test
    void upstream_acceptsHostIpv4AndBracketedIpv6_withAPortInRange() {
        assertThat(TorOnionRules.upstreamRefusal("127.0.0.1:443")).isEmpty();
        assertThat(TorOnionRules.upstreamRefusal("10.0.0.7:8443")).isEmpty();
        assertThat(TorOnionRules.upstreamRefusal("edge.mesh.internal:443")).isEmpty();
        assertThat(TorOnionRules.upstreamRefusal("[fd00::1]:443")).isEmpty();
        assertThat(TorOnionRules.upstreamRefusal("x:1")).isEmpty();
        assertThat(TorOnionRules.upstreamRefusal("x:65535")).isEmpty();
    }

    @Test
    void upstream_refusesWhatTheAgentWouldIgnore_andOutOfRangePorts() {
        assertThat(TorOnionRules.upstreamRefusal("10.0.0.7 :443")).isPresent();   // inner whitespace
        assertThat(TorOnionRules.upstreamRefusal(" 10.0.0.7:443")).isPresent();   // outer whitespace
        assertThat(TorOnionRules.upstreamRefusal("10.0.0.7")).isPresent();        // no port
        assertThat(TorOnionRules.upstreamRefusal("fd00::1:443")).isPresent();     // unbracketed v6
        assertThat(TorOnionRules.upstreamRefusal("10.0.0.7:443\nHiddenServicePort 80 x:1")).isPresent();
        assertThat(TorOnionRules.upstreamRefusal("10.0.0.7:123456")).isPresent(); // 6 digits
        assertThat(TorOnionRules.upstreamRefusal("x:0")).isPresent();
        assertThat(TorOnionRules.upstreamRefusal("x:65536")).isPresent();
        assertThat(TorOnionRules.upstreamRefusal("")).isPresent();
        assertThat(TorOnionRules.upstreamRefusal(null)).isPresent();
    }
}
