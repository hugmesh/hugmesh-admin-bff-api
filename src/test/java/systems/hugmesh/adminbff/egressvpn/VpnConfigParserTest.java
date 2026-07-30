package systems.hugmesh.adminbff.egressvpn;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * {@link VpnConfigParser} — proves the parse/validate of a provider config (the 422
 * gate): a complete ProtonVPN WireGuard {@code .conf} and a minimal OpenVPN {@code .ovpn}
 * parse to the right kind + display endpoint; an incomplete/garbage config throws
 * (mapped to a 422 by the controller). The private key is matched for PRESENCE only and
 * never surfaced.
 */
class VpnConfigParserTest {

    private static final String PROTON_WG = """
            [Interface]
            # Key for client
            PrivateKey = aGVsbG8td29ybGQtcHJpdmF0ZS1rZXktYmFzZTY0AA==
            Address = 10.2.0.2/32
            DNS = 10.2.0.1

            [Peer]
            PublicKey = cGVlci1wdWJsaWMta2V5LWJhc2U2NC1oZXJlAAAAAAA=
            AllowedIPs = 0.0.0.0/0
            Endpoint = 185.159.157.1:51820
            """;

    private static final String OPENVPN = """
            client
            dev tun
            proto udp
            remote vpn.example.com 1194
            resolv-retry infinite
            """;

    @Test
    void parsesProtonWireguard_kindAndEndpoint() {
        VpnConfigParser.Parsed p = VpnConfigParser.parse(PROTON_WG);
        assertThat(p.kind()).isEqualTo(VpnConfig.KIND_WIREGUARD);
        assertThat(p.endpoint()).isEqualTo("185.159.157.1:51820");
    }

    @Test
    void parsesOpenvpn_kindAndEndpoint() {
        VpnConfigParser.Parsed p = VpnConfigParser.parse(OPENVPN);
        assertThat(p.kind()).isEqualTo(VpnConfig.KIND_OPENVPN);
        assertThat(p.endpoint()).isEqualTo("vpn.example.com:1194");
    }

    @Test
    void rejectsEmpty() {
        assertThatThrownBy(() -> VpnConfigParser.parse("  "))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("empty");
    }

    @Test
    void rejectsWireguardMissingPrivateKey() {
        String bad = "[Interface]\nAddress = 10.2.0.2/32\n[Peer]\nPublicKey = x\nEndpoint = 1.2.3.4:51820\n";
        assertThatThrownBy(() -> VpnConfigParser.parse(bad))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("PrivateKey");
    }

    @Test
    void rejectsWireguardMissingPeerEndpoint() {
        String bad = "[Interface]\nPrivateKey = secret\n[Peer]\nPublicKey = x\n";
        assertThatThrownBy(() -> VpnConfigParser.parse(bad))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Endpoint");
    }

    @Test
    void rejectsOpenvpnMissingRemote() {
        String bad = "client\ndev tun\nproto udp\n";
        assertThatThrownBy(() -> VpnConfigParser.parse(bad))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsGarbage() {
        assertThatThrownBy(() -> VpnConfigParser.parse("this is not a vpn config at all"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("unrecognised");
    }
}
