package net.hugmesh.adminbff.desktop.terminal;

import net.schmizz.sshj.Config;
import net.schmizz.sshj.DefaultConfig;
import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.common.Factory;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * PINS the device dial's explicit SSH algorithm policy (hugmesh-admin-bff-api#11 H3). Every list is
 * written out here as a LITERAL, in order, so that adding OR removing a single algorithm — in
 * {@link DeviceDialAlgorithmPolicy}, or in a future sshj that changes what {@link DefaultConfig}
 * offers — fails this build and forces a human decision. That is the whole point: the previous state
 * of this dial was "whatever sshj ships", and nothing failed when that changed.
 *
 * <p>The exclusion pin ({@link #everyDefaultConfigAlgorithmWeDropped_isNamedHere()}) is the strict
 * half: it asserts that DefaultConfig's set MINUS the policy is EXACTLY the named exclusion list, so
 * an sshj release that introduces a new algorithm (say {@code sntrup761x25519-sha512}, which 0.40.0
 * does NOT have and the mesh node's sshd prefers) cannot slip in unreviewed in either direction.
 */
class DeviceDialAlgorithmPolicyTest {

    /** Where the main sources of this package live, relative to the module root (surefire's cwd). */
    private static final Path MAIN_SRC =
            Path.of("src/main/java/net/hugmesh/adminbff/desktop/terminal");

    // ── The policy itself, as literals ──────────────────────────────────────────────────────────

    @Test
    void keyExchange_isX25519Only_plusTheExtInfoMarker() {
        assertThat(DeviceDialAlgorithmPolicy.KEY_EXCHANGE).containsExactly(
                "curve25519-sha256",
                "curve25519-sha256@libssh.org",
                "ext-info-c");
    }

    @Test
    void keyAlgorithms_areEd25519_plusRsaSha2ForAnRsaDialKey() {
        assertThat(DeviceDialAlgorithmPolicy.KEY_ALGORITHMS).containsExactly(
                "ssh-ed25519",
                "rsa-sha2-512",
                "rsa-sha2-256");
    }

    @Test
    void ciphers_areAeadOnly_withGcmFirst() {
        // GCM first is deliberate: the CLIENT's order decides (sshj's Proposal.firstMatch iterates
        // the client list), it is the node sshd's own first preference, and GCM is the one AEAD
        // Terrapin (CVE-2023-48795) does not touch.
        assertThat(DeviceDialAlgorithmPolicy.CIPHERS).containsExactly(
                "aes256-gcm@openssh.com",
                "chacha20-poly1305@openssh.com");
    }

    @Test
    void macs_areEncryptThenMacSha2_untruncated() {
        assertThat(DeviceDialAlgorithmPolicy.MACS).containsExactly(
                "hmac-sha2-512-etm@openssh.com",
                "hmac-sha2-256-etm@openssh.com");
    }

    // ── What the policy DROPS from sshj's defaults, named in full ───────────────────────────────

    /**
     * Every algorithm sshj 0.40.0's {@link DefaultConfig} admits and this policy does not, named.
     * Measured by instantiating DefaultConfig on this classpath — 23 KEX, 14 host-key, 33 ciphers,
     * 16 MACs — not copied from documentation.
     */
    @Test
    void everyDefaultConfigAlgorithmWeDropped_isNamedHere() {
        DefaultConfig defaults = new DefaultConfig();

        assertThat(dropped(names(defaults.getKeyExchangeFactories()),
                DeviceDialAlgorithmPolicy.KEY_EXCHANGE))
                .as("key exchange algorithms sshj allows by default and this dial refuses")
                .containsExactlyInAnyOrder(
                        "diffie-hellman-group-exchange-sha256",
                        "diffie-hellman-group-exchange-sha1",
                        "diffie-hellman-group1-sha1",
                        "diffie-hellman-group14-sha1",
                        "diffie-hellman-group14-sha256",
                        "diffie-hellman-group14-sha256@ssh.com",
                        "diffie-hellman-group15-sha256",
                        "diffie-hellman-group15-sha256@ssh.com",
                        "diffie-hellman-group15-sha384@ssh.com",
                        "diffie-hellman-group15-sha512",
                        "diffie-hellman-group16-sha256",
                        "diffie-hellman-group16-sha384@ssh.com",
                        "diffie-hellman-group16-sha512",
                        "diffie-hellman-group16-sha512@ssh.com",
                        "diffie-hellman-group17-sha512",
                        "diffie-hellman-group18-sha512",
                        "diffie-hellman-group18-sha512@ssh.com",
                        "ecdh-sha2-nistp256",
                        "ecdh-sha2-nistp384",
                        "ecdh-sha2-nistp521");

        assertThat(dropped(names(defaults.getKeyAlgorithms()),
                DeviceDialAlgorithmPolicy.KEY_ALGORITHMS))
                .as("host-key/signature algorithms sshj allows by default and this dial refuses")
                .containsExactlyInAnyOrder(
                        "ssh-rsa",
                        "ssh-dss",
                        "ecdsa-sha2-nistp256",
                        "ecdsa-sha2-nistp384",
                        "ecdsa-sha2-nistp521",
                        "ssh-ed25519-cert-v01@openssh.com",
                        "ssh-rsa-cert-v01@openssh.com",
                        "ssh-dss-cert-v01@openssh.com",
                        "ecdsa-sha2-nistp256-cert-v01@openssh.com",
                        "ecdsa-sha2-nistp384-cert-v01@openssh.com",
                        "ecdsa-sha2-nistp521-cert-v01@openssh.com");

        assertThat(dropped(names(defaults.getCipherFactories()),
                DeviceDialAlgorithmPolicy.CIPHERS))
                .as("ciphers sshj allows by default and this dial refuses")
                .containsExactlyInAnyOrder(
                        "aes128-gcm@openssh.com",
                        "aes128-cbc", "aes192-cbc", "aes256-cbc",
                        "aes128-ctr", "aes192-ctr", "aes256-ctr",
                        "3des-cbc", "3des-ctr",
                        "blowfish-cbc", "blowfish-ctr",
                        "cast128-cbc", "cast128-ctr",
                        "idea-cbc", "idea-ctr",
                        "serpent128-cbc", "serpent128-ctr",
                        "serpent192-cbc", "serpent192-ctr",
                        "serpent256-cbc", "serpent256-ctr",
                        "twofish-cbc",
                        "twofish128-cbc", "twofish128-ctr",
                        "twofish192-cbc", "twofish192-ctr",
                        "twofish256-cbc", "twofish256-ctr",
                        "arcfour", "arcfour128", "arcfour256");

        assertThat(dropped(names(defaults.getMACFactories()), DeviceDialAlgorithmPolicy.MACS))
                .as("MACs sshj allows by default and this dial refuses")
                .containsExactlyInAnyOrder(
                        "hmac-sha1",
                        "hmac-sha1-etm@openssh.com",
                        "hmac-sha1-96",
                        "hmac-sha1-96@openssh.com",
                        "hmac-md5",
                        "hmac-md5-etm@openssh.com",
                        "hmac-md5-96",
                        "hmac-md5-96-etm@openssh.com",
                        "hmac-sha2-256",
                        "hmac-sha2-512",
                        "hmac-ripemd160",
                        "hmac-ripemd160-etm@openssh.com",
                        "hmac-ripemd160-96",
                        "hmac-ripemd160@openssh.com");
    }

    /** The same rule stated the way a reader checks it in a hurry: the broken primitives are gone. */
    @Test
    void theBrokenPrimitivesSshjShipsByDefault_cannotBeNegotiated() {
        Config policy = DeviceDialAlgorithmPolicy.newConfig();

        assertThat(names(policy.getKeyExchangeFactories()))
                .noneMatch(n -> n.contains("sha1"))
                .noneMatch(n -> n.startsWith("diffie-hellman"))
                .noneMatch(n -> n.startsWith("ecdh-sha2-nistp"));
        assertThat(names(policy.getKeyAlgorithms()))
                .doesNotContain("ssh-rsa", "ssh-dss")
                .noneMatch(n -> n.contains("cert-v01"))
                .noneMatch(n -> n.startsWith("ecdsa-"));
        assertThat(names(policy.getCipherFactories()))
                .noneMatch(n -> n.contains("cbc"))
                .noneMatch(n -> n.contains("ctr"))
                .noneMatch(n -> n.startsWith("arcfour"))
                .noneMatch(n -> n.startsWith("3des"));
        assertThat(names(policy.getMACFactories()))
                .noneMatch(n -> n.contains("md5"))
                .noneMatch(n -> n.contains("sha1"))
                .noneMatch(n -> n.contains("ripemd"))
                .noneMatch(n -> n.endsWith("-96"))
                .allMatch(n -> n.endsWith("-etm@openssh.com"));
    }

    // ── The inherited halves, pinned so an sshj upgrade cannot widen them silently ───────────────

    @Test
    void compressionAndFileKeyProviders_areTheInheritedDefaults_andArePinned() {
        Config policy = DeviceDialAlgorithmPolicy.newConfig();
        // Compression: NONE only. If an sshj upgrade ever adds zlib, this fails rather than
        // enabling compression on a dial nobody re-reviewed.
        assertThat(names(policy.getCompressionFactories())).containsExactly("none");
        // File key providers are deliberately NOT narrowed (the only file read is our own mounted
        // Secret, and narrowing would reject key formats an operator may legitimately hold in
        // Vault) — but the set is pinned so a change is noticed. loadDialKey picks from this list.
        assertThat(names(policy.getFileKeyProviderFactories()))
                .containsExactly("OpenSSHv1", "PKCS8", "OpenSSH", "PuTTY");
    }

    // ── The policy is REACHABLE: it resolves, and it can talk to a hugmesh node ─────────────────

    @Test
    void everyPolicyAlgorithm_resolvesToARealSshjImplementation() {
        assertThat(DeviceDialAlgorithmPolicy.unavailableAlgorithms())
                .as("policy names this sshj build cannot provide")
                .isEmpty();

        Config policy = DeviceDialAlgorithmPolicy.newConfig();
        assertCreatable(policy.getKeyAlgorithms());
        assertCreatable(policy.getCipherFactories());
        assertCreatable(policy.getMACFactories());
        // KEX: ext-info-c is a MARKER, not a key exchange — sshj's ExtInfoClientFactory.create()
        // returns null by design (measured), so only the two real KEX entries are instantiated.
        assertCreatable(policy.getKeyExchangeFactories().stream()
                .filter(f -> !"ext-info-c".equals(f.getName()))
                .toList());
    }

    /**
     * The policy must actually be able to negotiate with a hugmesh device. These are the literal
     * sets from hugmesh-generator {@code specs/etc/ssh/sshd_config.d/hardened.conf} (Ciphers, MACs,
     * KexAlgorithms, HostKeyAlgorithms). A policy with an empty intersection in ANY category is a
     * dial that can never connect — sshj's {@code Proposal.firstMatch} throws
     * {@code TransportException} — and no unit test that only inspects our own list would notice.
     */
    @Test
    void thePolicyIntersectsTheHardenedNodeSshdConfig_inEveryCategory() {
        List<String> nodeKex = List.of(
                "sntrup761x25519-sha512", "curve25519-sha256", "curve25519-sha256@libssh.org");
        List<String> nodeHostKeys = List.of("ssh-ed25519");
        List<String> nodeCiphers = List.of("aes256-gcm@openssh.com", "chacha20-poly1305@openssh.com");
        List<String> nodeMacs =
                List.of("hmac-sha2-512-etm@openssh.com", "hmac-sha2-256-etm@openssh.com");

        assertThat(DeviceDialAlgorithmPolicy.KEY_EXCHANGE).containsAnyElementsOf(nodeKex);
        assertThat(DeviceDialAlgorithmPolicy.KEY_ALGORITHMS).containsAnyElementsOf(nodeHostKeys);
        assertThat(DeviceDialAlgorithmPolicy.CIPHERS).containsAnyElementsOf(nodeCiphers);
        assertThat(DeviceDialAlgorithmPolicy.MACS).containsAnyElementsOf(nodeMacs);

        // And the negotiated result is predictable, because the CLIENT's order decides: the first
        // policy entry the node also offers wins. Recorded so a reordering is a visible decision.
        assertThat(firstCommon(DeviceDialAlgorithmPolicy.KEY_EXCHANGE, nodeKex))
                .isEqualTo("curve25519-sha256");
        assertThat(firstCommon(DeviceDialAlgorithmPolicy.CIPHERS, nodeCiphers))
                .isEqualTo("aes256-gcm@openssh.com");
        assertThat(firstCommon(DeviceDialAlgorithmPolicy.MACS, nodeMacs))
                .isEqualTo("hmac-sha2-512-etm@openssh.com");
        // The node PREFERS a post-quantum hybrid this sshj build simply does not implement. Pinned
        // so the day sshj ships it, this test fails and someone adds it deliberately.
        assertThat(names(new DefaultConfig().getKeyExchangeFactories()))
                .as("sshj 0.40.0 has no sntrup761x25519-sha512 — see #11 H3")
                .doesNotContain("sntrup761x25519-sha512");
    }

    // ── The policy is APPLIED: the factory's client carries it, on BOTH verbs ───────────────────

    @Test
    void theClientTheDialFactoryBuilds_carriesThePolicy_notSshjDefaults() throws IOException {
        SSHClient ssh = SshjDeviceSshChannelFactory.newPolicyClient();
        try {
            Config live = ssh.getTransport().getConfig();
            assertThat(names(live.getKeyExchangeFactories()))
                    .containsExactlyElementsOf(DeviceDialAlgorithmPolicy.KEY_EXCHANGE);
            assertThat(names(live.getKeyAlgorithms()))
                    .containsExactlyElementsOf(DeviceDialAlgorithmPolicy.KEY_ALGORITHMS);
            assertThat(names(live.getCipherFactories()))
                    .containsExactlyElementsOf(DeviceDialAlgorithmPolicy.CIPHERS);
            assertThat(names(live.getMACFactories()))
                    .containsExactlyElementsOf(DeviceDialAlgorithmPolicy.MACS);
            // Non-vacuity: this must NOT be what a bare `new SSHClient()` would have carried.
            assertThat(names(live.getCipherFactories()))
                    .isNotEqualTo(names(new DefaultConfig().getCipherFactories()));
        } finally {
            ssh.close();
        }
    }

    /**
     * STRUCTURAL: no {@code new SSHClient(...)} anywhere in this package's MAIN sources may be built
     * without the policy, and both dial verbs must go through {@link
     * SshjDeviceSshChannelFactory#newPolicyClient()}. A status-only test cannot see this: a verb
     * that quietly reverted to {@code new SSHClient()} would still pass every other test in the repo
     * (no unit test reaches a live handshake), and would negotiate SHA-1 KEX and RC4 in production.
     */
    @Test
    void noSshClientInMainSources_isBuiltWithoutTheAlgorithmPolicy() throws IOException {
        assertThat(Files.isDirectory(MAIN_SRC))
                .as("main sources must be scannable from surefire's working directory (%s)",
                        MAIN_SRC.toAbsolutePath())
                .isTrue();

        int constructions = 0;
        try (Stream<Path> files = Files.list(MAIN_SRC)) {
            for (Path file : files.filter(f -> f.toString().endsWith(".java")).toList()) {
                String code = stripComments(Files.readString(file, StandardCharsets.UTF_8));
                int at = code.indexOf("new SSHClient(");
                while (at >= 0) {
                    constructions++;
                    String tail = code.substring(at);
                    assertThat(tail)
                            .as("%s constructs an SSHClient without the dial algorithm policy",
                                    file)
                            .startsWith("new SSHClient(DeviceDialAlgorithmPolicy.newConfig())");
                    at = code.indexOf("new SSHClient(", at + 1);
                }
            }
        }
        // Anti-vacuity: a scan that matched nothing (a renamed class, a broken path) must FAIL.
        assertThat(constructions)
                .as("the scan must actually have found the one policy-carrying construction")
                .isEqualTo(1);

        // And both verbs must route through it — a mutant that inlines a bare client in exec() or
        // dial() is caught by the assertion above; this catches one that stops calling the helper.
        String factory = stripComments(Files.readString(
                MAIN_SRC.resolve("SshjDeviceSshChannelFactory.java"), StandardCharsets.UTF_8));
        assertThat(countOf(factory, "newPolicyClient()"))
                .as("open()'s dial(), exec()'s execBlocking(), and the helper's own declaration")
                .isEqualTo(3);
    }

    // ── Fail-closed on an sshj that no longer provides a policy algorithm ────────────────────────

    @Test
    void narrow_failsClosed_whenThisSshjBuildLacksAPolicyAlgorithm() {
        DefaultConfig defaults = new DefaultConfig();
        assertThatThrownBy(() -> DeviceDialAlgorithmPolicy.narrow(
                "cipher", defaults.getCipherFactories(), List.of("aes256-gcm@openssh.com",
                        "twofish512-no-such-cipher")))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("twofish512-no-such-cipher")
                .hasMessageContaining("refusing to dial");
    }

    /**
     * The startup check must actually REPORT a missing algorithm — on this classpath sshj provides
     * every policy name, so the no-arg form can only ever prove the happy path. Fed a config with
     * one algorithm removed, the check has to name exactly that one; an implementation that always
     * returned "nothing missing" (an inert startup check) fails here.
     */
    @Test
    void unavailableAlgorithms_namesWhatThisSshjBuildWouldNotProvide() {
        DefaultConfig stripped = new DefaultConfig();
        var withoutGcm = stripped.getCipherFactories().stream()
                .filter(f -> !"aes256-gcm@openssh.com".equals(f.getName()))
                .toList();
        stripped.setCipherFactories(withoutGcm);

        assertThat(DeviceDialAlgorithmPolicy.unavailableAlgorithms(stripped))
                .containsExactly("aes256-gcm@openssh.com");
        assertThat(DeviceDialAlgorithmPolicy.unavailableAlgorithms(new DefaultConfig())).isEmpty();
    }

    @Test
    void describe_namesEveryList_andNoKeyMaterial() {
        String described = DeviceDialAlgorithmPolicy.describe();
        assertThat(described)
                .contains("curve25519-sha256")
                .contains("ssh-ed25519")
                .contains("aes256-gcm@openssh.com")
                .contains("hmac-sha2-512-etm@openssh.com")
                .doesNotContain("PRIVATE");
    }

    // ── helpers ─────────────────────────────────────────────────────────────────────────────────

    private static List<String> names(List<? extends Factory.Named<?>> factories) {
        return factories.stream().map(Factory.Named::getName).toList();
    }

    private static List<String> dropped(List<String> available, List<String> policy) {
        return available.stream().filter(n -> !policy.contains(n)).toList();
    }

    private static String firstCommon(List<String> client, List<String> server) {
        return client.stream().filter(server::contains).findFirst().orElse(null);
    }

    private static void assertCreatable(List<? extends Factory.Named<?>> factories) {
        assertThat(factories).isNotEmpty();
        for (Factory.Named<?> factory : factories) {
            assertThat(factory.create())
                    .as("sshj factory '%s' must instantiate", factory.getName())
                    .isNotNull();
        }
    }

    private static int countOf(String haystack, String needle) {
        int count = 0;
        int at = haystack.indexOf(needle);
        while (at >= 0) {
            count++;
            at = haystack.indexOf(needle, at + needle.length());
        }
        return count;
    }

    /**
     * Strip Java comments (line, block and javadoc) while respecting string, text-block and char
     * literals — because BOTH classes discuss {@code new SSHClient()} in prose, and a scanner that
     * counted those would be measuring documentation instead of code.
     */
    private static String stripComments(String source) {
        StringBuilder out = new StringBuilder(source.length());
        int i = 0;
        int n = source.length();
        while (i < n) {
            char c = source.charAt(i);
            if (c == '/' && i + 1 < n && source.charAt(i + 1) == '/') {
                while (i < n && source.charAt(i) != '\n') {
                    i++;
                }
            } else if (c == '/' && i + 1 < n && source.charAt(i + 1) == '*') {
                i += 2;
                while (i + 1 < n && !(source.charAt(i) == '*' && source.charAt(i + 1) == '/')) {
                    i++;
                }
                i = Math.min(n, i + 2);
            } else if (c == '"' && source.startsWith("\"\"\"", i)) {
                out.append("\"\"\"");
                i += 3;
                while (i < n && !source.startsWith("\"\"\"", i)) {
                    i++;
                }
                i = Math.min(n, i + 3);
                out.append("\"\"\"");
            } else if (c == '"' || c == '\'') {
                char quote = c;
                out.append(c);
                i++;
                while (i < n && source.charAt(i) != quote) {
                    if (source.charAt(i) == '\\' && i + 1 < n) {
                        out.append(source.charAt(i));
                        i++;
                    }
                    out.append(source.charAt(i));
                    i++;
                }
                if (i < n) {
                    out.append(source.charAt(i));
                    i++;
                }
            } else {
                out.append(c);
                i++;
            }
        }
        return out.toString();
    }
}
