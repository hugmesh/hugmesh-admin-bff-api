package net.hugmesh.adminbff.desktop.terminal;

import net.schmizz.sshj.Config;
import net.schmizz.sshj.DefaultConfig;
import net.schmizz.sshj.common.Factory;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * The EXPLICIT SSH algorithm policy every device dial negotiates with — the answer to
 * hugmesh-admin-bff-api#11's H3, landed after the operator confirmed on 2026-09-10 that the SSH
 * device dial IS in launch scope. Until this class existed both {@code new SSHClient()} calls in
 * {@link SshjDeviceSshChannelFactory} used sshj's {@link DefaultConfig}, i.e. the dial would have
 * accepted <b>whatever sshj happens to ship</b> rather than a set this project chose and reviewed.
 *
 * <h3>What sshj 0.40.0's DefaultConfig actually admits (MEASURED, not read off the docs)</h3>
 * Instantiated on this exact classpath and its factory names printed: <b>23</b> key exchanges,
 * <b>14</b> host-key/signature algorithms, <b>33</b> ciphers, <b>16</b> MACs. That set still
 * includes SHA-1 key exchange ({@code diffie-hellman-group1-sha1}, {@code -group14-sha1},
 * {@code -group-exchange-sha1}), SHA-1 and DSA host keys ({@code ssh-rsa}, {@code ssh-dss}), RC4
 * ({@code arcfour*}), 64-bit-block ciphers ({@code 3des-*}, {@code blowfish-*}, {@code cast128-*},
 * {@code idea-*}), every CBC mode, and MD5/SHA-1/RIPEMD-160 MACs including truncated {@code -96}
 * variants. None of that may appear on a control-plane pod's dial to a mesh node.
 *
 * <h3>The policy, and WHY each entry is in it</h3>
 * The node side is not guesswork either: hugmesh's own device images ship
 * {@code specs/etc/ssh/sshd_config.d/hardened.conf} in hugmesh-generator, which sets
 * {@code Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com},
 * {@code MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com},
 * {@code KexAlgorithms sntrup761x25519-sha512,curve25519-sha256,curve25519-sha256@libssh.org} and
 * {@code HostKeyAlgorithms ssh-ed25519}. This policy is the CLIENT half of that same posture.
 * <ul>
 *   <li><b>KEX {@code curve25519-sha256} + {@code curve25519-sha256@libssh.org}</b> — X25519, no
 *       finite-field DH, no NIST curve, no SHA-1. The two names are the SAME primitive (sshj maps
 *       both to {@code Curve25519SHA256}); the {@code @libssh.org} spelling is the pre-RFC8731 alias
 *       and is kept because a node's sshd offers it too. <b>{@code ext-info-c}</b> is not a key
 *       exchange at all: it is the RFC 8308 marker that asks the server for {@code server-sig-algs},
 *       which is what lets an OpenSSH server tell us it accepts {@code rsa-sha2-*} for publickey
 *       auth. Dropping it would quietly break RSA dial keys on servers that refuse SHA-1.</li>
 *   <li><b>Host key / signature {@code ssh-ed25519}</b> — the ONLY host key any hugmesh node
 *       presents ({@code HostKeyAlgorithms ssh-ed25519} above; {@code provision.sh} generates an
 *       Ed25519-only host key) and the type {@code gen-provision-keys.sh} generates for the dial
 *       key itself ({@code ssh-keygen -t ed25519}). <b>{@code rsa-sha2-512} + {@code rsa-sha2-256}</b>
 *       are retained for ONE reason, stated so nobody mistakes it for indifference: sshj uses this
 *       ONE list for both the host-key proposal and the client's publickey-auth signature
 *       algorithm, and an operator-supplied RSA dial key (the shape this repo's own tests use, and
 *       one {@code docker/build-image.sh} accepts) could not authenticate without them. They cost
 *       nothing on the host-key side because the presented key is pinned by SHA-256 fingerprint
 *       ({@link PinnedHostKeyVerifier}) and a hugmesh node offers no RSA host key at all.</li>
 *   <li><b>Cipher {@code aes256-gcm@openssh.com} then {@code chacha20-poly1305@openssh.com}</b> —
 *       AEAD only, the node's exact set. GCM is FIRST deliberately: the client's order decides
 *       (measured — {@code Proposal.firstMatch} iterates the CLIENT list and returns the first entry
 *       the server also has), it is the node's own first preference, and it is the one AEAD that
 *       Terrapin (CVE-2023-48795) does not touch. ChaCha20-Poly1305 stays as the fallback; sshj
 *       always advertises {@code kex-strict-c-v00@openssh.com} (measured in {@code Proposal}'s
 *       bytecode), so against an OpenSSH ≥ 9.6 node strict key exchange neutralises Terrapin
 *       there too.</li>
 *   <li><b>MAC {@code hmac-sha2-512-etm@openssh.com} then {@code hmac-sha2-256-etm@openssh.com}</b>
 *       — encrypt-then-MAC, SHA-2, untruncated; again the node's exact set. This list is NOT
 *       decorative even though both ciphers are AEAD: sshj negotiates a MAC unconditionally
 *       (measured — {@code Proposal.negotiate} calls {@code firstMatch} on both MAC directions with
 *       no AEAD exemption, unlike OpenSSH), so an empty intersection here is a failed handshake.</li>
 * </ul>
 *
 * <h3>Everything excluded that {@link DefaultConfig} allowed</h3>
 * Named in full, because "restrictive" means nothing without the list. KEX: every
 * {@code diffie-hellman-*} entry — the SHA-1 ones ({@code group1-sha1}, {@code group14-sha1},
 * {@code group-exchange-sha1}) because SHA-1 and 1024-bit MODP are broken/Logjam-exposed, and the
 * SHA-2 MODP families ({@code group14/15/16/17/18-*}, {@code group-exchange-sha256}, and the
 * {@code @ssh.com} spellings) because no hugmesh node offers them and finite-field DH is strictly
 * more expensive for no gain; every {@code ecdh-sha2-nistp*} because they are NIST P-curves that no
 * hugmesh node offers. Host keys: {@code ssh-rsa} (SHA-1 signatures), {@code ssh-dss} (1024-bit
 * DSA), all {@code ecdsa-sha2-nistp*}, and EVERY {@code *-cert-v01@openssh.com} certificate variant
 * — this dial pins one exact host key, so an OpenSSH certificate host key would change what the pin
 * means while adding a whole certificate-parsing surface. Ciphers: every CBC mode (including
 * {@code aes*-cbc}), every CTR mode ({@code aes*-ctr} included — the node dropped CTR for being
 * non-AEAD), {@code aes128-gcm@openssh.com} (the node offers only the 256-bit AEADs),
 * {@code arcfour}/{@code arcfour128}/{@code arcfour256} (RC4), {@code 3des-*}, {@code blowfish-*},
 * {@code cast128-*}, {@code idea-*}, {@code serpent*}, {@code twofish*}. MACs: all
 * {@code hmac-md5*}, all {@code hmac-sha1*}, all {@code hmac-ripemd160*}, and every {@code -96}
 * truncation, plus the NON-etm {@code hmac-sha2-256}/{@code hmac-sha2-512} (encrypt-and-MAC
 * ordering).
 *
 * <h3>Two things this policy CANNOT fix, recorded so they are not rediscovered</h3>
 * <ul>
 *   <li><b>{@code sntrup761x25519-sha512} does not exist in sshj 0.40.0</b> (measured: absent from
 *       all 23 default KEX names). The node PREFERS that post-quantum hybrid; the BFF cannot offer
 *       it, so every dial settles on {@code curve25519-sha256}. Closing that gap needs an sshj
 *       release that implements it — it is not a configuration choice.</li>
 *   <li><b>Compression and file-key-provider factories are INHERITED</b> from {@link DefaultConfig}
 *       ({@code none} only, and {@code OpenSSHv1}/{@code PKCS8}/{@code OpenSSH}/{@code PuTTY}
 *       respectively). Narrowing the key providers would reject key formats an operator may
 *       legitimately have in Vault, and the only file this reads is our own mounted Secret. Both
 *       sets are PINNED in {@code DeviceDialAlgorithmPolicyTest} so an sshj upgrade that adds e.g.
 *       {@code zlib} fails the build instead of silently widening the dial.</li>
 * </ul>
 *
 * <h3>Fail-closed</h3>
 * {@link #newConfig()} resolves each policy name against the factories this sshj build actually
 * provides and THROWS if one is missing, rather than silently dialing on a shorter list — so an
 * sshj upgrade that renames or drops an algorithm kills the dial (which is off by default) instead
 * of quietly renegotiating something nobody reviewed. {@link #unavailableAlgorithms()} is the same
 * check without the throw, so {@link DeviceTerminalConfig} can say so at STARTUP.
 */
final class DeviceDialAlgorithmPolicy {

    /** Key exchange, in CLIENT preference order (the client's order decides — see the class doc). */
    static final List<String> KEY_EXCHANGE = List.of(
            "curve25519-sha256",
            "curve25519-sha256@libssh.org",
            "ext-info-c");

    /** Host-key AND publickey-auth signature algorithms — sshj uses ONE list for both. */
    static final List<String> KEY_ALGORITHMS = List.of(
            "ssh-ed25519",
            "rsa-sha2-512",
            "rsa-sha2-256");

    /** Ciphers: AEAD only. */
    static final List<String> CIPHERS = List.of(
            "aes256-gcm@openssh.com",
            "chacha20-poly1305@openssh.com");

    /** MACs: encrypt-then-MAC, SHA-2, untruncated. Negotiated even under an AEAD cipher. */
    static final List<String> MACS = List.of(
            "hmac-sha2-512-etm@openssh.com",
            "hmac-sha2-256-etm@openssh.com");

    private DeviceDialAlgorithmPolicy() {
        // static policy holder
    }

    /**
     * A fresh sshj {@link Config} carrying THIS policy — the ONLY config a device dial may use.
     * Built by NARROWING {@link DefaultConfig} (so the factory implementations are sshj's own, and
     * compression / file-key-provider / random / keep-alive defaults are untouched), never by
     * hand-assembling factories.
     *
     * @throws IllegalStateException if this sshj build does not provide a policy algorithm — the
     *         dial then fails closed rather than negotiating an unreviewed set.
     */
    static Config newConfig() {
        DefaultConfig config = new DefaultConfig();
        config.setKeyExchangeFactories(
                narrow("key exchange", config.getKeyExchangeFactories(), KEY_EXCHANGE));
        config.setKeyAlgorithms(
                narrow("host key/signature", config.getKeyAlgorithms(), KEY_ALGORITHMS));
        config.setCipherFactories(narrow("cipher", config.getCipherFactories(), CIPHERS));
        config.setMACFactories(narrow("MAC", config.getMACFactories(), MACS));
        return config;
    }

    /**
     * Keep ONLY the policy names, in POLICY order (not sshj's), and fail closed on a name this sshj
     * build does not provide.
     */
    static <T> List<Factory.Named<T>> narrow(String what, List<Factory.Named<T>> available,
                                             List<String> policy) {
        List<Factory.Named<T>> chosen = new ArrayList<>(policy.size());
        for (String name : policy) {
            Factory.Named<T> found = null;
            for (Factory.Named<T> candidate : available) {
                if (candidate.getName().equals(name)) {
                    found = candidate;
                    break;
                }
            }
            if (found == null) {
                throw new IllegalStateException("device dial " + what + " policy names '" + name
                        + "', which this sshj build does not provide — refusing to dial on an"
                        + " algorithm set nobody reviewed (see hugmesh-admin-bff-api#11 H3)");
            }
            chosen.add(found);
        }
        return chosen;
    }

    /**
     * The policy names this sshj build does NOT provide, in policy order; EMPTY when the whole
     * policy is available. Same resolution as {@link #newConfig()} without the throw, so a wiring
     * check can report it at startup instead of at 3am on the first dial.
     */
    static List<String> unavailableAlgorithms() {
        return unavailableAlgorithms(new DefaultConfig());
    }

    /**
     * The same check against an ARBITRARY config, so a test can feed one that is genuinely missing a
     * policy algorithm — this sshj build has them all, so the no-arg form above can only ever prove
     * the happy path.
     */
    static List<String> unavailableAlgorithms(Config config) {
        List<String> missing = new ArrayList<>();
        missing.addAll(absent(names(config.getKeyExchangeFactories()), KEY_EXCHANGE));
        missing.addAll(absent(names(config.getKeyAlgorithms()), KEY_ALGORITHMS));
        missing.addAll(absent(names(config.getCipherFactories()), CIPHERS));
        missing.addAll(absent(names(config.getMACFactories()), MACS));
        return List.copyOf(missing);
    }

    /** One-line, log-safe rendering of the policy (algorithm names only — never key material). */
    static String describe() {
        return "kex=" + KEY_EXCHANGE + " hostkey/sig=" + KEY_ALGORITHMS
                + " cipher=" + CIPHERS + " mac=" + MACS;
    }

    private static List<String> absent(Set<String> availableNames, List<String> policy) {
        List<String> missing = new ArrayList<>();
        for (String name : policy) {
            if (!availableNames.contains(name)) {
                missing.add(name);
            }
        }
        return missing;
    }

    private static Set<String> names(List<? extends Factory.Named<?>> factories) {
        Set<String> out = new LinkedHashSet<>();
        for (Factory.Named<?> factory : factories) {
            out.add(factory.getName());
        }
        return out;
    }
}
