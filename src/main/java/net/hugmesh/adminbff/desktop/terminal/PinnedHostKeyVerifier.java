package net.hugmesh.adminbff.desktop.terminal;

import net.schmizz.sshj.common.Buffer;
import net.schmizz.sshj.common.SecurityUtils;
import net.schmizz.sshj.transport.verification.HostKeyVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.MessageDigest;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * The MANDATORY, FAIL-CLOSED device host-key pin for the in-UI SSH terminal dial. It is the ONE
 * place the dial decides whether to trust the host key a mesh node presents, and it does so ONLY by
 * matching it against the fingerprint pinned in {@code device_ssh_dial.host_key_fp} for the ACTIVE
 * dial row of the target device.
 *
 * <h3>TOFU is FORBIDDEN</h3>
 * There is NO trust-on-first-use, NO known-hosts file write, NO auto-accept, and emphatically NO use
 * of {@code net.schmizz.sshj.transport.verification.PromiscuousVerifier}. {@link #verify} returns
 * {@code true} ONLY when the presented key's fingerprint equals the pinned fingerprint; ANY other
 * outcome (mismatch, unparseable pin, missing pin) returns {@code false}, which makes sshj abort the
 * transport before authentication — so a wrong/absent pin can never reach a shell.
 *
 * <h3>Fingerprint formats accepted</h3>
 * The pin is compared against BOTH fingerprint encodings sshj/OpenSSH emit for the SAME key, so the
 * seeding PR may have stored either:
 * <ul>
 *   <li>the legacy MD5 colon-hex form ({@code SecurityUtils.getFingerprint}, optionally
 *       {@code MD5:}-prefixed); and</li>
 *   <li>the modern {@code SHA256:base64} form.</li>
 * </ul>
 * Comparison is case-insensitive on the hex/label and ignores a leading {@code MD5:}/{@code SHA256:}
 * label, but is otherwise EXACT. Nothing here is secret; the pinned + presented fingerprints are
 * public key material, safe to log on a mismatch for audit.
 */
final class PinnedHostKeyVerifier implements HostKeyVerifier {

    private static final Logger log = LoggerFactory.getLogger(PinnedHostKeyVerifier.class);

    private final String deviceId;
    private final String pinnedFp;

    PinnedHostKeyVerifier(String deviceId, String pinnedFp) {
        this.deviceId = deviceId;
        this.pinnedFp = pinnedFp;
    }

    @Override
    public boolean verify(String hostname, int port, PublicKey key) {
        if (pinnedFp == null || pinnedFp.isBlank()) {
            // Absent pin -> REFUSE. This must never happen (the factory only builds this verifier
            // from an ACTIVE dial row whose host_key_fp is NOT NULL), but fail closed regardless.
            log.error("[device-terminal] host-key pin ABSENT for device={} host={}:{} — refusing "
                    + "(no TOFU)", deviceId, hostname, port);
            return false;
        }
        String presentedMd5 = normalize(SecurityUtils.getFingerprint(key));
        String presentedSha256 = sha256Fingerprint(key);
        String pin = normalize(pinnedFp);
        boolean ok = pin.equals(presentedMd5)
                || (presentedSha256 != null && pin.equals(normalize(presentedSha256)));
        if (!ok) {
            log.error("[device-terminal] HOST-KEY MISMATCH for device={} host={}:{} — pinned={} "
                    + "presented(md5)={} presented(sha256)={} — REFUSING (no TOFU)",
                    deviceId, hostname, port, pinnedFp, presentedMd5, presentedSha256);
        }
        return ok;
    }

    @Override
    public List<String> findExistingAlgorithms(String hostname, int port) {
        // No known-hosts store to consult — pin-only. Returning empty keeps sshj from narrowing
        // the server-host-key algorithm set based on a (nonexistent) prior entry.
        return Collections.emptyList();
    }

    /** Lower-cases and strips a leading {@code MD5:} / {@code SHA256:} label so an
     *  algorithm-labelled pin and the bare fingerprint compare equal. */
    private static String normalize(String fp) {
        if (fp == null) {
            return "";
        }
        String s = fp.trim();
        int colon = s.indexOf(':');
        // A "MD5:" / "SHA256:" label (alpha-numeric before the first colon) — strip it. A colon-hex
        // MD5 fingerprint's first segment is hex only, so this never strips a real hex byte.
        if (colon > 0) {
            String label = s.substring(0, colon);
            if (label.equalsIgnoreCase("MD5") || label.equalsIgnoreCase("SHA256")) {
                s = s.substring(colon + 1);
            }
        }
        return s.toLowerCase(Locale.ROOT);
    }

    /** The OpenSSH {@code SHA256:base64(nopadding)} fingerprint of the key's SSH wire encoding —
     *  computed locally so a SHA256-form pin can be matched regardless of which fingerprint format
     *  sshj's {@code getFingerprint} emits. Returns {@code null} if it cannot be computed (then only
     *  the MD5 form is compared — still fail-closed: a non-match still REFUSES). */
    private static String sha256Fingerprint(PublicKey key) {
        try {
            byte[] wire = new Buffer.PlainBuffer().putPublicKey(key).getCompactData();
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(wire);
            return "sha256:" + Base64.getEncoder().withoutPadding().encodeToString(digest)
                    .toLowerCase(Locale.ROOT);
        } catch (Exception e) {
            return null;
        }
    }

    /** Holds only PUBLIC fingerprint material (no key bytes), so this is non-secret. */
    @Override
    public String toString() {
        return "PinnedHostKeyVerifier{device=" + deviceId + ", pinned=" + pinnedFp + "}";
    }
}
