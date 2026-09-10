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
 * <h3>Fingerprint formats accepted, and how case is treated</h3>
 * The pin is compared against BOTH fingerprint encodings sshj/OpenSSH emit for the SAME key, so the
 * seeding PR may have stored either:
 * <ul>
 *   <li>the legacy MD5 colon-hex form ({@code SecurityUtils.getFingerprint}, optionally
 *       {@code MD5:}-prefixed) — hex, so compared CASE-INSENSITIVELY; and</li>
 *   <li>the modern {@code SHA256:base64} form — base64 is CASE-SIGNIFICANT, so compared EXACTLY.</li>
 * </ul>
 * Only the {@code MD5:} / {@code SHA256:} LABEL is case-folded. Folding the base64 digest too (as an
 * earlier revision did) collapsed 52 of base64's 64 symbols onto 26 and shrank the match space from
 * 2^256 to roughly 2^226 — not practically exploitable, but wrong in a security primitive, so the
 * digest is now compared byte-for-byte. A LABELLED pin is matched ONLY against that algorithm's
 * form; an unlabelled pin is tried against both. Nothing here is secret; the pinned + presented
 * fingerprints are public key material, safe to log on a mismatch for audit.
 *
 * <p>MD5 pins are still ACCEPTED here for rows seeded before the SHA-256 contract, but
 * {@code DesktopDialService.activate} now REFUSES to make a non-{@code SHA256:} pin ACTIVE, so an
 * MD5 pin cannot reach a live dial.
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
        String presentedMd5 = stripLabel(SecurityUtils.getFingerprint(key));
        String presentedSha256 = sha256Fingerprint(key);
        String label = labelOf(pinnedFp);
        String pin = stripLabel(pinnedFp);
        // MD5 is colon-HEX -> case-insensitive. SHA-256 is base64 -> EXACT (case IS significant).
        boolean md5Ok = !"SHA256".equals(label) && pin.equalsIgnoreCase(presentedMd5);
        boolean sha256Ok = !"MD5".equals(label) && presentedSha256 != null
                && pin.equals(presentedSha256);
        boolean ok = md5Ok || sha256Ok;
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

    /** The algorithm LABEL of a fingerprint — {@code "MD5"}, {@code "SHA256"}, or {@code ""} when it
     *  carries none. Upper-cased: only the LABEL is ever case-folded. */
    static String labelOf(String fp) {
        if (fp == null) {
            return "";
        }
        String s = fp.trim();
        int colon = s.indexOf(':');
        // A "MD5:" / "SHA256:" label (alphanumeric before the first colon). A colon-hex MD5
        // fingerprint's first segment is hex only, so this never mistakes a real hex byte for one.
        if (colon > 0) {
            String label = s.substring(0, colon);
            if (label.equalsIgnoreCase("MD5") || label.equalsIgnoreCase("SHA256")) {
                return label.toUpperCase(Locale.ROOT);
            }
        }
        return "";
    }

    /** The fingerprint DIGEST with its {@code MD5:} / {@code SHA256:} label removed and its case
     *  PRESERVED — base64 is case-significant, so this must never lower-case. */
    static String stripLabel(String fp) {
        if (fp == null) {
            return "";
        }
        String s = fp.trim();
        String label = labelOf(s);
        return label.isEmpty() ? s : s.substring(label.length() + 1);
    }

    /** The OpenSSH SHA-256 fingerprint DIGEST (unpadded base64 of the key's SSH wire encoding, NO
     *  label, case PRESERVED) — computed locally so a {@code SHA256:}-form pin can be matched
     *  regardless of which fingerprint format sshj's {@code getFingerprint} emits. Returns
     *  {@code null} if it cannot be computed (then only the MD5 form is compared — still
     *  fail-closed: a non-match still REFUSES). */
    private static String sha256Fingerprint(PublicKey key) {
        try {
            byte[] wire = new Buffer.PlainBuffer().putPublicKey(key).getCompactData();
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(wire);
            return Base64.getEncoder().withoutPadding().encodeToString(digest);
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
