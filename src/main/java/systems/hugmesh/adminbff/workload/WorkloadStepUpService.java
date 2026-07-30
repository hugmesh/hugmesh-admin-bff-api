package systems.hugmesh.adminbff.workload;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import systems.hugmesh.adminbff.device.SshLicenseRepository;
import systems.hugmesh.adminbff.lease.LeaderElection;
import reactor.core.publisher.Mono;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Short-TTL STEP-UP token broker for the DANGEROUS tier (exec / log-stream / mutations). A
 * superadmin must present a step-up token (DECISION 1 / DESIGN AXIOM 4) bound to:
 *
 * <ul>
 *   <li>the SUPERADMIN subject (the token is opaque + per-subject; a stolen token for one
 *       subject does not authorize another);</li>
 *   <li>a short TTL ({@link #STEP_UP_TTL}) — a stale/stolen session expires fast;</li>
 *   <li>the k8s {@link LeaderElection} Lease — ONLY the leader replica mints/holds the token
 *       store (in-memory, leader-pinned), so a non-leader replica cannot mint and a leader
 *       change drops outstanding tokens (bounding a stolen session further);</li>
 *   <li>a device/SSH-license check — the calling operator must hold an active SSH license
 *       (the same {@code device_ssh_license} registry that gates real SSH), so exec/port-
 *       forward is tied to a licensed operator/device, tailnet-only.</li>
 * </ul>
 *
 * <p>The transcript of an exec session is signed append-only via {@code RegistrySigner}
 * (tamper-evident) — see {@link WorkloadExecService}. This service mints/validates the
 * step-up tokens themselves.
 */
@Service
public class WorkloadStepUpService {

    private static final Logger log = LoggerFactory.getLogger(WorkloadStepUpService.class);

    /** Short TTL — a step-up token is valid only briefly after the deliberate re-confirm. */
    public static final Duration STEP_UP_TTL = Duration.ofMinutes(5);

    private final LeaderElection leader;
    private final SshLicenseRepository licenses;
    private final SecureRandom rng = new SecureRandom();

    /** subject -> (token, expiry). In-memory + leader-pinned: cleared on a leadership change
     *  (the leader is recreated) so outstanding tokens do not survive a leader flip. */
    private final Map<String, TokenEntry> tokens = new ConcurrentHashMap<>();

    public WorkloadStepUpService(LeaderElection leader, SshLicenseRepository licenses) {
        this.leader = leader;
        this.licenses = licenses;
    }

    private record TokenEntry(String token, Instant expiresAt) {
    }

    /**
     * Mint a step-up token for {@code subject}. Requires (a) THIS replica is the Lease leader
     * and (b) the operator holds an active SSH license (device or domain scope). Fails closed
     * (empty Mono.error) otherwise.
     */
    public Mono<String> mint(String subject, String operatorId) {
        if (!leader.isLeader()) {
            return Mono.error(new StepUpDeniedException(
                    "step-up can only be minted by the Lease leader (" + leader.label() + ")"));
        }
        return hasActiveLicense(operatorId)
                // Gate on active license then generate and store a secure step-up token.
                .flatMap(licensed -> mintIfLicensed(licensed, subject));
    }

    /** Require an active license then generate a 32-byte secure random step-up token for the subject. */
    private Mono<String> mintIfLicensed(boolean licensed, String subject) {
        if (!licensed) {
            return Mono.error(new StepUpDeniedException(
                    "step-up denied: operator holds no active SSH license"));
        }
        byte[] raw = new byte[32];
        rng.nextBytes(raw);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
        tokens.put(subject, new TokenEntry(token, Instant.now().plus(STEP_UP_TTL)));
        log.info("[workload-stepup] minted step-up for subject (ttl={}m)", STEP_UP_TTL.toMinutes());
        return Mono.just(token);
    }

    /** True iff {@code subject} presents a currently-valid step-up token. */
    public boolean validate(String subject, String token) {
        if (subject == null || token == null) return false;
        TokenEntry e = tokens.get(subject);
        if (e == null) return false;
        if (Instant.now().isAfter(e.expiresAt())) {
            tokens.remove(subject);
            return false;
        }
        return constantTimeEquals(e.token(), token);
    }

    /** Consume (single-use) a step-up token — removed after a successful exec/port-forward
     *  open so it cannot be replayed. */
    public void consume(String subject) {
        tokens.remove(subject);
    }

    private Mono<Boolean> hasActiveLicense(String operatorId) {
        if (operatorId == null || operatorId.isBlank()) {
            return Mono.just(false);
        }
        // Any active device OR domain license for the operator counts as "licensed to operate".
        return licenses.listActiveAll()
                .filter(l -> operatorId.equals(l.operator()))
                .hasElements();
    }

    private static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null || a.length() != b.length()) return false;
        int diff = 0;
        for (int i = 0; i < a.length(); i++) {
            diff |= a.charAt(i) ^ b.charAt(i);
        }
        return diff == 0;
    }

    /** A step-up mint/validate refusal (mapped to 403 by the caller). */
    public static class StepUpDeniedException extends RuntimeException {
        public StepUpDeniedException(String message) {
            super(message);
        }
    }
}
