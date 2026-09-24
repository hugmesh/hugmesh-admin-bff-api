package net.hugmesh.adminbff.matrixadmin;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.HexFormat;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

/**
 * The two-call confirmation for the ADMIN-only, ONE-WAY Matrix account deactivate (operator
 * decision 83a = C, 2026-09-23; hugmesh-mod-bff-api#23).
 *
 * <ol>
 *   <li>{@link #propose} mints a random 256-bit token bound to the normalised target MXID and
 *       to the acting admin's subject, valid for {@code matrix-admin.deactivate.confirm-ttl}
 *       (default two minutes). Only its SHA-256 is stored.</li>
 *   <li>{@link #confirm} performs the deactivate ONLY when the presented token exists, was
 *       minted by the SAME admin, for the SAME account, is inside its window, and has not been
 *       used — and it spends the token (a compare-and-swap) BEFORE the transport runs, so a
 *       confirm that races another, or that degrades, can never be replayed.</li>
 * </ol>
 *
 * <p>This is independent of the MFA step-up machinery (decision 83a chose it precisely because
 * it differs from what moderator writes already need and works with MFA off). It stops a
 * single accidental call, not a determined script holding an admin session.
 *
 * <p>Audit: both calls leave a row ({@code matrix_admin_deactivate_proposal}, never deleted)
 * and an {@code [matrix-admin] AUDIT} / {@code DENY (audit)} log line naming the actor, the
 * repo's existing pattern for operator actions.
 */
public class MatrixDeactivateService {

    private static final Logger log = LoggerFactory.getLogger(MatrixDeactivateService.class);

    /** Refusal causes surfaced to the caller (403) and in the DENY audit line. */
    public enum Refusal {
        /** The confirm carried no token. */
        NO_TOKEN("no-token"),
        /** No proposal carries this token: confirm without propose, or a forged/mistyped token. */
        UNKNOWN_TOKEN("unknown-token"),
        /** The token was already spent by an earlier (or concurrent) confirm. */
        ALREADY_USED("already-used"),
        /** The confirmation window has closed. */
        EXPIRED("expired"),
        /** The token was proposed for a different account. */
        OTHER_ACCOUNT("token-for-another-account"),
        /** The token was proposed by a different admin. */
        OTHER_ADMIN("token-minted-by-another-admin");

        private final String code;

        Refusal(String code) {
            this.code = code;
        }

        public String code() {
            return code;
        }
    }

    /** A propose/confirm the caller must be told was refused, and why. */
    public static final class RefusedException extends RuntimeException {
        private final Refusal refusal;

        RefusedException(Refusal refusal) {
            super("confirmation refused: " + refusal.code());
            this.refusal = refusal;
        }

        public Refusal refusal() {
            return refusal;
        }
    }

    /** The target is not a plain MXID (or a bare localpart with no server name configured). */
    public static final class BadTargetException extends RuntimeException {
        BadTargetException(String target) {
            super("not a Matrix user id: '" + target + "'");
        }
    }

    /** The transport is dark ({@code matrix-admin.enabled=false}); nothing was written. */
    public static final class DarkException extends RuntimeException {
        DarkException() {
            super("the ADMIN Matrix deactivate ships dark (matrix-admin.enabled=false)");
        }
    }

    /** A minted proposal. {@code token} is returned exactly once and never stored. */
    public record Proposal(String proposalId, String mxid, String token, Instant expiresAt, long ttlSeconds) {
    }

    /** A spent proposal and what the transport reported. */
    public record Confirmation(String proposalId, String mxid, MatrixAdminOutcome outcome) {
    }

    private final MatrixDeactivateProposalRepository repo;
    private final MatrixAdminDeactivateClient client;
    private final Duration ttl;
    private final Clock clock;
    private final SecureRandom rng = new SecureRandom();

    public MatrixDeactivateService(MatrixDeactivateProposalRepository repo,
                                   MatrixAdminDeactivateClient client,
                                   Duration ttl,
                                   Clock clock) {
        this.repo = repo;
        this.client = client;
        this.ttl = ttl;
        this.clock = clock;
    }

    /** Step 1: mint a single-use token for (target, actor). */
    public Mono<Proposal> propose(String actor, String target) {
        if (actor == null || actor.isBlank()) {
            return Mono.error(new IllegalArgumentException("no subject on the authenticated principal"));
        }
        if (!client.enabled()) {
            return Mono.error(new DarkException());
        }
        String mxid = client.mxid(target);
        if (mxid == null) {
            return Mono.error(new BadTargetException(target));
        }
        byte[] raw = new byte[32];
        rng.nextBytes(raw);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
        // Postgres timestamptz holds microseconds; truncate so the value read back equals the
        // value compared against.
        Instant now = clock.instant().truncatedTo(ChronoUnit.MICROS);
        Instant expiresAt = now.plus(ttl);
        MatrixDeactivateProposalRow row = MatrixDeactivateProposalRow.forInsert(
                UUID.randomUUID().toString(), sha256(token), mxid, actor, now, expiresAt);
        return repo.save(row).map(saved -> {
            log.warn("[matrix-admin] AUDIT propose deactivate actor={} mxid={} proposal={} expiresAt={}",
                    actor, mxid, saved.id(), expiresAt);
            return new Proposal(saved.id(), mxid, token, expiresAt, ttl.toSeconds());
        });
    }

    /** Step 2: spend the token and, only then, post the one-way deactivate. */
    public Mono<Confirmation> confirm(String actor, String target, String token) {
        if (actor == null || actor.isBlank()) {
            return Mono.error(new IllegalArgumentException("no subject on the authenticated principal"));
        }
        if (!client.enabled()) {
            return Mono.error(new DarkException());
        }
        String mxid = client.mxid(target);
        if (mxid == null) {
            return Mono.error(new BadTargetException(target));
        }
        if (token == null || token.isBlank()) {
            return refuse(actor, mxid, null, Refusal.NO_TOKEN);
        }
        Instant now = clock.instant();
        return repo.findByTokenHash(sha256(token.trim()))
                .flatMap(row -> checkAndConsume(actor, mxid, row, now))
                .switchIfEmpty(Mono.defer(() -> refuse(actor, mxid, null, Refusal.UNKNOWN_TOKEN)));
    }

    private Mono<Confirmation> checkAndConsume(String actor, String mxid, MatrixDeactivateProposalRow row,
                                               Instant now) {
        if (!MatrixDeactivateProposalRow.STATE_PROPOSED.equals(row.state())) {
            return refuse(actor, mxid, row.id(), Refusal.ALREADY_USED);
        }
        if (!now.isBefore(row.expiresAt())) {
            return refuse(actor, mxid, row.id(), Refusal.EXPIRED);
        }
        if (!actor.equals(row.proposedBy())) {
            return refuse(actor, mxid, row.id(), Refusal.OTHER_ADMIN);
        }
        if (!mxid.equals(row.mxid())) {
            return refuse(actor, mxid, row.id(), Refusal.OTHER_ACCOUNT);
        }
        return repo.consume(row.id(), actor, mxid, now).flatMap(won -> {
            if (won == null || won != 1L) {
                // Lost the race to a concurrent confirm (or the row changed under us).
                return refuse(actor, mxid, row.id(), Refusal.ALREADY_USED);
            }
            return client.deactivate(mxid)
                    .flatMap(outcome -> repo.recordOutcome(row.id(), outcome.result())
                            // The command may already be in the admin room: a failed outcome
                            // write must not turn a sent deactivate into an error response.
                            .onErrorResume(e -> {
                                log.error("[matrix-admin] outcome write for proposal={} failed: {}",
                                        row.id(), e.toString());
                                return Mono.just(0L);
                            })
                            .thenReturn(new Confirmation(row.id(), mxid, outcome)))
                    .doOnNext(c -> log.warn("[matrix-admin] AUDIT confirm deactivate actor={} mxid={} "
                            + "proposal={} outcome={}", actor, mxid, c.proposalId(), c.outcome().result()));
        });
    }

    private static <T> Mono<T> refuse(String actor, String mxid, String proposalId, Refusal why) {
        log.warn("[matrix-admin] DENY (audit) confirm deactivate actor={} mxid={} proposal={} cause={}",
                actor, mxid, proposalId, why.code());
        return Mono.error(new RefusedException(why));
    }

    static String sha256(String token) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(md.digest(token.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
