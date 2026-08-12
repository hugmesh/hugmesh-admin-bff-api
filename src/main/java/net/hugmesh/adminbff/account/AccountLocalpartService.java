package net.hugmesh.adminbff.account;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.provision.ServiceTokenBroker;

/**
 * Closes the account-takeover-by-collision bug: two DIFFERENT (provider, handle)
 * accounts (e.g. {@code google:alice@x.com} and {@code casdoor:alice@y.com} — both
 * legitimate rows since Liquibase changeset 181-casdoor-provider.xml relaxed
 * {@code ck_account_provider}) can derive the SAME homeserver localpart via {@link
 * ServiceTokenBroker#matrixUser}. Because both admin-bff's and user-bff's {@code
 * ServiceTokenBroker} register-or-login against the homeserver with ONE SHARED
 * service password, whichever account is PROVISIONED SECOND would otherwise silently
 * password-log into the FIRST account's already-registered homeserver identity.
 *
 * <p>This is the ONE chokepoint where uniqueness is decided: every account-creation
 * call site (registerGoogle, registerDiscord, InternalAccountController#ensureAccount
 * — all 3 in admin-bff-api, all 3 the only writers of new {@code account} rows) MUST
 * call {@link #resolveAndPersist} before returning to its caller, persisting the
 * resolved value into the {@code account.localpart} column (Liquibase changeset 290,
 * {@code UNIQUE}). Every homeserver-mint call site then reads that PERSISTED value
 * back (never re-derives it independently at mint time) — {@link
 * net.hugmesh.adminbff.AuthController#provision} here, and
 * user-bff-api's Matrix/Mastodon proxy controllers over the internal account-read API.
 *
 * <p><b>Two folds, one chokepoint (changeset 291).</b> The Matrix localpart above uses
 * {@link ServiceTokenBroker#matrixUser} ({@code [a-z0-9._=/-]}, no truncation). The
 * Mastodon/Akkoma mint re-folds it through the strictly COARSER {@link
 * ServiceTokenBroker#mastodonLocalpart} ({@code [a-z0-9_]}, 30-cap), so two accounts
 * DISTINCT under the Matrix fold ({@code john.doe} vs {@code john-doe}) still collapse
 * onto ONE Mastodon localpart and the shared-service-password recover leg lets the
 * second take over the first's Mastodon identity — the residual half of the takeover
 * bug 290 closed for Matrix. So {@link #resolveAndPersist} ALSO resolves +
 * collision-checks + persists the Mastodon fold ({@code account.mastodon_localpart},
 * its OWN {@code UNIQUE}); both folds are decided together, and every Mastodon-mint call
 * site reads {@link #mastodonLocalpartOf} rather than re-folding at mint time.
 *
 * <p>Deliberately uses the SAME sanitizer {@link ServiceTokenBroker#matrixUser} the
 * broker itself mints homeserver usernames with — ONE canonical sanitizer in this
 * repo, not a second independent implementation (a private copy in each repo is fine
 * per the fix's design; two DIVERGENT copies in the SAME repo would not be).
 */
@Service
public class AccountLocalpartService {

    private final AccountLocalpartRepository repo;

    public AccountLocalpartService(AccountLocalpartRepository repo) {
        this.repo = repo;
    }

    /** Thrown when the candidate localpart for an account already belongs to a
     *  DIFFERENT account row — the account-takeover-by-collision guard tripping.
     *  Each call site maps this to its own error idiom (see the class doc). */
    public static final class CollisionException extends RuntimeException {
        private final String localpart;

        public CollisionException(String localpart) {
            super("homeserver username '" + localpart + "' is already in use by a different account");
            this.localpart = localpart;
        }

        public String localpart() {
            return localpart;
        }
    }

    /**
     * Resolve (from {@code handle}, via {@link ServiceTokenBroker#matrixUser}) and
     * persist the canonical, collision-checked localpart for {@code accountId}.
     *
     * <p>Idempotent: {@code accountId} is derived from {@code provider:handle}
     * ({@link net.hugmesh.authcore.account.AccountStore#idFor}), so a repeat
     * call for an already-resolved row (e.g. the native-login {@code
     * ensureAccount(provider, handle, roles)} overload, which re-runs on EVERY sign-in
     * to sync roles) always recomputes the exact SAME candidate; the collision check
     * excludes this row's own id, so an account can never collide with itself — this
     * fast-paths to a pure read (no write, no collision check) whenever the persisted
     * value already matches the freshly-computed candidate.
     *
     * @throws CollisionException (as a {@code Mono} error) when the candidate is
     *         already persisted on a DIFFERENT account row
     */
    public Mono<String> resolveAndPersist(String accountId, String handle) {
        String candidate = ServiceTokenBroker.matrixUser(handle);
        // The Mastodon fold is the coarser fold of the SAME canonical Matrix candidate
        // (never a second independent fold of the raw handle) — so a row's two persisted
        // localparts always stand in the exact relationship every mint site reconstructs
        // (mastodonLocalpart(localpart)), and mastodonLocalpart is idempotent so this is a
        // fixed point (changeset 291's fold-stability invariant).
        String mastodonCandidate = ServiceTokenBroker.mastodonLocalpart(candidate);
        // Read the WHOLE row (both localpart columns): the fast-path no-ops ONLY when BOTH
        // folds already match — a row whose Matrix localpart is set but whose Mastodon
        // localpart is still null (a pre-291 self-heal window) must still fall through to
        // persist the Mastodon fold. defaultIfEmpty supplies a null-columned sentinel for an
        // account whose row isn't present yet (checkAndPersist's UPDATE then affects 0 rows,
        // exactly as the prior single-column code did on an absent row).
        return repo.findById(accountId)
                .defaultIfEmpty(new AccountLocalpartRow(accountId, null, null))
                .flatMap(row -> candidate.equals(row.localpart())
                                && mastodonCandidate.equals(row.mastodonLocalpart())
                        ? Mono.just(candidate)
                        : checkAndPersist(accountId, candidate, mastodonCandidate));
    }

    /**
     * Check-then-write. The check-and-write is NOT atomic (two concurrent {@code
     * resolveAndPersist} calls for two DIFFERENT accounts that happen to compute the
     * SAME candidate could both pass the {@code existsByLocalpartAndIdNot} check before
     * either writes) — the {@code uq_account_localpart} UNIQUE constraint (changeset 290)
     * is the actual backstop that makes a collision impossible to persist EITHER way, but
     * a raw constraint violation on the losing writer's {@code updateLocalpart} would
     * otherwise surface as an unmapped {@link DataIntegrityViolationException} (a 500)
     * instead of the same clean {@link CollisionException} (409) every OTHER collision
     * path returns — mapped here so a rare concurrent-registration race degrades to the
     * same documented error shape as the common (sequential) case, not a raw 500.
     */
    private Mono<String> checkAndPersist(String accountId, String candidate, String mastodonCandidate) {
        return repo.existsByLocalpartAndIdNot(candidate, accountId)
                .flatMap(matrixCollides -> Boolean.TRUE.equals(matrixCollides)
                        ? Mono.<String>error(new CollisionException(candidate))
                        : repo.existsByMastodonLocalpartAndIdNot(mastodonCandidate, accountId)
                                .flatMap(mastodonCollides -> Boolean.TRUE.equals(mastodonCollides)
                                        ? Mono.<String>error(new CollisionException(mastodonCandidate))
                                        : repo.updateLocalparts(accountId, candidate, mastodonCandidate)
                                                .thenReturn(candidate)))
                // Either UNIQUE constraint (uq_account_localpart / uq_account_mastodon_localpart)
                // is the concurrent-race backstop: map a raw violation on the losing writer to
                // the same clean 409-shaped CollisionException every sequential path returns
                // (candidate names the Matrix fold; the message shape is identical either way).
                .onErrorMap(DataIntegrityViolationException.class, e -> new CollisionException(candidate));
    }

    /** Read the persisted localpart for an account id. Empty {@link Mono} when the
     *  account/column is unset (a row that predates changeset 290's backfill window,
     *  or one created off the 3 official call sites — e.g. directly via {@code
     *  AccountStore} in a test) — callers that need a value self-heal by falling back
     *  to {@link #resolveAndPersist}, never by re-deriving the localpart themselves. */
    public Mono<String> localpartOf(String accountId) {
        return repo.findById(accountId)
                .mapNotNull(AccountLocalpartRow::localpart)
                .filter(lp -> !lp.isBlank());
    }

    /** Read the persisted Mastodon localpart (changeset 291) for an account id — the
     *  Mastodon-fold sibling of {@link #localpartOf}. Empty {@link Mono} when unset (a
     *  pre-291 / off-chokepoint row); callers self-heal via {@link #resolveAndPersist},
     *  never by re-folding a candidate themselves. */
    public Mono<String> mastodonLocalpartOf(String accountId) {
        return repo.findById(accountId)
                .mapNotNull(AccountLocalpartRow::mastodonLocalpart)
                .filter(lp -> !lp.isBlank());
    }

    /** Both persisted homeserver localpart folds in ONE read (blank when unset), for the
     *  account-view read paths that surface both to user-bff over the internal API —
     *  avoids two findById round trips per read. */
    public Mono<ResolvedLocalparts> localpartsOf(String accountId) {
        return repo.findById(accountId)
                .map(row -> new ResolvedLocalparts(
                        row.localpart() == null ? "" : row.localpart(),
                        row.mastodonLocalpart() == null ? "" : row.mastodonLocalpart()))
                .defaultIfEmpty(new ResolvedLocalparts("", ""));
    }

    /** The two persisted homeserver localpart folds for an account: the Matrix
     *  ({@code localpart}) fold and its coarser Mastodon ({@code mastodonLocalpart})
     *  fold. Either may be blank for a row that predates the columns. */
    public record ResolvedLocalparts(String localpart, String mastodonLocalpart) {
    }
}
