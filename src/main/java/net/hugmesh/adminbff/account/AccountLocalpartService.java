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
     * persist the canonical, collision-checked localpart for {@code accountId}. Same as
     * {@link #resolveAndPersist(String, String, String)} with no Casdoor username.
     */
    public Mono<String> resolveAndPersist(String accountId, String handle) {
        return resolveAndPersist(accountId, handle, null);
    }

    /**
     * Resolve and persist the canonical, collision-checked homeserver localparts for
     * {@code accountId}, and record {@code casdoorUsername} as its display-name hint.
     *
     * <p><b>Persisted localparts are pinned.</b> Once a row has a localpart it is kept
     * as-is on every later call (only a missing Mastodon fold is filled in, as the fold of
     * the persisted Matrix localpart). The homeserver identity is keyed on that value, so
     * re-deriving it would move the user to a different homeserver account. Pinning also
     * keeps rows whose localpart was disambiguated by a backfill (changesets 290/291 add
     * an md5 suffix on collision) from failing every later sign-in with a 409 because the
     * bare candidate belongs to another row.
     *
     * <p><b>New rows: the Casdoor username, not the UUID.</b> An email-less Casdoor
     * account's handle is its {@code sub} UUID (the hugmesh-realm JWT-Custom token carries
     * the username as {@code name}, never {@code preferred_username}). For such a row, when
     * no localpart is persisted yet, the candidate is taken from {@code casdoorUsername}
     * instead, so new Matrix and Mastodon/Akkoma handles read as the username. It falls
     * back to the UUID-derived candidate when the username is not a plain localpart, is a
     * reserved name, or either fold already belongs to another row, so a username can
     * never take over (or block) another account's homeserver identity.
     *
     * <p>{@code casdoorUsername} is then stored on the row (changeset 410) when it is
     * non-blank and differs from the stored value; a null/blank value never clears one.
     *
     * @throws CollisionException (as a {@code Mono} error) when the candidate is
     *         already persisted on a DIFFERENT account row
     */
    public Mono<String> resolveAndPersist(String accountId, String handle, String casdoorUsername) {
        String username = casdoorUsername == null ? null : casdoorUsername.trim();
        // defaultIfEmpty supplies a null-columned sentinel for an account whose row isn't
        // present yet (the targeted UPDATEs then affect 0 rows).
        return repo.findById(accountId)
                .defaultIfEmpty(new AccountLocalpartRow(accountId, null, null, null))
                .flatMap(row -> resolveLocalparts(row, handle, username)
                        .flatMap(lp -> stampUsername(row, username).thenReturn(lp)));
    }

    private Mono<String> resolveLocalparts(AccountLocalpartRow row, String handle, String username) {
        String accountId = row.id();
        String persisted = row.localpart();
        if (persisted != null && !persisted.isBlank()) {
            if (row.mastodonLocalpart() != null && !row.mastodonLocalpart().isBlank()) {
                return Mono.just(persisted);
            }
            // Pre-291 self-heal window: the Matrix localpart is set but the Mastodon fold is
            // not. The fold is taken from the PERSISTED localpart (changeset 291's
            // fold-stability invariant: mastodon_localpart == mastodonLocalpart(localpart)).
            return checkAndPersist(accountId, persisted, ServiceTokenBroker.mastodonLocalpart(persisted));
        }
        String fallback = ServiceTokenBroker.matrixUser(handle);
        String fromUsername = usernameCandidate(handle, username);
        if (fromUsername == null || fromUsername.equals(fallback)) {
            return checkAndPersist(accountId, fallback, ServiceTokenBroker.mastodonLocalpart(fallback));
        }
        // checkAndPersist refuses (CollisionException) when either fold of the username is
        // held by another row, sequentially or by a lost concurrent race; the UUID-derived
        // candidate is unique per account, so fall back to it.
        return checkAndPersist(accountId, fromUsername, ServiceTokenBroker.mastodonLocalpart(fromUsername))
                .onErrorResume(CollisionException.class, e -> checkAndPersist(
                        accountId, fallback, ServiceTokenBroker.mastodonLocalpart(fallback)));
    }

    /** Shape of a Casdoor user {@code sub}: the account handle of an email-less user. */
    private static final java.util.regex.Pattern UUID_HANDLE = java.util.regex.Pattern.compile(
            "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");

    /** A Casdoor username usable verbatim (lowercased) as a Matrix localpart: no '@' (an
     *  email-shaped name would be split by {@link ServiceTokenBroker#matrixUser}), no '/'
     *  (unsafe in homeserver URL paths), bounded length. */
    private static final java.util.regex.Pattern PLAIN_USERNAME =
            java.util.regex.Pattern.compile("^[A-Za-z0-9._=-]{1,64}$");

    /**
     * The localpart candidate taken from the Casdoor username, or {@code null} when the
     * handle is not a bare Casdoor UUID (an email handle keeps its email-derived
     * localpart) or the username is not usable: not a plain localpart, folds to nothing
     * on Mastodon, or is a reserved app path/prefix (which provisioning refuses).
     */
    static String usernameCandidate(String handle, String username) {
        if (handle == null || username == null || !UUID_HANDLE.matcher(handle).matches()
                || !PLAIN_USERNAME.matcher(username).matches()) {
            return null;
        }
        String candidate = username.toLowerCase(java.util.Locale.ROOT);
        if (candidate.replaceAll("[^a-z0-9]", "").isEmpty()
                || net.hugmesh.authcore.reserved.ReservedNames.isReserved(candidate)
                || net.hugmesh.authcore.reserved.ReservedNames.isReserved(
                        ServiceTokenBroker.mastodonLocalpart(candidate))) {
            return null;
        }
        return candidate;
    }

    private Mono<Void> stampUsername(AccountLocalpartRow row, String username) {
        if (username == null || username.isEmpty() || username.equals(row.casdoorUsername())) {
            return Mono.empty();
        }
        String capped = username.length() > CASDOOR_USERNAME_MAX
                ? username.substring(0, CASDOOR_USERNAME_MAX) : username;
        return repo.updateCasdoorUsername(row.id(), capped).then();
    }

    /** Width of {@code account.casdoor_username} (changeset 410). */
    static final int CASDOOR_USERNAME_MAX = 255;

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

    /** The Casdoor username recorded for an account (changeset 410), the default
     *  homeserver display name. Empty {@link Mono} when unset (google/discord accounts,
     *  or a native-login row that has not signed in since the column landed). */
    public Mono<String> casdoorUsernameOf(String accountId) {
        return repo.findById(accountId)
                .mapNotNull(AccountLocalpartRow::casdoorUsername)
                .filter(name -> !name.isBlank());
    }

    /** Both persisted homeserver localpart folds in ONE read (blank when unset), for the
     *  account-view read paths that surface both to user-bff over the internal API —
     *  avoids two findById round trips per read. */
    public Mono<ResolvedLocalparts> localpartsOf(String accountId) {
        return repo.findById(accountId)
                .map(row -> new ResolvedLocalparts(
                        row.localpart() == null ? "" : row.localpart(),
                        row.mastodonLocalpart() == null ? "" : row.mastodonLocalpart(),
                        row.casdoorUsername() == null ? "" : row.casdoorUsername()))
                .defaultIfEmpty(new ResolvedLocalparts("", "", ""));
    }

    /** The two persisted homeserver localpart folds for an account: the Matrix
     *  ({@code localpart}) fold and its coarser Mastodon ({@code mastodonLocalpart})
     *  fold, plus the Casdoor username display hint ({@code displayName}, changeset 410).
     *  Any may be blank for a row that predates the columns. */
    public record ResolvedLocalparts(String localpart, String mastodonLocalpart, String displayName) {

        /** No display-name hint recorded. */
        public ResolvedLocalparts(String localpart, String mastodonLocalpart) {
            this(localpart, mastodonLocalpart, "");
        }
    }
}
