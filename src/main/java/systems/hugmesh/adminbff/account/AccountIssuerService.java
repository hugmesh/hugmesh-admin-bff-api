package systems.hugmesh.adminbff.account;

import org.jspecify.annotations.Nullable;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.security.DomainRegistry;

import java.util.Set;

/**
 * Validate/stamp/read chokepoint for the {@code account.account_issuer} column (Liquibase
 * changeset 301) — the multi-brand bff_-session domain-scope fix. See {@link
 * AccountIssuerRow} for the full gap description; in one line: the introspect contract
 * carried no brand field, so user-bff's synthetic Jwt for a bff_ session could not stamp
 * an {@code iss} on a multi-issuer cluster and EVERY domain-scoped read/write for a
 * native-login caller failed closed ({@code "__deny__"}).
 *
 * <p>{@link #stamp} is called from the ONE native-login place the raw id_token is decoded
 * ({@code InternalAccountController#ensureAccount}, provider {@code "casdoor"}), which
 * re-runs on EVERY sign-in — so legacy rows (null column) self-heal on their next native
 * login from a trusted issuer, mirroring the roles re-sync and the 292 sub stamp.
 * Idempotent with a read-first fast path (the common repeat sign-in never writes).
 *
 * <h3>*** THE SECURITY CONTRACT — why this one validates and 292's did not ***</h3>
 * {@code InternalAccountController} decodes the id_token but does NOT re-verify its
 * signature (its own javadoc says so), and {@code body.handle()} is user-bff-supplied.
 * The gateway's {@code DomainRegistry} javadoc is explicit that tenant scope must never be
 * keyed off a forgeable claim: "a user could forge cross-tenant scope". {@code
 * casdoor_sub} (292) could tolerate a loose decode because it is only ever ADDED to the
 * gateway's deny-wins route-pin identity set — an extra id can make a pin APPLY, never
 * remove a deny. An ISSUER DECIDES TENANT SCOPE: stamping an unvalidated one would hand
 * any caller who can reach {@code /bff/internal/accounts/ensure} a cross-brand read/write
 * primitive — strictly WORSE than the fail-closed deny it replaces.
 *
 * <p>So {@link #trustedIssuerOrNull} admits an issuer ONLY on strict membership of the
 * CONFIGURED, NON-EMPTY {@link DomainRegistry#trustedIssuers()} set. Two deliberate
 * choices there:
 * <ul>
 *   <li><b>Not {@link DomainRegistry#isTrusted}.</b> That method delegates to {@code
 *       domainOf}, which short-circuits to {@code DEFAULT_DOMAIN} <em>without inspecting
 *       its argument</em> when the registry map is empty — i.e. in the no-config case it
 *       answers "trusted" for ANY string, forged ones included. Strict set membership
 *       cannot fail open that way.</li>
 *   <li><b>Empty set → never stamp.</b> With no tenancy config there is nothing to
 *       validate against and nothing to gain: {@code domainOf} ignores {@code iss}
 *       entirely and every token resolves {@code DEFAULT_DOMAIN}. Stamping an unvalidated
 *       value into a durable column for zero benefit is how a today-harmless value becomes
 *       tomorrow's trusted input after someone turns tenancy on.</li>
 * </ul>
 * The stored value is the canonical element FROM the trusted set (not the token's raw
 * string), so it is byte-identical to the {@link DomainRegistry} key user-bff will match
 * and stamp — no trailing-slash skew between the two repos' normalisation.
 */
@Service
public class AccountIssuerService {

    private final AccountIssuerRepository repo;
    private final DomainRegistry domains;

    public AccountIssuerService(AccountIssuerRepository repo, DomainRegistry domains) {
        this.repo = repo;
        this.domains = domains;
    }

    /**
     * Resolve a decoded, UNVERIFIED {@code iss} claim to the canonical trusted issuer it
     * names, or {@code null} if this deployment does not trust it.
     *
     * <p>THE security gate of changeset 301 (see the class doc). Null in — null out; a
     * blank, unknown or forged issuer is null out; an empty trusted set is ALWAYS null out
     * (never fail open). Package-private so the security test can drive it directly in
     * addition to the end-to-end stamp path.
     *
     * @param issuer the raw {@code iss} claim decoded from an unverified id_token
     * @return the canonical trusted-set element, or {@code null} when untrusted
     */
    @Nullable
    String trustedIssuerOrNull(@Nullable String issuer) {
        if (issuer == null || issuer.isBlank()) {
            return null;
        }
        Set<String> trusted = domains.trustedIssuers();
        // No tenancy config at all -> nothing to validate against, and domainOf ignores
        // iss anyway. Never stamp an unvalidated value. (Deliberately NOT isTrusted():
        // it fails OPEN here -- see the class doc.)
        if (trusted == null || trusted.isEmpty()) {
            return null;
        }
        String candidate = trimSlash(issuer);
        // Strict membership. Return the SET's element so the persisted value is
        // byte-identical to the DomainRegistry key user-bff matches against.
        for (String t : trusted) {
            if (t != null && t.equals(candidate)) {
                return t;
            }
        }
        return null;
    }

    /**
     * Persist the account's Casdoor issuer for {@code accountId}, but ONLY when {@code
     * issuer} validates as a member of the configured trusted set (see the class doc — the
     * id_token is not signature-verified, so an unvalidated issuer would be a cross-brand
     * forgery primitive).
     *
     * <p>An untrusted, unknown, blank or null issuer is a NO-OP: it never fails the login
     * and never clears a previously-stamped value. "Keep what we last verified, else stay
     * null and let the consumer fail closed" strictly beats both erasing a working brand
     * binding and writing an attacker-chosen one. Fast-paths to a pure read when the
     * persisted value already matches (the repeat-sign-in shape). An unknown {@code
     * accountId} no-ops at the UPDATE (0 rows), exactly like the sibling projections'
     * targeted writes.
     */
    public Mono<Void> stamp(String accountId, @Nullable String issuer) {
        String trusted = trustedIssuerOrNull(issuer);
        if (trusted == null) {
            return Mono.empty();
        }
        return repo.findById(accountId)
                .defaultIfEmpty(new AccountIssuerRow(accountId, null))
                .flatMap(row -> trusted.equals(row.accountIssuer())
                        ? Mono.empty()
                        : repo.updateAccountIssuer(accountId, trusted).then());
    }

    /**
     * Read the persisted Casdoor issuer URI for an account id. Empty {@link Mono} when
     * unset — a row that predates changeset 301, one created off the casdoor mint path
     * (google/discord invite accounts), or one whose last native login presented an
     * issuer this deployment does not trust. Callers surface "unset" as null ({@code
     * IntrospectResponse.issuer}) and consumers MUST degrade to the pre-301 behavior on
     * null — never guess a brand.
     *
     * <p>Re-validated on READ as well as on write: the trusted set is CONFIG, and config
     * changes (a brand decommissioned, {@code app.tenancy.issuers} rewritten) do not
     * rewrite already-stamped rows. Surfacing a no-longer-trusted issuer from a stale row
     * would resurrect exactly the cross-brand scope this changeset exists to prevent, so a
     * row whose stored issuer no longer validates reads as unset (fail closed).
     */
    public Mono<String> issuerOf(String accountId) {
        return repo.findById(accountId)
                .mapNotNull(AccountIssuerRow::accountIssuer)
                .mapNotNull(this::trustedIssuerOrNull);
    }

    /** Mirrors {@code DomainRegistry#trimSlash} (private there) so a configured
     *  {@code https://casdoor/} and a token's {@code https://casdoor} compare equal. */
    private static String trimSlash(String s) {
        if (s == null) {
            return "";
        }
        String t = s.trim();
        return t.endsWith("/") ? t.substring(0, t.length() - 1) : t;
    }
}
