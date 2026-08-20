package net.hugmesh.adminbff.internalapi;

import jakarta.validation.constraints.NotBlank;
import org.jspecify.annotations.Nullable;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.account.AccountCasdoorSubService;
import net.hugmesh.adminbff.account.AccountIssuerService;
import net.hugmesh.adminbff.account.AccountLocalpartService;
import net.hugmesh.adminbff.suspension.SuspensionService;
import net.hugmesh.authcore.account.Account;
import net.hugmesh.authcore.account.AccountStatus;
import net.hugmesh.authcore.account.AccountStore;
import net.hugmesh.authcore.account.BffSession;
import net.hugmesh.authcore.account.BffSessionRow;
import net.hugmesh.authcore.casdoor.BffCustodyCipher;
import net.hugmesh.authcore.casdoor.MfaStepUpService;
import net.hugmesh.authcore.casdoor.OidcExchangeClient;
import net.hugmesh.authcore.config.SessionCookieWebFilter;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

/**
 * In-cluster ACCOUNT/SESSION API for the login surface that is relocating to
 * {@code hugmesh-user-bff-api}. admin-bff owns the account/session DATA (it wires the
 * shared {@link AccountStore} against admin-bff-db); user-bff owns the login/OIDC ENDPOINTS
 * and performs every account/session read+write over THIS thin internal API rather than
 * touching admin-bff-db directly (the two BFF databases are mutually denied at the
 * NetworkPolicy layer).
 *
 * <p>Exposed under {@code /bff/internal/**}, which {@code SecurityConfig} gates to
 * {@code ROLE_SERVICE} — satisfied by a Casdoor client-credentials SERVICE JWT or by the
 * in-cluster {@code X-Internal-Token} (promoted to a SERVICE principal), which is what user-bff
 * and the gateway present. Layered on top: mTLS + auth-core's {@code InternalTokenWebFilter}
 * (constant-time compare) + {@code InternalSurfaceBootGuard}/{@code
 * InternalSurfaceTokenBootGuard}. The SERVICE floor matters MOST here: this controller MINTS a
 * {@code bff_} session for any {@code accountId} and serves the custody Bearer, so a human JWT
 * — including SUPERADMIN — must never reach it. Same idiom as the existing
 * {@code /bff/internal/device-enrollment} and {@code /bff/internal/oidc/first-login} surfaces.
 *
 * <p>Additive + inert: nothing calls these endpoints until user-bff's OIDC login lands
 * (behind {@code app.bff.oidc.enabled}); admin-bff's own {@code AuthController} keeps calling
 * the in-process {@code AccountStore} directly (no hop).
 *
 * <p><b>BFF-JWT-custody tail (band-180).</b> Two more endpoints complete the SSO custody chain
 * (and land together with the {@code bff_session} custody columns + Liquibase band-180 so the
 * schema is never half-applied):
 * <ul>
 *   <li>{@code POST /custody/stamp} — user-bff (which performed the OIDC exchange) sends the
 *       ALREADY-ciphertext (its own {@link BffCustodyCipher}-encrypted) access/refresh blobs;
 *       admin-bff stores them AS-IS via {@link AccountStore#stampCustody} — NO re-encryption.</li>
 *   <li>{@code POST /session/exchange} — the gateway sends a raw {@code bff_} token; admin-bff
 *       resolves the row, decrypts the held access JWT, lazily refreshes it when near expiry
 *       (when a refresh token + the OIDC bean are present), and returns the Bearer. FAIL-CLOSED:
 *       503 when no custody key is configured; 404 on an unknown/expired session; 401 when the
 *       custody blob can't be decrypted (tampered/absent).</li>
 * </ul>
 * Both ride the same {@code ROLE_SERVICE + InternalTokenWebFilter} guard as the endpoints above
 * (zero new wiring). They SHIP DARK: at defaults {@link BffCustodyCipher#isAvailable()} is
 * false (no {@code app.bff.custody-key}) so exchange 503s, the {@link OidcExchangeClient} bean
 * is absent ({@code app.bff.oidc.enabled=false}) so the refresh leg never fires, and the four
 * band-180 columns are never written by the mint path — nothing in-cluster calls these until
 * the gateway bff-exchange flag + the user-bff oidc flag flip.
 */
@RestController
@RequestMapping("/bff/internal")
@Validated
public class InternalAccountController {

    private final AccountStore accounts;
    private final SuspensionService suspensions;
    /** The account-takeover-by-collision guard (see its class doc): resolves + persists
     *  the canonical homeserver localpart for every account this internal API creates
     *  (the native-login {@code ensureAccount} leg is the 3rd of the fix's 3 creation
     *  call sites — the other 2 are {@code AuthController#registerGoogle/registerDiscord}),
     *  and exposes the persisted value on every account-read response below so
     *  user-bff-api's Matrix/Mastodon proxy controllers can read it back instead of
     *  deriving a candidate from a Casdoor JWT claim at mint time. */
    private final AccountLocalpartService localparts;

    /**
     * The A5 part-B cross-carrier route-pin fix (Liquibase changeset 292): stamps the
     * raw Casdoor {@code sub} UUID onto the account row at the native-login
     * {@code ensureAccount} leg (the ONE place the raw id_token is decoded — the
     * session mint at {@code POST /sessions} only ever receives the accountId), and
     * reads it back for {@link IntrospectResponse#casdoorSub} so the gateway can match
     * UUID-form {@code casdoor_user} route pins for bff_ session carriers. Null for
     * legacy/off-path rows — introspect then returns null and the gateway degrades to
     * the pre-292 behavior.
     */
    private final AccountCasdoorSubService casdoorSubs;

    /**
     * The multi-brand bff_-session domain-scope fix (Liquibase changeset 301): stamps the
     * account's OWN Casdoor issuer — the brand discriminator, one Casdoor per brand — onto
     * the account row at the same native-login {@code ensureAccount} leg, and reads it back
     * for {@link IntrospectResponse#issuer} so user-bff's synthetic-Jwt filter can stamp the
     * RIGHT brand's {@code iss} for a bff_ session carrier. Without it that filter can only
     * fall back to its {@code singleTrustedIssuerOrNull}, which stamps NOTHING on a genuinely
     * multi-issuer cluster — so {@code PrincipalDomain.forScope} yields {@code "__deny__"} and
     * every domain-scoped native-login read/write fails closed.
     *
     * <p>SECURITY: the id_token below is decoded but NOT signature-verified, and an issuer
     * DECIDES TENANT SCOPE (unlike {@code casdoorSub}, which only ever ADDS to a deny-wins pin
     * set). {@link AccountIssuerService#stamp} therefore writes ONLY an issuer that is a
     * member of the configured, non-empty trusted set; anything else stamps null and
     * degrades to the pre-301 fail-closed deny.
     */
    private final AccountIssuerService accountIssuers;

    /**
     * The A5 MFA step-up freshness leg (auth-core {@code @Service}). Introspect reports
     * {@code mfaSatisfied} as the WINDOWED snapshot ({@link MfaStepUpService#freshSnapshot})
     * — {@code mfa_satisfied} AND {@code now - mfa_satisfied_at <= freshness} — NOT the raw
     * stored boolean. The gateway's bff_ carrier trusts introspect's answer on PRESENCE of
     * the MFA_SATISFIED authority (its {@code Roles.isMfaSatisfied(Collection)} javadoc
     * explicitly delegates the freshness window to admin-bff), so returning the raw column
     * here would let a stale step-up clear the D8 privileged floor a Casdoor-JWT admin — whom
     * the gateway re-windows — would be re-challenged on.
     */
    private final MfaStepUpService mfaStepUp;

    /**
     * Always-present {@code @Component} (auth-core), but INERT when no {@code app.bff.custody-key}
     * is configured ({@link BffCustodyCipher#isAvailable()} == false). Injected {@code @Nullable}
     * defensively; in practice it is always resolved (the scanned bean), but a null guard keeps
     * the exchange path fail-closed (503) regardless.
     */
    @Nullable
    private final BffCustodyCipher custodyCipher;

    /**
     * The conditional refresh client — present ONLY when {@code app.bff.oidc.enabled=true}
     * (auth-core {@code OidcExchangeConfig}). {@code @Nullable} so Spring resolves it to null when
     * the bean is absent (the {@code RawJwtRefreshService} pattern); a HARD ctor dep on this
     * absent bean would abort context start.
     */
    @Nullable
    private final OidcExchangeClient oidcExchange;

    /** How long before access-token expiry the exchange leg pre-emptively refreshes. */
    private final long refreshSkewSeconds;

    public InternalAccountController(AccountStore accounts,
                                     SuspensionService suspensions,
                                     MfaStepUpService mfaStepUp,
                                     @Nullable BffCustodyCipher custodyCipher,
                                     @Nullable OidcExchangeClient oidcExchange,
                                     @Value("${app.bff.oidc.refresh-skew-seconds:60}") long refreshSkewSeconds,
                                     AccountLocalpartService localparts,
                                     AccountCasdoorSubService casdoorSubs,
                                     AccountIssuerService accountIssuers) {
        this.accounts = accounts;
        this.suspensions = suspensions;
        this.mfaStepUp = mfaStepUp;
        this.custodyCipher = custodyCipher;
        this.oidcExchange = oidcExchange;
        this.refreshSkewSeconds = refreshSkewSeconds;
        this.localparts = localparts;
        this.casdoorSubs = casdoorSubs;
        this.accountIssuers = accountIssuers;
    }

    /**
     * Gateway-facing response shape — mirrors
     * {@code net.hugmesh.gateway.filter.BffSessionAuthFilter.MeResponse} exactly so
     * the gateway can deserialize it without a separate DTO. All fields have safe defaults
     * so a partial row (freshly-minted session before MFA) does not throw.
     *
     * <p>{@code casdoorSub} (changeset 292, the A5 part-B cross-carrier route-pin fix) is
     * the raw Casdoor {@code sub} UUID stamped at the native-login mint — NULLABLE: null
     * for a legacy account row that predates the column (self-heals on its next native
     * login) or one created off the casdoor mint path (google/discord invite accounts).
     * The gateway folds it into the route-pin identity set ONLY when present and
     * non-blank; null degrades to the exact pre-292 behavior.
     *
     * <p>{@code issuer} (changeset 301, the multi-brand bff_-session domain-scope fix) is
     * the account's OWN Casdoor issuer URI — the BRAND discriminator (one Casdoor per
     * brand), a different axis entirely from {@code provider}, which is only the OAuth
     * LOGIN provider (google/discord/casdoor). It is what lets user-bff's synthetic-Jwt
     * filter stamp the right brand's {@code iss} for a bff_ session carrier instead of
     * denying every domain-scoped read/write on a multi-issuer cluster. NULLABLE: null for
     * a legacy row that predates the column (self-heals on its next native login), one
     * created off the casdoor mint path, or one whose token presented an issuer this
     * deployment does not trust. Only ever a VALIDATED, trusted issuer — never the raw
     * decoded claim (see {@link AccountIssuerService}). Consumers MUST re-check it against
     * their own trusted set and degrade to the pre-301 behavior on null/untrusted.
     */
    public record IntrospectResponse(
            String id,
            String provider,
            List<String> roles,
            boolean registrationComplete,
            String status,
            boolean mfaSatisfied,
            @Nullable String casdoorSub,
            @Nullable String issuer
    ) {}

    public record EnsureAccountRequest(@NotBlank String provider, @NotBlank String handle) {
    }

    /**
     * The account-read response shape user-bff-api's {@code AdminBffInternalClient.AccountView}
     * consumes (over {@code /accounts/ensure}, {@code GET /accounts/{id}} and {@code
     * /accounts/{id}/complete} below) — {@link Account} (auth-core) PLUS the persisted, collision
     * -checked homeserver {@code localpart} (Liquibase changeset 290; account-takeover-by-collision
     * fix). Deliberately NOT a field added to auth-core's {@link Account} record itself — see
     * {@code AccountLocalpartRow}'s class doc for why. {@code localpart} is blank only for a row
     * that predates the column / was created off the 3 official call sites; callers that mint a
     * homeserver token from it (user-bff's Matrix/Mastodon proxy controllers) must treat a blank
     * value as "resolve it" rather than falling back to an independently re-derived candidate —
     * exactly the bug this fix closes.
     *
     * <p>{@code mastodonLocalpart} (Liquibase changeset 291) is the coarser Mastodon/Akkoma fold
     * ({@code [a-z0-9_]}, 30-cap) of {@code localpart}, with its OWN {@code UNIQUE} constraint —
     * the residual half of the fix: {@code john.doe}/{@code john-doe} are DISTINCT under the
     * Matrix fold but collapse to one Mastodon localpart, so the Mastodon-mint call sites read
     * THIS field, not a re-fold of {@code localpart}. Same blank-means-"resolve it" contract.
     */
    public record AccountOut(String id, String provider, String handle, boolean registrationComplete,
                             List<String> roles, String localpart, String mastodonLocalpart) {
        static AccountOut of(Account a, String localpart, String mastodonLocalpart) {
            return new AccountOut(a.id(), a.provider(), a.handle(), a.registrationComplete(),
                    a.roles(), localpart == null ? "" : localpart,
                    mastodonLocalpart == null ? "" : mastodonLocalpart);
        }
    }

    public record CreateSessionRequest(@NotBlank String accountId) {
    }

    /**
     * The custody-stamp body from user-bff. {@code encAccess}/{@code encRefresh} are ALREADY
     * {@link BffCustodyCipher} ciphertext (user-bff encrypted them client-side) — admin-bff
     * stores them verbatim, NO re-encryption. {@code encRefresh} may be JSON null (no refresh
     * token in the grant). {@code expiresInSeconds} is the access JWT lifetime.
     */
    public record StampCustodyRequest(@NotBlank String sessionToken, @NotBlank String encAccess,
                                      @Nullable String encRefresh, long expiresInSeconds) {
    }

    /** The exchange body from the gateway: a raw opaque {@code bff_} session token. */
    public record ExchangeRequest(@NotBlank String token) {
    }

    /**
     * Get-or-create the durable account for a provider handle.
     *
     * <p><b>#112 SSO subject extraction.</b> For the native login leg, user-bff's
     * {@code OidcLoginCompletionService} — reached via {@code POST /bff/login}, which runs the
     * PKCE exchange server-side against the internal Casdoor — calls this with
     * {@code provider="casdoor"} and the raw OIDC {@code id_token} as the handle (it
     * deliberately does NOT parse a token claim locally). admin-bff extracts a SHORT,
     * STABLE subject from the id_token here ({@code email} &gt; {@code preferred_username}
     * &gt; {@code sub}) so {@code account.id = idFor("casdoor", subject)} fits
     * {@code varchar(400)} and is stable across logins (the id_token string itself rotates
     * every login and is ~1.5kB — storing it as the handle overflows the column and creates
     * a new account each login). The non-casdoor (invite) providers pass through verbatim.
     */
    @PostMapping("/accounts/ensure")
    public Mono<AccountOut> ensureAccount(@RequestBody EnsureAccountRequest body) {
        String provider = body.provider();
        if ("casdoor".equals(provider)) {
            String handle = subjectFromIdToken(body.handle());
            List<String> roles = rolesFromIdToken(body.handle());
            // A5 part-B (changeset 292): capture the raw Casdoor `sub` UUID HERE — the one
            // place the raw id_token is decoded on the native-login mint path (the session
            // mint at POST /sessions only ever receives the accountId). Stamped on every
            // sign-in like the roles re-sync, so legacy rows self-heal; a token with no
            // decodable sub claim no-ops inside stamp() (never fails the login, never
            // clears a previously-stamped value).
            String casdoorSub = subClaimFromIdToken(body.handle());
            // Changeset 301: capture the account's OWN Casdoor issuer (the BRAND) at the
            // same one decode point, so a bff_ session on a multi-issuer cluster can resolve
            // its brand instead of failing every domain-scoped read/write closed.
            //
            // SECURITY: the id_token is decoded but NOT signature-verified and body.handle()
            // is user-bff-supplied, so this raw claim is FORGEABLE. Unlike casdoorSub (only
            // ever ADDED to a deny-wins pin set), an issuer decides TENANT SCOPE — so
            // stamp() writes it ONLY on strict membership of the configured, non-empty
            // trusted-issuer set and otherwise no-ops (never fails the login, never clears a
            // previously-verified value, degrades to the pre-301 fail-closed deny).
            String issuer = issClaimFromIdToken(body.handle());
            return accounts.ensureAccount(provider, handle, roles)
                    .flatMap(a -> casdoorSubs.stamp(a.id(), casdoorSub).thenReturn(a))
                    .flatMap(a -> accountIssuers.stamp(a.id(), issuer).thenReturn(a))
                    .flatMap(this::withLocalpart);
        }
        return accounts.ensureAccount(provider, body.handle()).flatMap(this::withLocalpart);
    }

    /**
     * Creation call site #3/#3 of the account-takeover-by-collision fix (the other 2 are {@code
     * AuthController#registerGoogle/registerDiscord}): resolve + persist the canonical homeserver
     * localpart for {@code a} (idempotent — a repeat native-login {@code ensureAccount} call for an
     * EXISTING account, which re-runs on every sign-in to sync roles, recomputes the SAME candidate
     * and no-ops) BEFORE returning the account view to user-bff-api. A genuine collision — a
     * DIFFERENT account already holds this localpart — is surfaced as 409, matching this
     * controller's existing {@link ResponseStatusException} idiom (see {@link #subjectFromIdToken}).
     */
    private Mono<AccountOut> withLocalpart(Account a) {
        return localparts.resolveAndPersist(a.id(), a.handle())
                .then(localparts.localpartsOf(a.id()))
                .map(lp -> AccountOut.of(a, lp.localpart(), lp.mastodonLocalpart()))
                .onErrorMap(AccountLocalpartService.CollisionException.class,
                        e -> new ResponseStatusException(HttpStatus.CONFLICT, e.getMessage()));
    }

    /**
     * Extract a short, stable account subject from a Casdoor OIDC {@code id_token}.
     * Prefers {@code email}, then {@code preferred_username}, then {@code sub}. The token
     * arrives over the in-cluster internal surface (mTLS + {@code X-Internal-Token}) from
     * user-bff, which JUST obtained it from the Casdoor token endpoint, so the claim set is
     * decoded (not re-verified) here; the value is only used as a stable account key. If the
     * value is not a three-part JWT (e.g. a non-OIDC caller already passing a bare handle),
     * it is returned unchanged so the contract degrades gracefully.
     */
    private static String subjectFromIdToken(String idToken) {
        if (idToken == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "casdoor handle (id_token) is null");
        }
        String[] parts = idToken.split("\\.");
        if (parts.length != 3) {
            return idToken; // not a JWT — treat as an already-resolved handle.
        }
        try {
            byte[] payload = java.util.Base64.getUrlDecoder().decode(parts[1]);
            com.fasterxml.jackson.databind.JsonNode claims = ID_TOKEN_MAPPER.readTree(payload);
            for (String claim : SUBJECT_CLAIMS) {
                String v = claims.path(claim).asText(null);
                if (v != null && !v.isBlank()) {
                    return v;
                }
            }
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "casdoor id_token carries no email/preferred_username/sub claim");
        } catch (IllegalArgumentException | java.io.IOException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "casdoor id_token is not a decodable JWT", e);
        }
    }

    /**
     * Extract the lowercase, unprefixed role set from a Casdoor {@code id_token}'s
     * {@code roles} claim, for syncing onto the account row via
     * {@code AccountStore.ensureAccount(provider, handle, roles)}. Casdoor's
     * {@code roles} claim is an array of either plain strings or objects with a
     * {@code name} field — the SAME claim/shape the gateway's {@code CasdoorAuthorities}
     * converter reads, in the opposite direction: the gateway PREFIXES each entry to
     * {@code ROLE_<UPPER>} for Spring Security authorities; this STRIPS any
     * {@code ROLE_} prefix and lowercases, matching the BFF session's legacy
     * unprefixed-lowercase convention ({@link Account#roles()} — {@code "admin"}, not
     * {@code "ROLE_ADMIN"}). Returns an empty list (the caller then falls back to the
     * legacy default) when the token isn't decodable or carries no roles claim — never
     * throws, since degrading to the safe "user"-only default beats failing the login
     * over a malformed/missing claim.
     *
     * <p>The returned set is BOUNDED (issue #14) by {@link #MAX_ROLE_CLAIM_ENTRIES},
     * {@link #MAX_ROLE_LENGTH} and {@link #MAX_ROLES_CSV_LENGTH} — see the inline note at
     * the loop for why, and why a truncated list (not a thrown error) is the right
     * degradation.
     */
    private static List<String> rolesFromIdToken(String idToken) {
        if (idToken == null) {
            return List.of();
        }
        String[] parts = idToken.split("\\.");
        if (parts.length != 3) {
            return List.of();
        }
        try {
            byte[] payload = java.util.Base64.getUrlDecoder().decode(parts[1]);
            com.fasterxml.jackson.databind.JsonNode claims = ID_TOKEN_MAPPER.readTree(payload);
            com.fasterxml.jackson.databind.JsonNode rolesClaim = claims.path("roles");
            if (!rolesClaim.isArray()) {
                return List.of();
            }
            // LinkedHashSet: Casdoor can list the same role twice in this claim (e.g. once
            // via a direct grant, once via group membership) — de-dupe, preserving the
            // first-seen order, so the stored CSV/rendered role list is exactly the
            // distinct set the frontend's hasRole()/isAdmin()/isMod() checks expect.
            //
            // Issue #14: the claim is BOUNDED here, before this set is CSV-joined by
            // AccountStore.ensureAccount(provider, handle, roles) into account.roles —
            // varchar(255) (changeset 004). A malformed/attacker-influenced `roles` claim
            // can carry arbitrarily many entries, or one arbitrarily long entry, and the
            // id_token is decoded but NOT signature-verified on this path; an over-long
            // join then fails the INSERT outright, i.e. fails the login. Three narrow,
            // first-seen-wins bounds, none of which a real principal's role set reaches:
            // stop scanning past MAX_ROLE_CLAIM_ENTRIES, DROP any normalized entry longer
            // than MAX_ROLE_LENGTH (dropped, never truncated — a truncated role string is
            // a DIFFERENT role), and stop admitting once the join would exceed
            // MAX_ROLES_CSV_LENGTH. Degrading to a SHORTER role list is the right failure
            // mode here: this column is a cached nav-display field, never an authorization
            // decision boundary (see changeset 260) — the gateway's Casdoor-JWT RBAC is
            // wholly independent of it, so a dropped entry costs a nav item, not a grant.
            java.util.Set<String> roles = new java.util.LinkedHashSet<>();
            int scanned = 0;
            int csvLength = 0;
            for (com.fasterxml.jackson.databind.JsonNode entry : rolesClaim) {
                if (++scanned > MAX_ROLE_CLAIM_ENTRIES) {
                    break;
                }
                String raw = entry.isObject() ? entry.path("name").asText(null) : entry.asText(null);
                if (raw == null || raw.isBlank()) {
                    continue;
                }
                String role = normalizeRole(raw);
                if (role.length() > MAX_ROLE_LENGTH || roles.contains(role)) {
                    continue;
                }
                // The width this entry would add to String.join(",", roles): the role itself,
                // plus the separator it needs when it is not the first one admitted.
                int joined = csvLength + role.length() + (roles.isEmpty() ? 0 : 1);
                if (joined > MAX_ROLES_CSV_LENGTH) {
                    break;
                }
                roles.add(role);
                csvLength = joined;
            }
            return new java.util.ArrayList<>(roles);
        } catch (IllegalArgumentException | java.io.IOException e) {
            return List.of();
        }
    }

    /** Strip a leading {@code ROLE_} (possibly doubled — this org's Casdoor role/group
     *  names are stored WITH the prefix already; mirrors the gateway's
     *  {@code Roles.canonicalRoleName()} double-prefix guard) and lowercase, so
     *  {@code "ROLE_ADMIN"} / {@code "ROLE_ROLE_ADMIN"} both normalize to {@code "admin"}. */
    private static String normalizeRole(String raw) {
        String r = raw;
        while (r.regionMatches(true, 0, "ROLE_", 0, 5)) {
            r = r.substring(5);
        }
        return r.toLowerCase(java.util.Locale.ROOT);
    }

    /**
     * Extract the raw Casdoor {@code sub} claim (the stable UUID) from an OIDC
     * {@code id_token}, for the changeset-292 account stamp — SEPARATE from
     * {@link #subjectFromIdToken}, which applies the {@code email >
     * preferred_username > sub} account-key precedence (when email or
     * preferred_username won, the UUID is exactly what the account id does NOT
     * carry — that is the A5 part-B gap this closes). Mirrors
     * {@link #rolesFromIdToken}'s degrade posture: returns null (never throws) on a
     * non-JWT handle, an undecodable token, or a missing/blank claim — the caller's
     * {@code stamp(null)} is a no-op, so a degenerate token can never fail the
     * login or erase a previously-stamped value.
     */
    @Nullable
    private static String subClaimFromIdToken(String idToken) {
        if (idToken == null) {
            return null;
        }
        String[] parts = idToken.split("\\.");
        if (parts.length != 3) {
            return null; // not a JWT — a bare-handle ensure call carries no sub to capture.
        }
        try {
            byte[] payload = java.util.Base64.getUrlDecoder().decode(parts[1]);
            com.fasterxml.jackson.databind.JsonNode claims = ID_TOKEN_MAPPER.readTree(payload);
            String sub = claims.path("sub").asText(null);
            return (sub == null || sub.isBlank()) ? null : sub;
        } catch (IllegalArgumentException | java.io.IOException e) {
            return null;
        }
    }

    /**
     * Extract the raw {@code iss} claim from an OIDC {@code id_token}, for the
     * changeset-301 brand stamp.
     *
     * <p><b>The returned value is UNVERIFIED and MUST NOT be trusted by the caller.</b>
     * Like {@link #subjectFromIdToken} and {@link #subClaimFromIdToken}, this only
     * base64-decodes the payload — the signature is NOT re-checked here, and the token
     * arrives as a user-bff-supplied request body. An attacker who reaches this endpoint can
     * put any string in this claim. It becomes trustworthy ONLY after {@link
     * AccountIssuerService#stamp} validates it against the configured trusted-issuer set;
     * that validation is the entire security boundary of changeset 301 and must not be
     * bypassed or moved.
     *
     * <p>Mirrors {@link #rolesFromIdToken}'s degrade posture: returns null (never throws) on
     * a non-JWT handle, an undecodable token, or a missing/blank claim — the caller's
     * {@code stamp(null)} is a no-op, so a degenerate token can never fail the login or
     * erase a previously-verified value.
     */
    @Nullable
    private static String issClaimFromIdToken(String idToken) {
        if (idToken == null) {
            return null;
        }
        String[] parts = idToken.split("\\.");
        if (parts.length != 3) {
            return null; // not a JWT — a bare-handle ensure call carries no iss to capture.
        }
        try {
            byte[] payload = java.util.Base64.getUrlDecoder().decode(parts[1]);
            com.fasterxml.jackson.databind.JsonNode claims = ID_TOKEN_MAPPER.readTree(payload);
            String iss = claims.path("iss").asText(null);
            return (iss == null || iss.isBlank()) ? null : iss;
        } catch (IllegalArgumentException | java.io.IOException e) {
            return null;
        }
    }

    /** Stateless JSON reader for decoding the id_token payload (thread-safe, reused). */
    private static final com.fasterxml.jackson.databind.ObjectMapper ID_TOKEN_MAPPER =
            new com.fasterxml.jackson.databind.ObjectMapper();

    /** Subject claims tried in order when deriving a stable account handle from an id_token. */
    private static final String[] SUBJECT_CLAIMS = {"email", "preferred_username", "sub"};

    /** Issue #14 — max {@code roles}-claim array entries {@link #rolesFromIdToken} SCANS.
     *  Bounds the parse work itself for a claim carrying an absurd number of entries;
     *  entries past this are ignored. */
    private static final int MAX_ROLE_CLAIM_ENTRIES = 64;

    /** Issue #14 — max characters in a single NORMALIZED role (post-{@link #normalizeRole},
     *  so the stripped {@code ROLE_} prefix does not count). The longest name in the
     *  platform's role vocabulary is {@code "mastodon_external_client"} (24), so this is
     *  pure headroom; a longer entry is dropped rather than truncated. */
    private static final int MAX_ROLE_LENGTH = 64;

    /** Issue #14 — max characters in the CSV {@code AccountStore.ensureAccount} joins the
     *  role set into: exactly the width of {@code account.roles} (varchar(255), changeset
     *  004), so an over-long {@code roles} claim degrades to a shorter role list instead of
     *  failing the login on an INSERT that no longer fits the column. */
    private static final int MAX_ROLES_CSV_LENGTH = 255;

    /** Read an account by id; 404 when absent. */
    @GetMapping("/accounts/{id}")
    public Mono<AccountOut> account(@PathVariable String id) {
        return accounts.account(id)
                .switchIfEmpty(Mono.error(notFound("account")))
                .flatMap(this::readWithLocalpart);
    }

    /** Mark an account's onboarding complete; 404 when absent. */
    @PostMapping("/accounts/{id}/complete")
    public Mono<AccountOut> complete(@PathVariable String id) {
        return accounts.account(id)
                .switchIfEmpty(Mono.error(notFound("account")))
                .flatMap(accounts::markComplete)
                .flatMap(this::readWithLocalpart);
    }

    /**
     * A pure READ of the already-resolved localpart (never resolves/writes/collision-checks —
     * that only ever happens at {@link #withLocalpart}, an account-CREATION call site). Blank
     * when unset (see {@link AccountOut}'s doc for why that can legitimately happen and how a
     * caller must treat it).
     */
    private Mono<AccountOut> readWithLocalpart(Account a) {
        return localparts.localpartsOf(a.id())
                .map(lp -> AccountOut.of(a, lp.localpart(), lp.mastodonLocalpart()));
    }

    /** The invite gate: is this provider handle on the allowlist? */
    @GetMapping("/allowlist/{provider}/{handle}")
    public Mono<Map<String, Boolean>> allowlist(@PathVariable String provider, @PathVariable String handle) {
        Mono<Boolean> invited = switch (provider) {
            case "google" -> accounts.isEmailInvited(handle);
            case "discord" -> accounts.isDiscordInvited(handle);
            default -> Mono.error(new ResponseStatusException(HttpStatus.BAD_REQUEST, "unknown provider"));
        };
        return invited.map(b -> Map.of("invited", b));
    }

    /** Mint a new opaque {@code bff_} session for an account; 404 when the account is absent. */
    @PostMapping("/sessions")
    public Mono<Map<String, String>> createSession(@RequestBody CreateSessionRequest body) {
        return accounts.account(body.accountId())
                .switchIfEmpty(Mono.error(notFound("account")))
                .flatMap(accounts::newSession)
                .map(token -> Map.of("token", token));
    }

    /** Revoke an opaque {@code bff_} session (logout). Idempotent — always 204. */
    @DeleteMapping("/sessions/{token}")
    public Mono<ResponseEntity<Void>> deleteSession(@PathVariable String token) {
        return accounts.deleteSession(token).then(Mono.just(ResponseEntity.noContent().build()));
    }

    /**
     * List the LIVE (un-expired) opaque {@code bff_} sessions for an account, newest-first —
     * the read user-bff performs to render a user's "active sessions" surface (and to validate,
     * before a revoke, that a target session belongs to the caller).
     *
     * <p><b>Account scoping is the CALLER's responsibility.</b> This internal surface is
     * mTLS + {@code X-Internal-Token} guarded ({@code InternalTokenWebFilter}), so the only
     * client is user-bff, which derives {@code accountId} SERVER-SIDE from the validated JWT
     * principal and passes it here. This endpoint simply lists by the supplied id — it performs
     * no cross-account leak check because there is no untrusted principal at this hop.
     *
     * <p>Returns each row's raw {@code bff_} token (so user-bff can offer a per-session revoke
     * via {@code DELETE /sessions/{token}}) plus the created/expires timestamps. Live-only +
     * newest-first ordering come from {@link AccountStore#sessionsForAccount} (auth-core 2.2.0),
     * which filters {@code expires_at > now()} and orders by {@code created_at} descending. An
     * unknown account yields an empty stream (200 with {@code []}), not a 404 — absent and
     * "no live sessions" are indistinguishable and both are benign for this read.
     */
    @GetMapping("/sessions/{accountId}")
    public Flux<BffSessionRow> sessionsForAccount(@PathVariable String accountId) {
        return accounts.sessionsForAccount(accountId);
    }

    /** The namespaces (per-app access grants) for an account; 404 when the account is absent. */
    @GetMapping("/accounts/{id}/namespaces")
    public Mono<Map<String, List<String>>> namespaces(@PathVariable String id) {
        return accounts.account(id)
                .switchIfEmpty(Mono.error(notFound("account")))
                .flatMap(accounts::namespacesFor)
                .map(ns -> Map.of("namespaces", ns));
    }

    // ──────────────────────────── Gateway BFF session introspection ───────────────────────────

    /**
     * Validate an opaque {@code bff_} session token and return the account details the
     * gateway's {@code BffSessionAuthFilter} needs to build a Spring SecurityContext.
     *
     * <p>The caller sends {@code Authorization: Bearer bff_<token>}; this endpoint resolves
     * the account from the {@code bff_session} table, fetches the suspension status, and
     * reads the per-session MFA-satisfied flag — then returns a JSON body whose shape exactly
     * matches {@code BffSessionAuthFilter.MeResponse} so the gateway can deserialize it without
     * a dedicated DTO.
     *
     * <p>Fail-closed: unknown/expired session → 401. Suspension check is live (not cached):
     * a banned account that presents a still-live session token is denied 200 with
     * {@code status:"banned"}, which the gateway converts to a 403.
     *
     * <p>This endpoint sits on the {@code ROLE_SERVICE} floor: the gateway's {@code bff_} Bearer
     * is inert to the JWT resource server, so the principal comes from its {@code
     * X-Internal-Token} (promoted by {@code SecurityConfig}), with {@code InternalTokenWebFilter}
     * (mTLS + the same header in enforcing mode) as the in-depth layer behind it. It
     * replaces the previous (broken) design where the filter called {@code /bff/me} — that
     * endpoint falls through to {@code anyExchange().authenticated()}, so bff_ Bearers (which
     * are inert to the JWT resource server) received a 401 before the controller was reached.
     */
    @GetMapping("/session/introspect")
    public Mono<IntrospectResponse> introspect(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String header) {
        String token = SessionCookieWebFilter.bffTokenFrom(null, header);
        if (token == null) {
            return Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED, "no session token"));
        }
        return accounts.sessionOf(header)
                .switchIfEmpty(Mono.error(
                        new ResponseStatusException(HttpStatus.UNAUTHORIZED, "unknown or expired session")))
                // Zip account-status + MFA-satisfied checks and build the introspect response.
                .flatMap(account -> buildIntrospectResponse(account, token));
    }

    // ──────────────────────────── BFF-JWT-custody tail (band-180) ────────────────────────────

    /**
     * Stamp the (already-ciphertext) OIDC token custody onto an opaque session — the band-180
     * write user-bff performs after its OIDC exchange. The blobs are stored AS-IS (NO
     * re-encryption — re-encrypting would double-encrypt and the exchange decrypt would yield
     * garbage). 204 on success; 404 when the session token is unknown (rows updated == 0).
     */
    @PostMapping("/custody/stamp")
    @org.springframework.web.bind.annotation.ResponseStatus(HttpStatus.NO_CONTENT)
    public Mono<Void> stampCustody(@RequestBody StampCustodyRequest body) {
        LocalDateTime accessExpiresAt =
                LocalDateTime.now().plusSeconds(body.expiresInSeconds() > 0 ? body.expiresInSeconds() : 3600);
        return accounts.stampCustody(body.sessionToken(), body.encAccess(), body.encRefresh(), accessExpiresAt)
                .flatMap(rows -> rows == 0 ? Mono.error(notFound("session")) : Mono.empty());
    }

    /**
     * Exchange a raw opaque {@code bff_} token for the custody-held access JWT — the read the
     * gateway's bff-exchange filter performs to turn an opaque session into a Bearer it can
     * forward. Lazily refreshes a near-expiry access token (when a refresh token + the OIDC bean
     * are present). FAIL-CLOSED throughout:
     * <ul>
     *   <li>cipher unavailable (no key) ⇒ 503;</li>
     *   <li>unknown/expired session ⇒ 404;</li>
     *   <li>access blob can't be decrypted (tampered/absent custody) ⇒ 401;</li>
     *   <li>a refresh ERROR while the current access is still cryptographically valid ⇒ serve
     *       the current access (it's still a valid JWT — do NOT 401 a still-valid session).</li>
     *   <li>account suspended/banned ⇒ 403 (the {@link #suspensionGate}, BEFORE custody is served).</li>
     * </ul>
     *
     * <p><b>Suspension is enforced HERE, not only at introspect.</b> The gateway's
     * bff-exchange filter swaps an opaque {@code bff_} for the custody JWT BEFORE the
     * principal-reading {@code BffSessionAuthFilter} (which does the introspect-based
     * ban→403) runs, so without a gate at this swap a suspended/banned account would keep
     * authorizing through the gateway on a still-valid custody JWT. {@link #suspensionGate}
     * closes that bypass by consulting the {@code access_suspension} desired-state and
     * refusing the swap for a blocked account.
     */
    @PostMapping("/session/exchange")
    public Mono<Map<String, String>> exchange(@RequestBody ExchangeRequest body) {
        if (custodyCipher == null || !custodyCipher.isAvailable()) {
            return Mono.error(serviceUnavailable("custody disabled"));
        }
        // FAIL-CLOSED: refuse the custody swap for a suspended/banned account (close the
        // bff-exchange-bypasses-ban gap), THEN do the unchanged custody read. Mono.defer so the
        // custody read is not even invoked until the gate passes (banned ⇒ sessionRow untouched).
        return suspensionGate(body.token())
                .then(Mono.defer(() -> accounts.sessionRow(body.token())
                        .switchIfEmpty(Mono.error(notFound("session")))
                        // Decrypt custody, lazily refresh if near expiry, serve the current JWT on refresh failure.
                        .flatMap(s -> exchangeSessionRow(s))));
    }

    /**
     * Refuse the custody swap (403) when the account behind the opaque session is
     * suspended/banned — the fail-closed gate that keeps the bff-exchange path from
     * bypassing the introspect-based ban enforcement. Resolves the account from the raw
     * {@code bff_} token; an unknown session yields an empty signal (the caller's
     * {@code sessionRow} read then 404s as before); an ACTIVE account yields empty
     * (proceed). The suspension read fails OPEN inside {@link SuspensionService#statusFor}
     * (absence of rows ⇒ active), which is correct: the desired-state being unreadable
     * must not 403 a legitimate session here (the swap still requires valid custody).
     */
    private Mono<Void> suspensionGate(String token) {
        return accounts.sessionOfToken(token)
                .flatMap(account -> suspensions.statusFor(account.handle()))
                .flatMap(st -> {
                    String s = (st == null) ? AccountStatus.ACTIVE : st.status();
                    if (AccountStatus.SUSPENDED.equals(s) || AccountStatus.BANNED.equals(s)) {
                        return Mono.<Void>error(forbidden("account-" + s));
                    }
                    return Mono.<Void>empty();
                });
    }

    private static ResponseStatusException notFound(String what) {
        return new ResponseStatusException(HttpStatus.NOT_FOUND, what + " not found");
    }

    private static ResponseStatusException serviceUnavailable(String why) {
        return new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, why);
    }

    private static ResponseStatusException forbidden(String why) {
        return new ResponseStatusException(HttpStatus.FORBIDDEN, why);
    }

    /** Build the introspect response by zipping the account-status, MFA-satisfied,
     *  casdoor-sub and account-issuer lookups. */
    private Mono<IntrospectResponse> buildIntrospectResponse(Account account, String token) {
        Mono<AccountStatus> statusMono = suspensions.statusFor(account.handle());
        // WINDOWED, not the raw column: the gateway's bff_ MFA floor trusts this on the
        // mere presence of the MFA_SATISFIED authority, so a stale stamp must report false
        // here or the D8 privileged floor is bypassable via native login (see field javadoc).
        Mono<Boolean> mfaMono = accounts.mfaStateOf(token)
                .map(mfaStepUp::freshSnapshot)
                .defaultIfEmpty(false);
        // Changeset 292: the raw Casdoor sub UUID for the UUID-form route-pin match.
        // "" sentinel inside the zip (Reactor tuples reject null) → null on the response
        // for a legacy/off-path row, which the gateway treats as "field absent" (the
        // exact pre-292 behavior).
        Mono<String> casdoorSubMono = casdoorSubs.casdoorSubOf(account.id())
                .defaultIfEmpty("");
        // Changeset 301: the account's validated Casdoor issuer (the BRAND) for the
        // multi-brand bff_-session domain scope. Same "" sentinel idiom → null on the
        // response for a legacy/off-path/untrusted row, which user-bff treats as "field
        // absent" (the exact pre-301 fail-closed behavior). issuerOf() re-validates against
        // the trusted set on read, so a row stamped before a tenancy-config change cannot
        // resurrect a no-longer-trusted brand.
        Mono<String> issuerMono = accountIssuers.issuerOf(account.id())
                .defaultIfEmpty("");
        return Mono.zip(statusMono, mfaMono, casdoorSubMono, issuerMono)
                .map(tuple -> new IntrospectResponse(
                        account.id(), account.provider(), account.roles(),
                        account.registrationComplete(),
                        tuple.getT1() != null ? tuple.getT1().status() : AccountStatus.ACTIVE,
                        tuple.getT2(),
                        tuple.getT3().isBlank() ? null : tuple.getT3(),
                        tuple.getT4().isBlank() ? null : tuple.getT4()));
    }

    /** Decrypt the session's custody access token and optionally refresh it if near expiry. */
    private Mono<Map<String, String>> exchangeSessionRow(BffSession s) {
        String access = custodyCipher.decrypt(s.accessTokenEnc());
        if (access == null) {
            // Tampered/absent custody — the gateway then rejects the bff_.
            return Mono.error(unauthorized("no custody"));
        }
        boolean nearExpiry = s.accessTokenExpiresAt() != null
                && s.accessTokenExpiresAt().isBefore(LocalDateTime.now().plusSeconds(refreshSkewSeconds));
        if (nearExpiry && s.refreshTokenEnc() != null && oidcExchange != null) {
            String refresh = custodyCipher.decrypt(s.refreshTokenEnc());
            if (refresh == null) {
                // Can't refresh (refresh blob undecryptable) — serve current access.
                return Mono.just(Map.of("bearer", access));
            }
            return oidcExchange.refresh(refresh)
                    .flatMap(tok -> stampRefreshedCustody(s, tok))
                    // Refresh failed but the current access is still valid — serve it.
                    .onErrorResume(e -> Mono.just(Map.of("bearer", access)));
        }
        return Mono.just(Map.of("bearer", access));
    }

    /** Encrypt and store the refreshed access+refresh tokens, then return the new access Bearer. */
    private Mono<Map<String, String>> stampRefreshedCustody(BffSession s,
                                                              net.hugmesh.authcore.casdoor.OidcTokens tok) {
        String newAccessEnc = custodyCipher.encrypt(tok.accessToken());
        String newRefreshEnc = tok.refreshToken() != null
                ? custodyCipher.encrypt(tok.refreshToken()) : s.refreshTokenEnc();
        LocalDateTime exp = LocalDateTime.now()
                .plusSeconds(tok.expiresInSeconds() > 0 ? tok.expiresInSeconds() : 3600);
        return accounts.stampCustody(s.token(), newAccessEnc, newRefreshEnc, exp)
                .thenReturn(Map.of("bearer", tok.accessToken()));
    }

    private static ResponseStatusException unauthorized(String why) {
        return new ResponseStatusException(HttpStatus.UNAUTHORIZED, why);
    }
}
