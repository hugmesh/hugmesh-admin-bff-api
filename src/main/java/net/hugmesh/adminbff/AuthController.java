package net.hugmesh.adminbff;

import io.swagger.v3.oas.annotations.Operation;

import jakarta.validation.Valid;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.lang.Nullable;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.account.AccountLocalpartService;
import net.hugmesh.adminbff.account.RegistrationDomainResolver;
import net.hugmesh.authcore.account.Account;
import net.hugmesh.authcore.account.AccountStore;
import net.hugmesh.authcore.casdoor.CasdoorAdminClient;
import net.hugmesh.authcore.casdoor.MfaChallengeService;
import net.hugmesh.authcore.config.SessionCookieService;
import net.hugmesh.authcore.config.SessionCookieWebFilter;
import net.hugmesh.adminbff.locallogin.LocalLoginRateLimiter;
import net.hugmesh.adminbff.locallogin.LocalLoginRequest;
import net.hugmesh.adminbff.locallogin.LocalSecretVerifier;
import net.hugmesh.adminbff.profile.ProfileForwarder;
import net.hugmesh.authcore.provision.GatewayRevocationClient;
import net.hugmesh.adminbff.provision.ServiceTokenBroker;
import net.hugmesh.authcore.reserved.ReservedNames;
import net.hugmesh.authcore.account.AccountStatus;
import net.hugmesh.adminbff.suspension.SuspensionService;
import net.hugmesh.adminbff.usage.UsageService;
import net.hugmesh.commons.web.ApiException;
import net.hugmesh.authcore.web.dto.LoginRequest;
import net.hugmesh.authcore.web.dto.RegisterDiscordRequest;
import net.hugmesh.authcore.web.dto.RegisterEmailRequest;
import net.hugmesh.authcore.web.dto.RegisterProfileRequest;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * User-facing BFF endpoints (reactive): the Google/Discord-only, admin-invited
 * TWO-STAGE registration; login; {@code /me}; {@code /me/namespaces}; and the
 * server-side Matrix/Mastodon token brokering. JSON shapes mirror the verified
 * reference impl (mock-bff.mjs) EXACTLY, so the admin-ui / login-ui
 * {@code bff.service.ts} work unchanged.
 *
 * <p>{@code /bff/login} and {@code /bff/register/**} are {@code permitAll} at the
 * resource-server filter chain ({@code SecurityConfig}) because the caller has no
 * Casdoor JWT yet — the BFF itself enforces the invite gate here, then issues an
 * opaque BFF session token (now persisted durably). {@code /me},
 * {@code /me/namespaces} and {@code /provision/**} are {@code authenticated} at
 * the gateway+resource server and additionally validated against the durable BFF
 * session here.
 *
 * <h2>RETIREMENT AUDIT, 2026-09-10 — NONE of the five "shadowed" paths could be
 * retired (issue #2)</h2>
 * The operator answered "retire" for the legacy user-facing paths. Measured
 * BEFORE deleting anything, and the answer could not be carried out: ZERO of the
 * five candidates — {@code POST /register/google}, {@code POST /register/discord},
 * {@code GET /me/namespaces}, {@code POST /provision/matrix},
 * {@code POST /provision/mastodon} — is safe to remove, because "shadowed" holds
 * on ONE deployment lane only and every one of them still has a live caller.
 *
 * <h3>The same five paths route differently on the three lanes</h3>
 * <ul>
 *   <li><b>kind / cluster — SHADOWED.</b> The DEPLOYED ConfigMap
 *       {@code hugmesh-frontend/hugmesh-fe-gateway-routes} (read live off the running
 *       cluster on 2026-09-10, not just the repo file) declares
 *       {@code Path=/bff/register/**}, {@code Path=/bff/me/**} and
 *       {@code Path=/bff/provision/**} to user-bff BEFORE the {@code /bff/**}
 *       admin-bff catch-all, and Spring Cloud Gateway matches in declared order. All
 *       five therefore reach user-bff — which implements NONE of them: its
 *       {@code SsoAuthController} is the ONLY controller at the {@code /bff} root and
 *       maps exactly {@code POST /login}, {@code POST /register},
 *       {@code DELETE /session}, {@code GET /me}, {@code GET /session}
 *       (verified on hugmesh-user-bff-api origin/main). So on a cluster these calls
 *       404 TODAY. That is a routing defect in the generator's gateway table, NOT a
 *       reason to delete the handler that still serves the other two lanes.</li>
 *   <li><b>compose test stack — NOT SHADOWED.</b>
 *       {@code hugmesh-generator tests/stack/gateway-routes/fe/application-routes.yml:274}
 *       lists user-bff's paths EXACTLY
 *       ({@code Path=/bff/login,/bff/register,/bff/session,/bff/session/**,/bff/me,/bff/user/**,…}),
 *       with no {@code /bff/provision} entry at all. {@code /bff/register/google},
 *       {@code /bff/register/discord}, {@code /bff/me/namespaces} and
 *       {@code /bff/provision/*} consequently fall through to the {@code /bff/**}
 *       admin-bff catch-all and are served BY THIS CLASS. Retiring them breaks the
 *       compose lane and its e2e suite outright.</li>
 *   <li><b>device images — NO GATEWAY AT ALL.</b>
 *       {@code hugmesh-generator tests/qemu/seed-accounts.sh:408,464} curls
 *       {@code POST ${BFF}/bff/register/google} straight at
 *       {@code http://127.0.0.1:8403} (admin-bff on the node) as the bootstrap
 *       fallback taken when a fresh mesh has no admin account yet. No route table can
 *       shadow that call.</li>
 * </ul>
 *
 * <h3>Live callers, each read off origin/main of its own repo</h3>
 * <ul>
 *   <li>{@code POST /provision/matrix} + {@code POST /provision/mastodon} —
 *       hugmesh-login-ui {@code src/app/bff.service.ts:387-399}
 *       ({@code provisionServiceTokens()}), invoked from {@code login()},
 *       {@code loginLocal()} and {@code completeRegistration()} on EVERY successful
 *       sign-in. Also {@code hugmesh-generator tests/stack/seed-e2e.sh:547} and
 *       {@code tests/stack/mock-bff.mjs:318}.</li>
 *   <li>{@code GET /me/namespaces} — hugmesh-admin-ui
 *       {@code src/app/bff.service.ts:77} ({@code myNamespaces()}, a plain
 *       {@code fetch}). Also {@code tests/stack/mock-bff.mjs:433} and the e2e
 *       {@code tests/e2e/specs/17-rbac-user-and-pending.spec.ts:49}.</li>
 *   <li>{@code POST /register/google} — {@code tests/qemu/seed-accounts.sh:408,464},
 *       direct-to-admin-bff as described above.</li>
 *   <li>{@code POST /register/discord} — the WEAKEST case: no hand-written caller
 *       was found in any UI (only the generated {@code src/app/api/fn/auth-controller/}
 *       clients in login-ui, admin-ui and superadmin-service-catalog-ui). It still
 *       stays, because it is not shadowed on the compose or device lanes either, so
 *       "unreachable" is not established for it — only "uncalled by a UI".</li>
 * </ul>
 *
 * <p>Two neighbouring paths that were never retirement candidates were re-measured at
 * the same time, because the 2026-09-04 audit on #2 overstated both: {@code POST
 * /login/local} is called by hugmesh-login-ui {@code src/app/bff.service.ts:314}, and
 * {@code POST /sessionOut} by hugmesh-login-ui {@code src/app/session.service.ts:444}
 * ({@code clear()} awaits it before dropping local state). The audit's "admin-ui" for
 * both is wrong: admin-ui origin/main has NO production caller for either — only the
 * generated client — so its counts were counting {@code openapi.json} and
 * {@code src/app/api/} entries, not call sites.
 *
 * <h3>What was probed live, and what a probe still cannot settle</h3>
 * All five were GET-probed (GET only — a GET onto a {@code @PostMapping} cannot
 * mutate) through the REAL running front door,
 * {@code curl -sk -H 'Host: hugmesh.net' https://172.18.0.2<path>}: every one
 * answered <b>401</b>, as did {@code /bff/register}, {@code /bff/me},
 * {@code /bff/session} and {@code /bff/register/complete}, while the controls
 * {@code GET /bff/login} answered 405 and {@code GET /bff/public/theme} answered 200.
 * The gateway's coarse {@code anyExchange().authenticated()} floor fires BEFORE
 * routing for every path outside {@code SecurityConfig.PUBLIC_PATHS} (which ends at
 * {@code /bff/login}), so an anonymous probe cannot reveal which service answers.
 * Settling that live needs a request carrying a valid {@code bff_} session — i.e. a
 * real sign-in, which mutates — or an in-cluster call straight at the two BFF
 * Services, which serve TLS with {@code client-auth=need}.
 *
 * <p><b>What would unblock the retirement</b>, per path: a user-bff implementation
 * (or a deliberate product decision to drop the feature) for the three lanes to agree
 * on, the compose route table narrowed or widened to match the cluster's, the two
 * {@code bff.service.ts} call sites migrated, and {@code seed-accounts.sh} moved off
 * {@code /bff/register/google}. Until then every mapping below stays; see
 * {@code LegacyUserPathRetirementGuardTest}.
 */
@RestController
@RequestMapping("/bff")
@Validated
public class AuthController {

    private final AccountStore store;
    private final ServiceTokenBroker broker;
    private final UsageService usage;
    /** The account-takeover-by-collision guard: resolves + persists (at the 2
     *  registration call sites here) and reads back (at {@link #provision}) the
     *  canonical, collision-checked homeserver localpart — see its class doc. */
    private final AccountLocalpartService localparts;
    /** BFF-computed principal account-state (active|suspended|banned) read off the
     *  access_suspension desired-state — surfaced on /bff/me + the /bff/login response. */
    private final SuspensionService suspensions;
    /** Forwards the registration display-name / screen-reader-name to the user-bff
     *  profile (the a11y aria-label source). Gated stub-seam — never hard-fails. */
    private final ProfileForwarder profiles;
    /** A2 cookie MINT (ships dark behind app.session.cookie.enabled). When enabled,
     *  login/register/sessionOut also Set-Cookie the opaque session token, host-only
     *  scoped to the validated-issuer brand host. */
    private final SessionCookieService cookies;
    /** Best-effort gateway RevocationList writer — logout RevocationLists the subject's
     *  homeserver localparts so a logged-out session's brokered tokens are denied. */
    private final GatewayRevocationClient revocations;
    /** A4 MFA challenge orchestrator — logout CLEARS the caller's advisory Casdoor
     *  {@code mfa_satisfied_at} Property (bounds the cross-session bleed window). Inert
     *  when MFA ships dark / no Casdoor admin client is wired. */
    private final MfaChallengeService mfaChallenge;
    /** REAL Casdoor credential oracle for {@code POST /bff/login/local} (passwordless
     *  local-secrets login). {@code @Nullable}: present ONLY when
     *  {@code app.local-login.enabled=true} (see {@code LocalLoginConfig}); when null the
     *  local endpoint fails closed (401) — no agent secret is ever trusted without a real
     *  Casdoor validation. Every OTHER endpoint is byte-for-byte unaffected. */
    @Nullable
    private final LocalSecretVerifier localSecretVerifier;
    /** Per-IP AND per-(IP,username) throttle in front of {@link LocalSecretVerifier#verify} (PR
     *  #198 security review, MEDIUM finding; the per-(IP,username) shape is PR #199 security
     *  review, HIGH finding) — see {@link LocalLoginRateLimiter} for the exact numbers and why.
     *  ALWAYS present (cheap, no I/O): harmless when local-login ships dark, since
     *  {@code loginLocal} already 401s before it would be consulted. */
    private final LocalLoginRateLimiter localLoginRateLimiter;
    /** Resolves the REQUESTING DOMAIN the two-stage registration gate is evaluated against
     *  (auth-core issue #1). The invite row has been domain-stamped since changeset 220, but
     *  the gate READ was not, so an invite an admin of brand X issued also admitted that
     *  identifier here on brand Y. A registration is PRE-AUTHENTICATION, so there is no
     *  {@code PrincipalDomain} to thread — see the resolver's class doc for why the domain is
     *  derived ONLY from server-trusted inputs (a body field would re-open the same hole). */
    private final RegistrationDomainResolver registrationDomains;

    public AuthController(AccountStore store, ServiceTokenBroker broker, UsageService usage,
                          SuspensionService suspensions, ProfileForwarder profiles,
                          SessionCookieService cookies, GatewayRevocationClient revocations,
                          MfaChallengeService mfaChallenge,
                          @Nullable LocalSecretVerifier localSecretVerifier,
                          LocalLoginRateLimiter localLoginRateLimiter,
                          AccountLocalpartService localparts,
                          RegistrationDomainResolver registrationDomains) {
        this.store = store;
        this.broker = broker;
        this.usage = usage;
        this.suspensions = suspensions;
        this.profiles = profiles;
        this.cookies = cookies;
        this.revocations = revocations;
        this.mfaChallenge = mfaChallenge;
        this.localSecretVerifier = localSecretVerifier;
        this.localLoginRateLimiter = localLoginRateLimiter;
        this.localparts = localparts;
        this.registrationDomains = registrationDomains;
    }

    // ── Registration stage 1: create an invited Casdoor account ────────
    // The optional body carries the login-ui's displayName (UTF-8) +
    // screenReaderName (ASCII a11y aria-label); both are forwarded to the user-bff
    // profile (best-effort) so the spoken name is recorded at registration.
    @Operation(summary = "Register google", operationId = "authRegisterGoogle")
    @PostMapping("/register/google")
    public Mono<Map<String, Object>> registerGoogle(@Valid @RequestBody RegisterEmailRequest body,
                                                    @Nullable Authentication auth,
                                                    ServerWebExchange exchange) {
        String email = str(body.email()).toLowerCase();
        // DOMAIN-SCOPED GATE (auth-core issue #1): only an invite stamped with THIS
        // request's brand admits the registration. `auth` is null/anonymous on the ordinary
        // untokened registration and the resolver falls back to the deployment's own brand;
        // it never reads a caller-supplied domain. See RegistrationDomainResolver.
        return store.isEmailInvited(email, registrationDomains.forRegistration(auth))
                .flatMap(invited -> {
                    if (!invited) return Mono.error(ApiException.forbidden("email not invited by an admin"));
                    return store.ensureAccount("google", email)
                            .flatMap(this::persistLocalpart)
                            .flatMap(store::restartOnboarding)
                            .flatMap(a -> forwardProfile(a, body.displayName(), body.screenReaderName())
                                    .then(emitAndSession(email, a, "register", List.of(), exchange)));
                });
    }

    @Operation(summary = "Register discord", operationId = "authRegisterDiscord")
    @PostMapping("/register/discord")
    public Mono<Map<String, Object>> registerDiscord(@Valid @RequestBody RegisterDiscordRequest body,
                                                     @Nullable Authentication auth,
                                                     ServerWebExchange exchange) {
        String handle = str(body.username()).toLowerCase();
        // DOMAIN-SCOPED GATE (auth-core issue #1) — see registerGoogle above.
        return store.isDiscordInvited(handle, registrationDomains.forRegistration(auth))
                .flatMap(invited -> {
                    if (!invited) return Mono.error(ApiException.forbidden("discord username not invited by an admin"));
                    return store.ensureAccount("discord", handle)
                            .flatMap(this::persistLocalpart)
                            .flatMap(store::restartOnboarding)
                            .flatMap(a -> forwardProfile(a, body.displayName(), body.screenReaderName())
                                    .then(emitAndSession(handle, a, "register", List.of(), exchange)));
                });
    }

    /**
     * Registration call site #1/#2 of the account-takeover-by-collision fix (the 3rd is
     * {@code InternalAccountController#ensureAccount}): resolve + persist the canonical
     * homeserver localpart for a freshly-{@code ensureAccount}'d row BEFORE any session
     * is issued, so a colliding registration is rejected here rather than silently
     * succeeding and later hijacking a different account's homeserver identity at
     * {@link #provision}. Passes the (unchanged) account through on success so this
     * composes into the existing {@code .flatMap(store::restartOnboarding)} chain.
     */
    private Mono<Account> persistLocalpart(Account a) {
        return localparts.resolveAndPersist(a.id(), a.handle())
                .thenReturn(a)
                .onErrorMap(AccountLocalpartService.CollisionException.class,
                        e -> ApiException.conflict(e.getMessage()));
    }

    // ── Login: only for an existing (invited + created) account ────────
    @Operation(summary = "Login", operationId = "authLogin")
    @PostMapping("/login")
    public Mono<Map<String, Object>> login(@Valid @RequestBody LoginRequest body, Authentication auth,
                                           ServerWebExchange exchange) {
        String provider = str(body.provider());
        if (provider.isEmpty()) provider = body.username() != null ? "discord" : "google";
        else provider = provider.toLowerCase();
        String handle = str(body.email() != null ? body.email() : body.username()).toLowerCase();
        // Surface the *_DOMAINLOCKED marker authorities from the validated JWT (when
        // the gateway forwarded one) into the session roles[] so the matrix/mastodon
        // UIs can read the domain-locked flag. They are in the token but not on the
        // account roles, so they would otherwise be lost on the BFF session.
        List<String> domainlock = domainlockRoles(auth);
        return store.account(AccountStore.idFor(provider, handle))
                .switchIfEmpty(Mono.error(ApiException.unauthorized("no account — register first")))
                .flatMap(a -> emitAndSession(handle, a, "login", domainlock, exchange));
    }

    // ── Login (local passwordless secrets): the loopback-agent handoff path ──
    /**
     * {@code POST /bff/login/local} — SIBLING of {@link #login} for the passwordless
     * local-secrets flow (login-ui role-picker → loopback agent {@code /v1/handoff} → this
     * endpoint, contract v1). The ONE and ONLY difference from {@code /bff/login} is the
     * credential SOURCE: the caller supplies a {@code username}+{@code secret} the local agent
     * vended from an on-disk role-credential file. The rigor is NOT relaxed — it is INCREASED:
     * {@code /bff/login} trusts the fronting gateway's already-validated Casdoor session, but
     * this endpoint is reached pre-token from a loopback agent, so it FULLY validates the secret
     * against Casdoor HERE ({@link LocalSecretVerifier} — a real resource-owner-password grant)
     * BEFORE any session is minted. There is NO trust of the agent and NO trust of the
     * client-asserted {@code roleId} (telemetry only; the granted roles come from the looked-up
     * account, never the request).
     *
     * <p>On a valid credential the SAME account lookup + {@link #emitAndSession} path runs, so the
     * response body + httpOnly {@code bff_} cookie are byte-identical to {@code /bff/login}. Any
     * failure — a blank/invalid secret, a Casdoor-less deployment (verifier not wired /
     * {@code app.local-login.enabled=false}), or an unknown account — returns a 401 with the
     * SAME shape a bad password yields (no oracle for which of the three failed).
     *
     * <p><b>Throttled BEFORE Casdoor is ever called</b> ({@link LocalLoginRateLimiter} — PR #198
     * security review, MEDIUM finding): unauthenticated and un-rate-limited, this endpoint is a
     * Casdoor credential oracle — one real {@code grant_type=password} call per request for an
     * attacker-chosen username. A caller over EITHER the per-IP or per-(IP,username) budget gets
     * a 429 here, and {@link LocalSecretVerifier#verify} is never invoked for that request.
     */
    @Operation(summary = "Login local", operationId = "authLoginLocal")
    @PostMapping("/login/local")
    public Mono<Map<String, Object>> loginLocal(@Valid @RequestBody LocalLoginRequest body,
                                                Authentication auth, ServerWebExchange exchange) {
        // Fail CLOSED when the Casdoor verifier is not wired (app.local-login.enabled=false):
        // NEVER trust the agent secret — return the same 401 a bad credential yields. This keeps
        // the default build free of any local-login trust surface.
        if (localSecretVerifier == null) {
            return Mono.error(ApiException.unauthorized("invalid credentials"));
        }
        String username = str(body.username());
        String secret = body.secret();
        // Per-IP AND per-(IP,username) throttle — BEFORE the Casdoor call below. A throttled
        // request returns 429 immediately; verify() is never reached (the whole point is to stop
        // the oracle, not merely decorate it).
        if (!localLoginRateLimiter.tryAcquire(clientIp(exchange), username)) {
            return Mono.error(new ApiException(HttpStatus.TOO_MANY_REQUESTS,
                    "too many attempts, try again shortly"));
        }
        // Local role accounts carry no provider field; derive it the SAME way /bff/login does
        // when only one identifier is present — an '@'-bearing username is a google-style identity
        // (the contract's brandowner@acme.local shape), otherwise a discord handle. The account is
        // keyed on the EXACT username Casdoor validates (lowercased to match /bff/login's handle
        // normalisation), so the validated identity and the loaded account are the same principal.
        String provider = username.indexOf('@') > 0 ? "google" : "discord";
        String handle = username.toLowerCase();
        List<String> domainlock = domainlockRoles(auth);
        // 1) REALLY validate the secret through Casdoor. 2) only THEN reuse the SAME account
        // lookup + emitAndSession/cookies.mint path /bff/login uses. A false verdict short-circuits
        // to the identical 401 (no account is touched, no session is minted).
        return localSecretVerifier.verify(username, secret)
                .flatMap(valid -> Boolean.TRUE.equals(valid)
                        ? store.account(AccountStore.idFor(provider, handle))
                                .switchIfEmpty(Mono.error(ApiException.unauthorized("invalid credentials")))
                                .flatMap(a -> emitAndSession(handle, a, "login", domainlock, exchange))
                        : Mono.error(ApiException.unauthorized("invalid credentials")));
    }

    /**
     * Record usage (fire-and-forget) then issue a durable session for the account,
     * additionally folding any forwarded domain-lock marker roles + the BFF-computed
     * account status into the session response. When the A2 cookie mode is enabled
     * ({@code app.session.cookie.enabled}), ALSO Set-Cookie the opaque session token
     * (httpOnly+Secure+SameSite=Lax+Path=/, host-only to the validated-issuer brand
     * host). The token STAYS in the response body regardless (cookie ships dark —
     * existing UIs keep reading the body token).
     */
    private Mono<Map<String, Object>> emitAndSession(String handle, Account a, String action,
                                                     List<String> extraRoles, ServerWebExchange exchange) {
        usage.record(handle, a.roles(), action).subscribe();
        return Mono.zip(store.newSession(a), suspensions.statusFor(a.handle()))
                .map(t -> {
                    String token = t.getT1();
                    ResponseCookie cookie = cookies.mint(exchange.getRequest(), token);
                    if (cookie != null) {
                        exchange.getResponse().addCookie(cookie);
                    }
                    return sessionOut(token, a, extraRoles, t.getT2());
                });
    }

    // ── Registration stage 2: complete; releases service entitlement ───
    // The optional body carries the same displayName + screenReaderName as stage 1,
    // for login-ui flows that collect the a11y names at completion rather than at
    // invite-accept; they are forwarded to the user-bff profile (best-effort).
    @Operation(summary = "Complete", operationId = "authComplete")
    @PostMapping("/register/complete")
    public Mono<Map<String, Object>> complete(
            Authentication auth,
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String header,
            @RequestBody(required = false) @Valid RegisterProfileRequest body) {
        String displayName = body == null ? null : body.displayName();
        String screenReaderName = body == null ? null : body.screenReaderName();
        return me(auth, header)
                .flatMap(store::markComplete)
                .flatMap(done -> forwardProfile(done, displayName, screenReaderName)
                        .thenReturn(done))
                .map(done -> {
                    usage.record(done.id(), done.roles(), "complete").subscribe();
                    usage.record(done.id(), done.roles(), "matrix.entitled").subscribe();
                    usage.record(done.id(), done.roles(), "mastodon.entitled").subscribe();
                    Map<String, Object> out = new LinkedHashMap<>();
                    out.put("id", done.id());
                    out.put("registrationComplete", true);
                    return out;
                });
    }

    @Operation(summary = "Me endpoint", operationId = "authMeEndpoint")
    @GetMapping("/me")
    public Mono<Map<String, Object>> meEndpoint(
            Authentication auth,
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String header) {
        // /me also surfaces the *_DOMAINLOCKED marker roles from the validated JWT so
        // a returning principal (already holding a Casdoor token) sees the same
        // domain-locked flag the login response carries.
        List<String> domainlock = domainlockRoles(auth);
        return me(auth, header)
                .flatMap(a -> suspensions.statusFor(a.handle())
                        .map(status -> meOut(a, domainlock, status)));
    }

    // ── The caller's own granted namespaces (gates observability views) ─
    @Operation(summary = "My namespaces", operationId = "authMyNamespaces")
    @GetMapping("/me/namespaces")
    public Mono<Map<String, Object>> myNamespaces(
            Authentication auth,
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String header) {
        return me(auth, header)
                .flatMap(store::namespacesFor)
                .map(ns -> Map.of("namespaces", ns));
    }

    // ── A2: cookie-mode session hydration ──────────────────────────────
    /**
     * Authenticated session hydration for cookie-mode UIs: {@code {roles,
     * registrationComplete, mfaSatisfied}}. A cookie-mode UI cannot read the httpOnly
     * session cookie from JS, so it hydrates its session state from this endpoint after a
     * cookie-borne login. The carrier is resolved dual (the cookie bridge synthesises the
     * Bearer header from the cookie, so {@code header} carries the {@code bff_} token in
     * BOTH carriers). {@code mfaSatisfied} reflects the raw {@code bff_session.mfa_satisfied}
     * stamp (false until a fresh MFA challenge stamps it; default false = fail closed).
     */
    @Operation(summary = "Session", operationId = "authSession")
    @GetMapping("/session")
    public Mono<Map<String, Object>> session(
            Authentication auth,
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String header) {
        String token = SessionCookieWebFilter.bffTokenFrom(null, header);
        // Resolve account then merge the MFA satisfaction state into the session response.
        return me(auth, header).flatMap(a -> buildSessionResponse(a, token));
    }

    /** Merge MFA satisfaction state from the opaque session into the /session response body. */
    private Mono<Map<String, Object>> buildSessionResponse(Account a, String token) {
        Mono<Boolean> mfa = (token == null)
                ? Mono.just(false)
                : store.mfaStateOf(token).map(AccountStore.MfaState::satisfied).defaultIfEmpty(false);
        return mfa.map(mfaSatisfied -> {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("roles", a.roles());
            out.put("registrationComplete", a.registrationComplete());
            out.put("mfaSatisfied", mfaSatisfied);
            return out;
        });
    }

    // ── A2: real logout ────────────────────────────────────────────────
    /**
     * Logout: delete the opaque {@code bff_session} row (so the token no longer resolves),
     * EXPIRE the session cookie (cookie mode), and best-effort RevocationList the subject's
     * homeserver localparts on the gateway (so any token brokered under this identity is
     * denied at the gateway). Carrier-agnostic — resolves the token from the cookie-bridged
     * {@code Authorization} header. Idempotent: an unknown/expired token returns
     * {@code {loggedOut:true}} with no row to delete.
     *
     * <p>hugmesh-generator#549: the fe route tables now send the browser-facing
     * {@code POST /bff/sessionOut} to user-bff's alias instead, so a browser should never
     * reach this copy at all.
     *
     * <p><b>Correction (land-lane re-review, admin-bff-api#102):</b> this method also takes a
     * {@code @CookieValue} for the {@code bff_} session cookie and resolves via
     * {@code bffTokenFrom(cookie, header)} rather than the prior {@code bffTokenFrom(null,
     * header)}. The PR that added this originally claimed that closed a live "silent no-op" for
     * a cookie-only caller — that claim does NOT hold for any request this running app actually
     * serves. {@link SessionCookieWebFilter} is unconditionally component-scanned into this app
     * ({@code AdminBffApplication}'s {@code scanBasePackages} includes
     * {@code net.hugmesh.authcore}) and runs at {@code Ordered.HIGHEST_PRECEDENCE + 5} — before
     * every controller, on every request — so a cookie-only caller's {@code bff_session} is
     * ALREADY bridged into a synthesised {@code Authorization} header before this method is
     * ever entered. {@code bffTokenFrom(null, header)} (the pre-#102 code) would have resolved
     * the SAME token via that bridged header. Proven by mutation testing: reverting this
     * parameter still leaves {@code AuthControllerSessionCookieTest
     * #sessionOut_viaCookieOnly_deletesRow} green, because that test (correctly, matching the
     * real app) imports the filter.
     *
     * <p>What DOES hold: reading the cookie directly here is still the more explicit,
     * carrier-agnostic form, matching {@link #session(Authentication, String)} / {@code /me}
     * above, and it is independently correct in isolation from the filter — see
     * {@code AuthControllerSessionOutUnitTest}, a plain Mockito unit test with NO Spring context
     * (a {@code @WebFluxTest} slice cannot isolate the filter here: it inherits
     * {@code AdminBffApplication}'s {@code scanBasePackages} and auto-detects the filter
     * regardless of any {@code @Import} list — see that class's javadoc for the full story).
     * That test goes RED on the pre-#102 code. Treat this change as hardening / explicit
     * precedence for a caller that might one day reach this method without the filter in front
     * of it (a different composition, a future refactor) — NOT as a fix for any behavior
     * reachable in the app as deployed today.
     */
    @Operation(summary = "Session out", operationId = "authSessionOut")
    @PostMapping("/sessionOut")
    public Mono<Map<String, Object>> sessionOut(
            Authentication auth,
            @CookieValue(value = SessionCookieWebFilter.SESSION_COOKIE, required = false) String cookie,
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String header,
            ServerWebExchange exchange) {
        String token = SessionCookieWebFilter.bffTokenFrom(cookie, header);
        // Expire the cookie regardless of carrier (a Bearer-auth logout must still clear any
        // cookie the browser holds). No-op when cookie mode is disabled.
        ResponseCookie expired = cookies.expire();
        if (expired != null) {
            exchange.getResponse().addCookie(expired);
        }
        Mono<String> deletion = (token == null) ? Mono.empty() : store.deleteSession(token);
        return deletion
                .flatMap(accountId -> revokeSubject(accountId).thenReturn(accountId))
                .thenReturn(Map.<String, Object>of("loggedOut", true));
    }

    /** Best-effort RevocationList the logged-out subject's homeserver localparts (matrix +
     *  mastodon) AND clear the caller's advisory Casdoor {@code mfa_satisfied_at} Property
     *  (D8 — bounds the cross-session bleed: a parallel same-user session can otherwise ride a
     *  stale Property until the freshness window elapses). All best-effort — logout NEVER fails
     *  on a revocation / Casdoor hiccup, and the clear is inert when MFA ships dark / no admin
     *  client is wired. */
    private Mono<Void> revokeSubject(String accountId) {
        if (accountId == null || accountId.isBlank()) return Mono.empty();
        // account id is "provider:handle".
        int colon = accountId.indexOf(':');
        String provider = colon >= 0 ? accountId.substring(0, colon) : "google";
        String handle = colon >= 0 ? accountId.substring(colon + 1) : accountId;
        // The Casdoor username for this identity (gmail local-part / discord handle).
        String casdoorUsername = CasdoorAdminClient.usernameOf(provider, handle);
        // Read the PERSISTED, collision-checked localpart rather than re-deriving it here: a
        // pre-fix account whose localpart was auto-disambiguated by the changeset-290 backfill
        // (a numeric suffix) would otherwise have this re-derivation silently revoke the WRONG
        // (colliding) localpart's homeserver token instead of its own. Best-effort like the rest
        // of this method: fall back to the raw derivation on a lookup miss (should not happen
        // post-registration) rather than ever blocking logout on it.
        return localparts.localpartOf(accountId)
                .defaultIfEmpty(ServiceTokenBroker.matrixUser(handle))
                .flatMap(localpart -> revocations.revokeCoarse("matrix", localpart, "logout", 0)
                        .then(revocations.revokeCoarse("mastodon", localpart, "logout", 0)))
                .then(mfaChallenge.clearProperty(casdoorUsername));
    }

    // ── Broker real Matrix/Mastodon tokens (post full registration) ────
    // Each platform is now gated on its access role (method-level, on top of the
    // gateway + resource-server path rules): brokering a Matrix token requires
    // ROLE_MATRIX, a Mastodon token requires ROLE_MASTODON. A user whose platform
    // role was removed by an access_suspension therefore cannot mint a fresh token
    // here (and ServiceTokenBroker additionally refuses a suspended localpart).
    @PreAuthorize("hasRole('MATRIX')")
    @Operation(summary = "Provision matrix", operationId = "authProvisionMatrix")
    @PostMapping("/provision/matrix")
    public Mono<Map<String, Object>> provisionMatrix(
            Authentication auth,
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String header) {
        return me(auth, header).flatMap(me -> provision(me, true));
    }

    @PreAuthorize("hasRole('MASTODON')")
    @Operation(summary = "Provision mastodon", operationId = "authProvisionMastodon")
    @PostMapping("/provision/mastodon")
    public Mono<Map<String, Object>> provisionMastodon(
            Authentication auth,
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String header) {
        return me(auth, header).flatMap(me -> provision(me, false));
    }

    private Mono<Map<String, Object>> provision(Account me, boolean matrix) {
        if (!me.registrationComplete()) {
            return Mono.error(ApiException.forbidden("complete registration first"));
        }
        // Account-takeover-by-collision fix: READ the persisted, collision-checked
        // localpart (set at registration by persistLocalpart / InternalAccountController)
        // rather than re-deriving it from me.handle() here — a fresh re-derivation would
        // skip the collision check entirely and is exactly how the bug was reachable.
        return localpartOf(me)
                .flatMap(username -> provisionFor(me, matrix, username))
                .onErrorMap(AccountLocalpartService.CollisionException.class,
                        e -> ApiException.conflict(e.getMessage()));
    }

    private Mono<Map<String, Object>> provisionFor(Account me, boolean matrix, String username) {
        // Never broker a real Matrix/Mastodon account whose username is a
        // reserved app path/prefix (defence-in-depth: a reserved handle should
        // already have been blocked at registration, but the broker mints a
        // real homeserver localpart here, so re-check at the provision point).
        if (ReservedNames.isReserved(username)) {
            return Mono.error(ApiException.badRequest(
                    "username '" + username + "' is reserved and cannot be provisioned"));
        }
        if (matrix) {
            return broker.matrixToken(username)
                    .onErrorResume(e -> Mono.error(ApiException.badGateway(String.valueOf(e))));
        }
        // Mastodon needs BOTH: the Matrix-style username (the suspension row key the
        // broker guards on) AND the PERSISTED, collision-checked Mastodon localpart
        // (changeset 291) the homeserver account is keyed on. Resolve the latter FIRST
        // and OUTSIDE the badGateway wrap — a self-heal here can raise CollisionException
        // that must reach the outer 409 mapper, not be masked as a 502.
        return mastodonLocalpartOf(me).flatMap(mastodonLocalpart ->
                broker.mastodonToken(username, mastodonLocalpart)
                        .onErrorResume(e -> Mono.error(ApiException.badGateway(String.valueOf(e)))));
    }

    /**
     * The persisted localpart for {@code me}, self-healing (via the SAME collision-checked
     * {@link AccountLocalpartService#resolveAndPersist} chokepoint every creation call site
     * uses) an account row that predates the {@code account.localpart} column / was created
     * off the 3 official call sites (e.g. directly via {@code AccountStore}, as some tests
     * do) — this NEVER re-derives the localpart independently and returns it unchecked; a
     * self-heal still goes through the same collision guard as a normal registration.
     */
    private Mono<String> localpartOf(Account me) {
        return localparts.localpartOf(me.id())
                .switchIfEmpty(Mono.defer(() -> localparts.resolveAndPersist(me.id(), me.handle())));
    }

    /**
     * The persisted Mastodon localpart for {@code me} (changeset 291), self-healing an
     * account that predates the {@code account.mastodon_localpart} column via the SAME
     * collision-checked {@link AccountLocalpartService#resolveAndPersist} chokepoint (which
     * resolves BOTH folds), then re-reading the now-persisted Mastodon value. NEVER re-folds
     * the localpart independently — a self-heal still goes through the collision guard, so a
     * colliding row raises {@link AccountLocalpartService.CollisionException} (surfaced 409),
     * exactly like {@link #localpartOf}.
     */
    private Mono<String> mastodonLocalpartOf(Account me) {
        return localparts.mastodonLocalpartOf(me.id())
                .switchIfEmpty(Mono.defer(() -> localparts.resolveAndPersist(me.id(), me.handle())
                        .then(localparts.mastodonLocalpartOf(me.id()))));
    }

    // ── Helpers ────────────────────────────────────────────────────────
    /**
     * Resolve the acting account for an authenticated endpoint. Two paths, in
     * order: (1) the opaque BFF session token carried in {@code Authorization}
     * (the standalone/mock flow), then (2) the validated Casdoor JWT principal
     * (the production flow — the gateway forwards the JWT; we map its email /
     * preferred_username claim to the registered account). 401 if neither resolves.
     */
    private Mono<Account> me(Authentication auth, String header) {
        return store.sessionOf(header)
                .switchIfEmpty(Mono.defer(() -> accountFromJwt(auth)))
                .switchIfEmpty(Mono.error(ApiException.unauthorized("login required")));
    }

    /** Map a Casdoor JWT to a registered account via its identity claims. */
    private Mono<Account> accountFromJwt(Authentication auth) {
        if (!(auth instanceof JwtAuthenticationToken jwtAuth)) return Mono.empty();
        Jwt jwt = jwtAuth.getToken();
        String email = jwt.getClaimAsString("email");
        String username = jwt.getClaimAsString("preferred_username");
        Mono<Account> byEmail = (email != null && !email.isBlank())
                ? store.account(AccountStore.idFor("google", email))
                : Mono.empty();
        Mono<Account> byUsername = (username != null && !username.isBlank())
                ? store.account(AccountStore.idFor("discord", username))
                : Mono.empty();
        return byEmail.switchIfEmpty(byUsername);
    }

    private static Map<String, Object> sessionOut(String token, Account a, List<String> extraRoles,
                                                  AccountStatus status) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("token", token);
        out.put("id", a.id());
        out.put("provider", a.provider());
        out.put("roles", mergeRoles(a.roles(), extraRoles));
        out.put("registrationComplete", a.registrationComplete());
        putStatus(out, status);
        return out;
    }

    private static Map<String, Object> meOut(Account a, List<String> extraRoles, AccountStatus status) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("id", a.id());
        out.put("provider", a.provider());
        out.put("roles", mergeRoles(a.roles(), extraRoles));
        out.put("registrationComplete", a.registrationComplete());
        putStatus(out, status);
        return out;
    }

    /** Append the forwarded domain-lock marker roles to the account roles (de-duped,
     *  order-preserving) so the session roles[] carries the domain-locked flag. */
    private static List<String> mergeRoles(List<String> base, List<String> extra) {
        List<String> out = new ArrayList<>(base == null ? List.of() : base);
        if (extra != null) {
            for (String r : extra) if (r != null && !out.contains(r)) out.add(r);
        }
        return out;
    }

    /** Surface the BFF-computed account-state on the response. {@code status} is
     *  always present (active|suspended|banned); {@code until} (expiry) and
     *  {@code reason} are added only when set, so an active account stays a clean
     *  {@code {status:"active"}}. */
    private static void putStatus(Map<String, Object> out, AccountStatus status) {
        if (status == null) {
            out.put("status", AccountStatus.ACTIVE);
            return;
        }
        out.put("status", status.status());
        if (status.until() != null) out.put("until", status.until().toString());
        if (status.reason() != null && !status.reason().isBlank()) out.put("reason", status.reason());
    }

    /**
     * The {@code ROLE_MATRIX_DOMAINLOCKED} / {@code ROLE_MASTODON_DOMAINLOCKED} marker
     * authorities carried on the validated JWT (when the gateway forwarded one). They
     * are NOT on the BFF account roles, so without this they would be dropped from the
     * session; the matrix/mastodon UIs read them to render the domain-locked flag.
     * Returns the lowercase role names (matching the existing session roles[] shape).
     */
    private static List<String> domainlockRoles(Authentication auth) {
        if (auth == null || auth.getAuthorities() == null) return List.of();
        // Filter null authorities, strip the ROLE_ prefix, keep only the two domainlock roles,
        // lowercase, then collect distinct into a list.
        return auth.getAuthorities().stream()
                .filter(ga -> ga != null && ga.getAuthority() != null)
                .map(ga -> ga.getAuthority().startsWith("ROLE_")
                        ? ga.getAuthority().substring("ROLE_".length()) : ga.getAuthority())
                .filter(role -> role.equals("MATRIX_DOMAINLOCKED") || role.equals("MASTODON_DOMAINLOCKED"))
                .map(String::toLowerCase)
                .distinct()
                .collect(java.util.stream.Collectors.toList());
    }

    /** Forward the registration display-name / screen-reader-name to the user-bff
     *  profile (best-effort; an error never fails registration). No-op when neither
     *  is supplied. */
    private Mono<Void> forwardProfile(Account a, String displayName, String screenReaderName) {
        if ((displayName == null || displayName.isBlank())
                && (screenReaderName == null || screenReaderName.isBlank())) {
            return Mono.empty();
        }
        return profiles.forward(a.id(), displayName, screenReaderName);
    }

    private static String str(Object o) {
        return o == null ? "" : o.toString().trim();
    }

    /** The direct TCP peer address, for {@link LocalLoginRateLimiter}'s per-IP bucket. Reads
     *  {@link ServerWebExchange#getRequest()}'s remote address only — NOT a client-supplied
     *  {@code X-Forwarded-For} (which a caller in front of this BFF could spoof to evade the
     *  bucket). {@code "unknown"} on the rare exchange with no resolvable remote address, which
     *  still throttles correctly (every such caller shares one bucket — a conservative fallback,
     *  never a bypass). */
    private static String clientIp(ServerWebExchange exchange) {
        InetSocketAddress remote = exchange.getRequest().getRemoteAddress();
        return (remote == null || remote.getAddress() == null)
                ? "unknown" : remote.getAddress().getHostAddress();
    }
}
