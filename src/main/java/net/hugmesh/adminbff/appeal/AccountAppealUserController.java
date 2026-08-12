package net.hugmesh.adminbff.appeal;

import io.swagger.v3.oas.annotations.Operation;

import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.authcore.account.Account;
import net.hugmesh.authcore.account.AccountStore;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.PrincipalDomain;
import net.hugmesh.commons.web.ApiException;
import net.hugmesh.adminbff.web.dto.AccountAppealSubmit;

/**
 * The self-service ACCOUNT-BAN appeal surface at {@code /bff/me/appeal} — a curtailed
 * (suspended or banned) principal files a structured appeal against their OWN
 * {@code access_suspension} state, and reads back their own appeal history.
 *
 * <h3>Reachable from a curtailed session</h3>
 * A {@code PROFILE} ban/suspension is NOT a Casdoor-role flip (see
 * {@link net.hugmesh.adminbff.suspension.SuspensionExpiryAction} — "PROFILE has
 * no homeserver revocation key... not a Casdoor-role flip"), so a principal who was
 * ALREADY signed in when curtailed keeps a fully valid JWT with {@code ROLE_USER}
 * intact; the host's {@code roleHomeGuard} routes them to {@code /login/appeal}
 * CLIENT-side but their session still authenticates here exactly like any other
 * {@code /bff/me/**} read. This mirrors {@code AuthController.meEndpoint}'s own
 * resolution (BFF session token first, JWT identity claims as fallback) rather than
 * requiring a fresh {@code ROLE_USER} grant, so the SAME curtailed session that reads
 * {@code GET /bff/me} can also file its appeal here. A principal with NO session at
 * all (denied at login, never authenticated) has no path to this endpoint — for that
 * case login-ui's {@code AppealComponent} falls back to the public
 * {@code /bff/public/appeal-contact} mailto resolver (this is unaffected by this PR).
 *
 * <h3>owner == subject (fail-closed)</h3>
 * {@code userSub}/{@code handle}/{@code domain} are ALWAYS resolved from the caller's
 * own account (never body fields) — a user can only create/see their OWN appeal rows.
 */
@RestController
@RequestMapping("/bff/me/appeal")
@Validated
public class AccountAppealUserController {

    private static final Logger log = LoggerFactory.getLogger(AccountAppealUserController.class);

    private final AccountAppealService service;
    private final AccountStore store;
    private final DomainRegistry domainRegistry;

    public AccountAppealUserController(AccountAppealService service, AccountStore store,
                                       DomainRegistry domainRegistry) {
        this.service = service;
        this.store = store;
        this.domainRegistry = domainRegistry;
    }

    /** Submit (or, if one is already pending, re-fetch) the caller's own appeal.
     *  {@code userSub}/{@code handle}/{@code domain} are caller-derived. */
    @Operation(summary = "Submit appeal", operationId = "accountAppealSubmit")
    @PostMapping("")
    @ResponseStatus(HttpStatus.CREATED)
    public Mono<AccountAppeal> submit(@Valid @RequestBody AccountAppealSubmit body,
                                      Authentication auth,
                                      @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String header) {
        return account(auth, header)
                .flatMap(a -> service.submit(a.id(), a.handle(), domain(auth), body.reason(), body.contactEmail()))
                .doOnNext(appeal -> log.info("[account-appeal] user submit id={} userSub={}", appeal.id(), appeal.userSub()));
    }

    /** The caller's OWN appeal history (owner == subject). */
    @Operation(summary = "My appeals", operationId = "accountAppealMine")
    @GetMapping("")
    public Flux<AccountAppeal> mine(Authentication auth,
                                    @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String header) {
        return account(auth, header).flatMapMany(a -> service.listMine(a.id(), domain(auth)));
    }

    /** Resolve the caller's own account: the durable BFF session token first (cookie/
     *  Bearer-carried), falling back to the validated JWT's identity claims — the SAME
     *  resolution {@code AuthController.meEndpoint} uses, so any session that can read
     *  {@code GET /bff/me} can also reach this endpoint. */
    private Mono<Account> account(Authentication auth, String header) {
        return store.sessionOf(header)
                .switchIfEmpty(Mono.defer(() -> accountFromJwt(auth)))
                .switchIfEmpty(Mono.error(ApiException.unauthorized("login required")));
    }

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

    private String domain(Authentication auth) {
        return PrincipalDomain.of(auth, domainRegistry).domain();
    }
}
