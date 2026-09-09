package net.hugmesh.adminbff.account;

import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import net.hugmesh.authcore.account.AccountStore;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.PrincipalDomain;

import java.util.Set;

/**
 * Resolves the REQUESTING DOMAIN for the two-stage registration gate — the brand whose
 * allowlist a {@code POST /bff/register/**} (or the internal
 * {@code GET /bff/internal/allowlist/**}) is allowed to satisfy.
 *
 * <h2>Why this class exists (hugmesh-auth-core issue #1)</h2>
 *
 * <p>The invite row has been domain-stamped since changeset 220 ({@code AdminController.invite}
 * writes the acting admin's {@link PrincipalDomain#domain()}), but the registration GATE read
 * was not: {@code AccountStore.isEmailInvited(email)} answered "invited in ANY domain", so an
 * invite an admin of brand X issued also admitted that identifier on brand Y. auth-core 2.5.0
 * added the domain-scoped overloads ({@code isEmailInvited(email, domain)} /
 * {@code isDiscordInvited(handle, domain)}) and deprecated the unscoped ones; what was missing
 * was a domain to pass, because a registration request is PRE-AUTHENTICATION — there is no
 * validated JWT at the call site and therefore no {@link PrincipalDomain}.
 *
 * <h2>*** THE SECURITY CONTRACT — only server-trusted inputs ***</h2>
 *
 * <p>The gate's whole purpose is that brand Y's operator decides who joins brand Y, so the
 * domain it is evaluated against must never be something the registering caller can choose.
 * That rules out the obvious shape:
 *
 * <ul>
 *   <li><b>A request-body / query field is NOT a fix.</b> An attacker who knows an identifier
 *       is invited on brand X would simply send {@code domain: "brandx"} while registering
 *       against brand Y and pass the gate — the exact hole, re-opened with extra steps. The
 *       one place an explicit domain IS honoured is the {@code /bff/internal} surface, which
 *       is mTLS + {@code X-Internal-Token} guarded and carries no untrusted principal (the
 *       same rationale {@code InternalAccountController}'s session-listing read already
 *       documents).</li>
 *   <li><b>The {@code Host} header is NOT usable.</b> There is no host-to-domain mapping on
 *       this platform — {@link DomainRegistry} maps a validated JWT ISSUER to a brand and
 *       nothing maps {@code login.example.test:8443} to one. {@code DomainThemeSurfaceController}
 *       documents that same finding for the other unauthenticated surface.</li>
 * </ul>
 *
 * <h2>Resolution order</h2>
 *
 * <ol>
 *   <li><b>{@code app.tenancy.registration-domain}</b> — the per-deployment pin, when set. It
 *       is checked FIRST, ahead of any forwarded token: the pin is the operator's statement of
 *       which brand this admin-bff registers for, and it is the one input a caller cannot
 *       choose. A token would otherwise let the caller pick the gate's domain merely by
 *       attaching one (see {@link #forRegistration}).</li>
 *   <li><b>The forwarded token's issuer</b>, when unpinned and the gateway forwarded one.
 *       Admitted ONLY on strict membership of the CONFIGURED, NON-EMPTY
 *       {@link DomainRegistry#trustedIssuers()}
 *       set — deliberately not {@link DomainRegistry#isTrusted(String)}, which delegates to
 *       {@code domainOf} and short-circuits to {@code "default"} <em>without inspecting its
 *       argument</em> when the registry map is empty (i.e. answers "trusted" for any string).
 *       Same reasoning, and the same strict-membership shape, as {@link AccountIssuerService}.</li>
 *   <li><b>The deployment's only brand</b>, when the registry knows exactly one. This is what
 *       keeps the single-tenant install byte-identical: with no tenancy config
 *       {@link DomainRegistry#knownDomains()} is empty and this resolves
 *       {@link AccountStore#DEFAULT_DOMAIN} — precisely the domain {@code AccountStore.seedAdmins}
 *       stamps and the changeset-220 back-fill wrote onto every pre-existing row; in
 *       ISSUER-URI-ONLY back-compat mode the registry's one known domain is likewise
 *       {@code "default"}. Note the one known domain is NOT {@code "default"} when
 *       {@code app.tenancy.issuers} names a single brand — it is that brand — which is why
 *       {@link RegistrationDomainAdminSeed} mirrors the bootstrap admin invites into whatever
 *       this method returns.</li>
 *   <li><b>Fail closed</b> — {@link PrincipalDomain#NO_DOMAIN}. A multi-brand deployment that
 *       reached here has an untokened registration and no pin, so there is no honest answer.
 *       The sentinel begins with a space and can never equal a
 *       {@link DomainRegistry}-sanitized ({@code [a-z0-9-]}) domain name, so the gate query
 *       matches no row and the registration is refused. Refusing beats guessing {@code
 *       "default"}: a guess would be indistinguishable from a correct answer in the logs while
 *       admitting anyone the mesh-default allowlist holds.</li>
 * </ol>
 */
@Service
public class RegistrationDomainResolver {

    private static final Logger log = LoggerFactory.getLogger(RegistrationDomainResolver.class);

    private final DomainRegistry domains;

    /** The {@code app.tenancy.registration-domain} pin, trimmed; empty when unset. */
    private final String pinnedDomain;

    public RegistrationDomainResolver(
            DomainRegistry domains,
            @Value("${app.tenancy.registration-domain:}") @Nullable String pinnedDomain) {
        this.domains = domains;
        this.pinnedDomain = pinnedDomain == null ? "" : pinnedDomain.trim();
        if (!this.pinnedDomain.isEmpty()) {
            log.info("[registration-gate] pre-auth registrations are pinned to domain '{}' "
                    + "(app.tenancy.registration-domain)", this.pinnedDomain);
        }
    }

    /**
     * The domain a PRE-AUTH registration ({@code POST /bff/register/**}) may satisfy its invite
     * from. Never {@code null}; {@link PrincipalDomain#NO_DOMAIN} when unresolvable, which
     * matches no allowlist row.
     *
     * @param auth the request's Spring Security authentication — {@code null} / anonymous on
     *             the ordinary untokened registration, a {@link Jwt}-backed token when the
     *             gateway forwarded one
     */
    public String forRegistration(@Nullable Authentication auth) {
        // The PIN OUTRANKS A FORWARDED TOKEN, deliberately. A validated JWT proves who the
        // caller is; it does not prove which brand THIS deployment registers for — and the
        // caller chooses whether to attach one and which one to attach. On a pinned
        // deployment that also trusts a sibling brand's issuer (the ordinary multi-issuer
        // shape), preferring the token would let an attacker holding a valid brand-A token
        // satisfy the gate from brand-A's allowlist and be minted a brand-B session: the
        // exact cross-brand hole this class exists to close, re-opened by adding a header.
        // The pin is operator configuration, so it is the one input the caller cannot pick.
        if (!pinnedDomain.isEmpty()) {
            return pinnedDomain;
        }
        String fromToken = domainOfTrustedIssuer(auth);
        return fromToken != null ? fromToken : fallback();
    }

    /**
     * The domain the mTLS + {@code X-Internal-Token} guarded internal invite read evaluates.
     * The trusted in-cluster caller (user-bff, which HAS the validated token this hop lost)
     * MAY name the brand explicitly — but ONLY a brand THIS deployment serves (issue #47):
     *
     * <ul>
     *   <li>strict membership of the CONFIGURED {@link DomainRegistry#knownDomains()} set, via
     *       {@link DomainRegistry#isKnownDomain(String)} — the same strict-membership shape
     *       {@link #domainOfTrustedIssuer} uses for issuers; or</li>
     *   <li>the deployment's own {@link #fallback()} answer — the per-deployment pin, or the
     *       legacy {@code "default"} brand of an unconfigured / issuer-uri-only registry, which
     *       {@code isKnownDomain} deliberately rejects as a back-compat sentinel. This keeps a
     *       single-tenant install accepting the one name it actually stamps on its rows.</li>
     * </ul>
     *
     * <p>Anything else FAILS CLOSED to {@link PrincipalDomain#NO_DOMAIN} (matches no allowlist
     * row) rather than degrading to {@link #fallback()}: a supplied-but-unknown brand is a
     * caller bug, and answering with the deployment's own brand would both hide the bug and,
     * on a multi-brand mesh, widen the answer. The value is compared EXACTLY (the registry's
     * names are already {@code [a-z0-9-]}-sanitized, so a differently-cased or decorated
     * spelling cannot match a row and is refused, never normalised into a match). An
     * omitted/blank value still degrades to {@link #fallback()}, so a caller that does not
     * send one keeps the single-brand behaviour it has today.
     *
     * @param supplied the caller-supplied {@code domain}, or {@code null}/blank when omitted
     */
    public String forInternalCaller(@Nullable String supplied) {
        if (supplied == null || supplied.isBlank()) {
            return fallback();
        }
        String candidate = supplied.trim();
        if (domains.isKnownDomain(candidate)) {
            return candidate;
        }
        String own = fallback();
        if (!PrincipalDomain.NO_DOMAIN.equals(own) && own.equals(candidate)) {
            return candidate;
        }
        log.warn("[registration-gate] internal caller named domain '{}', which this deployment "
                + "does not serve — failing closed (no allowlist row can match)",
                candidate.replaceAll("[^\\x20-\\x7e]", "?"));
        return PrincipalDomain.NO_DOMAIN;
    }

    /**
     * The domain to use when no token names one: the per-deployment pin, else the deployment's
     * only brand, else the fail-closed sentinel. See the class doc's resolution order.
     */
    public String fallback() {
        if (!pinnedDomain.isEmpty()) {
            return pinnedDomain;
        }
        Set<String> known = domains.knownDomains();
        if (known == null || known.isEmpty()) {
            // No tenancy config at all: the legacy single-tenant install, whose rows all carry
            // the seed/back-fill "default" stamp.
            return AccountStore.DEFAULT_DOMAIN;
        }
        if (known.size() == 1) {
            return known.iterator().next();
        }
        // Multi-brand and nothing names the brand. Fail closed rather than guess.
        return PrincipalDomain.NO_DOMAIN;
    }

    /**
     * The brand named by {@code auth}'s validated issuer, or {@code null} when the request
     * carries no JWT or an issuer this deployment does not trust. Strict membership of the
     * configured trusted set — never {@link DomainRegistry#isTrusted(String)}, which fails
     * open on an unconfigured registry (see the class doc).
     */
    @Nullable
    private String domainOfTrustedIssuer(@Nullable Authentication auth) {
        if (auth == null || !(auth.getPrincipal() instanceof Jwt jwt) || jwt.getIssuer() == null) {
            return null;
        }
        Set<String> trusted = domains.trustedIssuers();
        if (trusted == null || trusted.isEmpty()) {
            return null;
        }
        String candidate = trimSlash(jwt.getIssuer().toString());
        for (String t : trusted) {
            if (t != null && t.equals(candidate)) {
                // The registry's own answer for the canonical key, so this is byte-identical
                // to the domain AdminController.invite stamped for the same brand.
                return domains.domainOf(t);
            }
        }
        return null;
    }

    /** Mirrors {@code DomainRegistry#trimSlash} (private there), as {@link AccountIssuerService}
     *  does, so a configured {@code https://casdoor/} and a token's {@code https://casdoor}
     *  compare equal. */
    private static String trimSlash(String s) {
        String t = s.trim();
        return t.endsWith("/") ? t.substring(0, t.length() - 1) : t;
    }
}
