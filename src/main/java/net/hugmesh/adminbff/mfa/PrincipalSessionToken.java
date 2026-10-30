package net.hugmesh.adminbff.mfa;

import net.hugmesh.authcore.config.SessionCookieWebFilter;
import org.springframework.http.HttpHeaders;

/**
 * The opaque {@code bff_} session token whose MFA stamp may count as evidence for the CURRENT
 * principal: the token the principal was built from, never a second session riding along.
 *
 * <p>Why not {@link SessionCookieWebFilter#bffTokenFrom(String, String)}: that reads the
 * {@code bff_session} COOKIE first, while the principal comes from the {@code Authorization}
 * header. {@link SessionCookieWebFilter} keeps an explicit {@code Bearer bff_...} over the
 * cookie (and otherwise copies the cookie into that header), and
 * {@code BffCookieAuthenticationWebFilter} builds the principal from that header alone. A
 * request carrying {@code Authorization: Bearer bff_A} (an admin with no MFA stamp) plus
 * {@code Cookie: bff_session=bff_B} (any account with a fresh stamp) therefore ran AS A while a
 * cookie-first lookup read B's stamp.
 *
 * <p>So the header decides, parsed the way the principal filter parses it (trimmed,
 * case-insensitive scheme, {@code bff_} prefix). The cookie is consulted only when the header
 * holds no {@code bff_} token at all, which behind the bridge means the cookie is not a
 * {@code bff_} token either; it is kept for compositions without the bridge in front.
 */
public final class PrincipalSessionToken {

    private static final String BEARER = "Bearer ";
    private static final String BFF_PREFIX = "bff_";

    private PrincipalSessionToken() {
    }

    /**
     * The {@code bff_} token in an {@code Authorization} header value, or {@code null}. Same
     * parse as the principal filter: trim, case-insensitive {@code Bearer }, trim, prefix.
     */
    public static String fromAuthorization(String authorizationHeader) {
        if (authorizationHeader == null) {
            return null;
        }
        String trimmed = authorizationHeader.trim();
        if (!trimmed.regionMatches(true, 0, BEARER, 0, BEARER.length())) {
            return null;
        }
        String candidate = trimmed.substring(BEARER.length()).trim();
        return candidate.startsWith(BFF_PREFIX) ? candidate : null;
    }

    /** The first {@code Authorization} header of a request, as a token (see above). */
    public static String fromAuthorization(HttpHeaders headers) {
        return headers == null ? null : fromAuthorization(headers.getFirst(HttpHeaders.AUTHORIZATION));
    }

    /**
     * The MFA-evidence token for a handler that bound both carriers: the header's {@code bff_}
     * token when there is one, else the cookie's. Never the cookie when the header names a
     * session.
     */
    public static String of(String sessionCookieValue, String authorizationHeader) {
        String fromHeader = fromAuthorization(authorizationHeader);
        if (fromHeader != null) {
            return fromHeader;
        }
        return SessionCookieWebFilter.bffTokenFrom(sessionCookieValue, null);
    }
}
