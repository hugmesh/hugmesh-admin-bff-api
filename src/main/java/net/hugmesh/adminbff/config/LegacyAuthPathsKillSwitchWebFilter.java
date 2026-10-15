package net.hugmesh.adminbff.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.PathContainer;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import org.springframework.web.util.pattern.PathPattern;
import org.springframework.web.util.pattern.PathPatternParser;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Ships-dark, per-path KILL SWITCH for the eleven legacy user-facing mappings of
 * {@link net.hugmesh.adminbff.AuthController} (hugmesh-admin-bff-api#86, split from #2).
 *
 * <h2>What it is for</h2>
 * Issue #2's answer is "retire" the legacy {@code /bff/register|login|me|session|provision}
 * surface, but the 2026-09-10 audit measured that the same paths land on DIFFERENT services on
 * the cluster, compose and device lanes, so a plain deletion can break a lane nobody was
 * watching. This switch lets an operator turn a named path OFF, reversibly and per path, and
 * READ the resulting 404s (and the log line below, which names the caller) before the
 * deletion is attempted. <b>Flipping it is an observation step, not the retirement</b>: no
 * mapping is removed, {@code LegacyUserPathRetirementGuardTest} still pins all eleven, and
 * setting the property back restores the path with no redeploy of code.
 *
 * <h2>Configuration</h2>
 * <ul>
 *   <li>{@value #ENABLED_PROPERTY} (default {@code true}) — {@code false} turns the WHOLE
 *       legacy surface off.</li>
 *   <li>{@value #DISABLED_PROPERTY} (default empty) — a list of {@code "METHOD /bff/path"}
 *       entries (for example {@code POST /bff/register/google}) turned off even while the
 *       global switch is {@code true}. Env form: {@code APP_AUTH_LEGACY_PATHS_DISABLED}
 *       with comma-separated entries.</li>
 * </ul>
 * With both at their defaults the filter is a pass-through: every path serves exactly as before
 * on every lane. An entry that is not one of the eleven known mappings FAILS THE BOOT: a typo
 * that silently disabled nothing would let an operator read "no 404s" as "path is dead" and
 * delete a live path, which is the exact failure this switch exists to prevent.
 *
 * <h2>What a switched-off path answers</h2>
 * <b>404</b>, not 410: 404 is what the path will answer once it is really deleted, so the
 * observation rehearses the retirement faithfully (a 410 would be a status no client has ever
 * been tested against). The response has an empty body and an {@code X-Bff-Denied:
 * legacy-path-disabled} header, so a person debugging can tell a switched-off path from a
 * mistyped one; no client can act on it. The status is pinned by
 * {@code LegacyAuthPathsKillSwitchWebFilterTest}.
 *
 * <h2>Where it sits</h2>
 * At {@code HIGHEST_PRECEDENCE + 5}: ahead of Spring Security's chain and of the session lookups
 * ({@code +9} to {@code +11}), so a switched-off path answers 404 to EVERY caller (anonymous
 * included, where the security floor would otherwise answer 401 and hide that the path was
 * switched off) and costs no session lookup. It is tied at {@code +5} with auth-core's
 * {@code SessionCookieWebFilter}, which only copies the cookie into the Authorization header and
 * neither looks up a session nor rejects, so the order between the two does not change the
 * answer; the test pins "before {@code +9}", not "first". After a real
 * deletion an anonymous caller of a protected path would be answered by the security floor
 * instead, so the 404 seen here is the observation signal, not a byte-exact preview of every
 * caller's post-deletion answer.
 *
 * <h2>What is matched</h2>
 * The known set below is a literal copy of the eleven mappings, NOT read reflectively (a
 * reflective read of controller annotations is a native-image hazard). Drift is caught
 * two ways: {@code LegacyUserPathRetirementGuardTest} fails when AuthController gains or loses
 * a mapping, and {@code LegacyAuthPathsKillSwitchWebFilterTest} fails when this set differs from
 * what AuthController declares. Matching uses the same {@link PathPattern} semantics Spring's
 * handler mapping uses (decoded segments, path parameters stripped), so {@code /bff/%6Cogin}
 * and {@code /bff/login;x=1} cannot slip past a switch the controller would still answer.
 * {@code HEAD} is treated as {@code GET} (a GET mapping answers HEAD); {@code OPTIONS} is
 * never gated.
 *
 * <h2>What is logged</h2>
 * One WARN per hit: the matched key, the socket peer, the claimed {@code X-Forwarded-For}
 * (client-controlled, so labelled as claimed) and the {@code User-Agent}. Header values have
 * every control character (ASCII, C1 and the Unicode line/paragraph separators) replaced and
 * are truncated, so a caller cannot start a new log line. There is NO rate limit: while a path
 * is switched off, every anonymous hit writes one WARN, so a caller can raise log volume at
 * the cost of one request per line. The request path itself is NOT logged raw; the matched key
 * (a fixed string) is.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 5)
public class LegacyAuthPathsKillSwitchWebFilter implements WebFilter {

    public static final String ENABLED_PROPERTY = "app.auth.legacy-paths.enabled";
    public static final String DISABLED_PROPERTY = "app.auth.legacy-paths.disabled";

    /** Value of the {@code X-Bff-Denied} header on a switched-off path. */
    public static final String DENIED_HEADER_VALUE = "legacy-path-disabled";

    /** The status a switched-off path answers. Pinned by test; see the class doc for 404 vs 410. */
    public static final HttpStatus DISABLED_STATUS = HttpStatus.NOT_FOUND;

    private static final Logger LOG = LoggerFactory.getLogger(LegacyAuthPathsKillSwitchWebFilter.class);

    private static final int MAX_LOGGED_HEADER_CHARS = 200;

    /**
     * The eleven legacy mappings, as {@code "METHOD /bff<path>"}, in AuthController's source
     * order. Keep in step with AuthController; two tests fail if it is not.
     */
    public static final Set<String> LEGACY_PATHS = Collections.unmodifiableSet(new LinkedHashSet<>(List.of(
            "POST /bff/register/google",
            "POST /bff/register/discord",
            "POST /bff/login",
            "POST /bff/login/local",
            "POST /bff/register/complete",
            "GET /bff/me",
            "GET /bff/me/namespaces",
            "GET /bff/session",
            "POST /bff/sessionOut",
            "POST /bff/provision/matrix",
            "POST /bff/provision/mastodon")));

    private static final PathPatternParser PARSER = new PathPatternParser();

    /** key -> compiled pattern for the path half of the key. */
    private static final Map<String, PathPattern> PATTERNS = compile();

    private final Set<String> switchedOff;

    /** Spring wiring: reads the two properties off the {@link Environment}. */
    @Autowired
    public LegacyAuthPathsKillSwitchWebFilter(Environment env) {
        this(env.getProperty(ENABLED_PROPERTY, Boolean.class, Boolean.TRUE),
                Binder.get(env).bind(DISABLED_PROPERTY, Bindable.listOf(String.class)).orElse(List.of()));
    }

    /** Direct construction (tests): {@code enabled=false} switches every legacy path off. */
    public LegacyAuthPathsKillSwitchWebFilter(boolean enabled, Collection<String> disabled) {
        Set<String> off = new LinkedHashSet<>();
        for (String raw : disabled == null ? List.<String>of() : disabled) {
            String key = normalise(raw);
            if (key == null) {
                continue; // blank entry, e.g. an empty env var
            }
            if (!LEGACY_PATHS.contains(key)) {
                throw new IllegalStateException("Unknown entry '" + raw + "' in " + DISABLED_PROPERTY
                        + ": it is not one of the legacy AuthController mappings, so it would silently"
                        + " switch nothing off. Known entries: " + LEGACY_PATHS);
            }
            off.add(key);
        }
        if (!enabled) {
            off.addAll(LEGACY_PATHS);
        }
        this.switchedOff = Collections.unmodifiableSet(off);
        if (!switchedOff.isEmpty()) {
            LOG.warn("Legacy auth paths switched OFF (observation step, nothing retired): {}", switchedOff);
        }
    }

    /** The keys currently answering 404. Empty with the defaults. */
    public Set<String> switchedOff() {
        return switchedOff;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        if (switchedOff.isEmpty()) {
            return chain.filter(exchange);
        }
        ServerHttpRequest request = exchange.getRequest();
        String key = matchedKey(request);
        if (key == null || !switchedOff.contains(key)) {
            return chain.filter(exchange);
        }
        LOG.warn("Switched-off legacy auth path {} was called: remote={} x-forwarded-for(claimed)={} user-agent={}",
                key,
                request.getRemoteAddress() == null ? "unknown" : request.getRemoteAddress(),
                loggable(request.getHeaders().getFirst("X-Forwarded-For")),
                loggable(request.getHeaders().getFirst("User-Agent")));
        exchange.getResponse().setStatusCode(DISABLED_STATUS);
        exchange.getResponse().getHeaders().set("X-Bff-Denied", DENIED_HEADER_VALUE);
        return exchange.getResponse().setComplete();
    }

    /** The legacy key this request would be served by, or null when it is not a legacy mapping. */
    private static String matchedKey(ServerHttpRequest request) {
        HttpMethod method = request.getMethod();
        String verb = HttpMethod.HEAD.equals(method) ? "GET" : method.name();
        PathContainer path = request.getPath().pathWithinApplication();
        for (Map.Entry<String, PathPattern> e : PATTERNS.entrySet()) {
            if (e.getKey().startsWith(verb + " ") && e.getValue().matches(path)) {
                return e.getKey();
            }
        }
        return null;
    }

    private static Map<String, PathPattern> compile() {
        Map<String, PathPattern> out = new LinkedHashMap<>();
        for (String key : LEGACY_PATHS) {
            out.put(key, PARSER.parse(key.substring(key.indexOf(' ') + 1)));
        }
        return Collections.unmodifiableMap(out);
    }

    /** {@code "post   /bff/login "} to {@code "POST /bff/login"}; null for a blank entry. */
    private static String normalise(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        List<String> parts = new ArrayList<>(List.of(raw.trim().split("\\s+")));
        if (parts.size() != 2) {
            return raw.trim(); // never in LEGACY_PATHS, so the caller rejects it with the full message
        }
        return parts.get(0).toUpperCase(Locale.ROOT) + " " + parts.get(1);
    }

    /** Header text safe to put in a log line: no control or line-separator characters, bounded length. */
    static String loggable(String value) {
        if (value == null) {
            return "-";
        }
        String clean = value.replaceAll("[\\p{Cc}\\u2028\\u2029]", "?");
        return clean.length() > MAX_LOGGED_HEADER_CHARS
                ? clean.substring(0, MAX_LOGGED_HEADER_CHARS) + "...(truncated)"
                : clean;
    }
}
