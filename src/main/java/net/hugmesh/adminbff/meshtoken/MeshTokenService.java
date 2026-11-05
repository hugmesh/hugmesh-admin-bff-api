package net.hugmesh.adminbff.meshtoken;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.security.PrincipalDomain;

import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * Issues HugMesh tokens v1 for the web admin UI: one headscale pre-auth key + one signed grant
 * (mesh, access domain, role, shell, expiry), byte-for-byte the format the Studio tray verifies
 * ({@code hugmesh-generator docs/HUGMESH-TOKEN.md}).
 *
 * <h2>Who may issue what</h2>
 * <ul>
 *   <li>ADMIN: role {@code user}, {@code mod} or {@code admin}; shell only with {@code admin};
 *       only for access domains its own brand owns ({@link MeshTokenProperties#domains()}).</li>
 *   <li>SUPERADMIN: any role, including {@code superadmin}, for any configured domain.</li>
 *   <li>Shell is never granted to {@code user} or {@code mod} (the format refuses it).</li>
 * </ul>
 * The token's role and domain are a GRANT the tray acts on; the pre-auth key itself is created
 * with {@code tag:hugmesh} only ({@link HeadscalePreAuthKeyClient#KEY_TAGS}) and the mesh's
 * policy decides the rest.
 *
 * <h2>Secrets</h2>
 * The issuer private key is loaded once from {@code app.mesh-token.issuer-key-path} and never
 * leaves this object. The token (and the pre-auth key inside it) is returned once from
 * {@link #issue}; it is not stored, not logged, and the audit row has no column for it.
 *
 * <h2>SHIPS DARK</h2>
 * {@code app.mesh-token.enabled=false}: {@link #issue} fails with {@link MeshTokenDarkException}
 * before touching headscale or the key, and the issuer key file is never read. When ENABLED,
 * a bad mesh id, domain table or issuer key fails the boot — a half-configured issuer is worse
 * than a service that does not start.
 */
@Service
public class MeshTokenService {

    private static final Logger log = LoggerFactory.getLogger(MeshTokenService.class);
    private static final DateTimeFormatter WHEN =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm 'UTC'", Locale.ROOT).withZone(ZoneOffset.UTC);
    static final long MIN_LIFETIME_SECONDS = 60;

    /** The sentence the dark endpoints answer with. */
    public static final String DARK_NOTE = "Mesh token issuing is off on this mesh "
            + "(app.mesh-token.enabled=false). On a local docker mesh, start it with "
            + "`make stack-up HEADSCALE=1`.";

    private final MeshTokenProperties props;
    private final HeadscalePreAuthKeyClient headscale;
    private final MeshTokenIssuedRowRepository issued;
    private final Clock clock;
    private final SecureRandom random = new SecureRandom();
    private final List<MeshTokenProperties.DomainEntry> domains;
    private final MeshTokenIssuerKey issuerKey;

    public MeshTokenService(MeshTokenProperties props, HeadscalePreAuthKeyClient headscale,
                            MeshTokenIssuedRowRepository issued) {
        this(props, headscale, issued, Clock.systemUTC(), null);
    }

    /** Test seam: a fixed clock and/or an in-memory issuer key. */
    MeshTokenService(MeshTokenProperties props, HeadscalePreAuthKeyClient headscale,
                     MeshTokenIssuedRowRepository issued, Clock clock, MeshTokenIssuerKey key) {
        this.props = props;
        this.headscale = headscale;
        this.issued = issued;
        this.clock = clock;
        if (!props.isEnabled()) {
            this.domains = List.of();
            this.issuerKey = null;
            return;
        }
        if (props.getMesh() == null || !MeshTokenPayload.MESH_RE.matcher(props.getMesh()).matches()) {
            throw new IllegalStateException("app.mesh-token.mesh '" + props.getMesh()
                    + "' is not a valid mesh name (^[a-z0-9][a-z0-9-]{0,62}$).");
        }
        this.domains = List.copyOf(props.domains());
        if (domains.isEmpty()) {
            throw new IllegalStateException("app.mesh-token.enabled=true but app.mesh-token.login-servers "
                    + "names no access domain.");
        }
        if (key != null) {
            this.issuerKey = key;
        } else {
            String path = props.getIssuerKeyPath();
            if (path == null || path.isBlank()) {
                throw new IllegalStateException("app.mesh-token.enabled=true but app.mesh-token.issuer-key-path is empty.");
            }
            this.issuerKey = MeshTokenIssuerKey.load(Path.of(path));
        }
        log.info("[mesh-token] issuer ready: mesh={} issuer={} domains={}", props.getMesh(),
                issuerKey.fingerprint(), domains.stream().map(MeshTokenProperties.DomainEntry::domain).toList());
    }

    public boolean isEnabled() {
        return props.isEnabled();
    }

    // ── errors (each maps to one HTTP status in the controller) ────────────────────────

    /** 503: issuing is switched off. */
    public static final class MeshTokenDarkException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        public MeshTokenDarkException() {
            super(DARK_NOTE, null, false, false);
        }
    }

    /** 403: the caller may not issue this grant. */
    public static final class MeshTokenDeniedException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        public MeshTokenDeniedException(String message) {
            super(message, null, false, false);
        }
    }

    /** 400: the request is not a grant this mesh can issue. */
    public static final class MeshTokenInvalidException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        public MeshTokenInvalidException(String message) {
            super(message, null, false, false);
        }
    }

    // ── issuer descriptor ───────────────────────────────────────────────────────────

    /** The issuer as the admin UI shows it: public key, fingerprint, and the domains THIS caller may issue for. */
    public Map<String, Object> issuer(PrincipalDomain scope) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("enabled", isEnabled());
        out.put("publicKey", issuerKey == null ? null : issuerKey.publicLine());
        out.put("fingerprint", issuerKey == null ? null : issuerKey.fingerprint());
        out.put("mesh", isEnabled() ? props.getMesh() : null);
        List<Map<String, Object>> ds = new ArrayList<>();
        for (MeshTokenProperties.DomainEntry d : visibleDomains(scope)) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("domain", d.domain());
            m.put("loginServer", d.loginServer());
            ds.add(m);
        }
        out.put("domains", ds);
        out.put("roles", rolesFor(scope));
        out.put("maxLifetimeSeconds", props.effectiveMaxLifetimeSeconds());
        out.put("defaultLifetimeSeconds", defaultLifetime());
        out.put("note", isEnabled() ? null : DARK_NOTE);
        return out;
    }

    private List<MeshTokenProperties.DomainEntry> visibleDomains(PrincipalDomain scope) {
        if (scope != null && scope.superadmin()) {
            return domains;
        }
        String brand = scope == null ? PrincipalDomain.NO_DOMAIN : scope.domain();
        return domains.stream().filter(d -> d.brand().equals(brand)).toList();
    }

    static List<String> rolesFor(PrincipalDomain scope) {
        return scope != null && scope.superadmin()
                ? MeshTokenPayload.ROLES
                : List.of("user", "mod", "admin");
    }

    private long defaultLifetime() {
        return Math.min(Math.max(props.getDefaultLifetimeSeconds(), MIN_LIFETIME_SECONDS),
                props.effectiveMaxLifetimeSeconds());
    }

    // ── issue ───────────────────────────────────────────────────────────────────────

    /** What the caller asked for. {@code lifetimeSeconds} null means the default. */
    public record IssueRequest(String domain, String role, boolean shell, Long lifetimeSeconds, String nodeName) {
    }

    /** What the caller gets back, once. {@link #toString()} never prints the token. */
    public record IssueResult(String token, String id, long expires, String fingerprint, String describe) {
        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("token", token);
            m.put("id", id);
            m.put("expires", expires);
            m.put("fingerprint", fingerprint);
            m.put("describe", describe);
            return m;
        }

        @Override
        public String toString() {
            return "IssueResult[id=" + id + ", expires=" + expires + ", fingerprint=" + fingerprint
                    + ", token=<redacted>]";
        }
    }

    /** The grant after validation and authorization; still no key material. */
    record Authorized(MeshTokenProperties.DomainEntry domain, String role, boolean shell, long lifetime, String nodeName) {
    }

    /**
     * Validate and authorize {@code req} for {@code scope}. Throws {@link MeshTokenInvalidException}
     * or {@link MeshTokenDeniedException}; pure, so the whole role/shell/domain matrix is testable
     * without headscale.
     */
    Authorized authorize(IssueRequest req, PrincipalDomain scope) {
        if (req == null) {
            throw new MeshTokenInvalidException("No grant was given.");
        }
        boolean superadmin = scope != null && scope.superadmin();
        String role = req.role() == null ? "" : req.role().trim();
        if (!MeshTokenPayload.ROLES.contains(role)) {
            throw new MeshTokenInvalidException("The role must be one of "
                    + String.join(", ", MeshTokenPayload.ROLES) + ".");
        }
        if (req.shell() && !MeshTokenPayload.SHELL_ROLES.contains(role)) {
            throw new MeshTokenInvalidException("Shell access can only be granted with the role admin or "
                    + "superadmin; the role " + role + " never holds shell access.");
        }
        if ("superadmin".equals(role) && !superadmin) {
            throw new MeshTokenDeniedException("Only a superadmin can issue a superadmin token.");
        }
        String domainName = req.domain() == null ? "" : req.domain().trim().toLowerCase(Locale.ROOT);
        while (domainName.endsWith(".")) {
            domainName = domainName.substring(0, domainName.length() - 1);
        }
        if (!MeshTokenPayload.DOMAIN_RE.matcher(domainName).matches()) {
            throw new MeshTokenInvalidException("The access domain must be a domain name such as example.org.");
        }
        final String wanted = domainName;
        Optional<MeshTokenProperties.DomainEntry> entry =
                domains.stream().filter(d -> d.domain().equals(wanted)).findFirst();
        if (entry.isEmpty()) {
            throw new MeshTokenInvalidException("This mesh has no login server for the access domain "
                    + wanted + ", so it cannot issue tokens for it.");
        }
        if (!superadmin) {
            String brand = scope == null ? PrincipalDomain.NO_DOMAIN : scope.domain();
            if (!entry.get().brand().equals(brand)) {
                throw new MeshTokenDeniedException("The access domain " + wanted
                        + " belongs to another brand; an admin can only issue tokens for its own.");
            }
        }
        long lifetime = req.lifetimeSeconds() == null ? defaultLifetime() : req.lifetimeSeconds();
        if (lifetime < MIN_LIFETIME_SECONDS || lifetime > props.effectiveMaxLifetimeSeconds()) {
            throw new MeshTokenInvalidException("The lifetime must be between " + MIN_LIFETIME_SECONDS
                    + " seconds and " + props.effectiveMaxLifetimeSeconds() / 86400 + " days.");
        }
        String nodeName = req.nodeName() == null ? "" : req.nodeName().trim();
        if (!nodeName.isEmpty() && !MeshTokenPayload.NODE_NAME_RE.matcher(nodeName).matches()) {
            throw new MeshTokenInvalidException("The node name must be empty or lower-case letters, digits "
                    + "and '-' (at most 63, not starting with '-').");
        }
        return new Authorized(entry.get(), role, req.shell(), lifetime, nodeName);
    }

    /**
     * Issue one token for {@code actor}. Order: dark check, validation + authorization, then the
     * headscale key (only after every refusal has had its chance), sign, audit, return. If the
     * audit insert fails the token is NOT returned: an unaudited token is never handed out.
     */
    public Mono<IssueResult> issue(String actor, PrincipalDomain scope, IssueRequest req) {
        if (!isEnabled()) {
            return Mono.error(new MeshTokenDarkException());
        }
        Authorized a;
        try {
            a = authorize(req, scope);
        } catch (MeshTokenInvalidException | MeshTokenDeniedException e) {
            return Mono.error(e);
        }
        long issuedAt = clock.instant().getEpochSecond();
        long expires = issuedAt + a.lifetime();
        String id = HexFormat.of().formatHex(randomBytes(8));
        return headscale.create(Instant.ofEpochSecond(expires))
                .flatMap(key -> signAndRecord(actor, a, id, issuedAt, expires, key));
    }

    private Mono<IssueResult> signAndRecord(String actor, Authorized a, String id, long issuedAt, long expires,
                                            HeadscalePreAuthKeyClient.PreAuthKey key) {
        MeshTokenPayload payload = new MeshTokenPayload(key.key(), a.domain().domain(), expires, id, issuedAt,
                issuerKey.publicLine(), a.domain().loginServer(), props.getMesh(), a.nodeName(), a.role(), a.shell());
        try {
            payload.check(clock.instant().getEpochSecond());
        } catch (MeshTokenPayload.InvalidPayloadException e) {
            return Mono.error(new MeshTokenInvalidException(e.getMessage()));
        }
        byte[] body = payload.canonicalBytes();
        byte[] sig = issuerKey.sign(body);
        String token = MeshTokenPayload.FORMAT + "." + b64u(body) + "." + b64u(sig);
        MeshTokenIssued audit = new MeshTokenIssued(id, props.getMesh(), a.domain().domain(), a.role(), a.shell(),
                a.domain().loginServer(), issuerKey.fingerprint(), key.id(), a.nodeName(), actor,
                Instant.ofEpochSecond(issuedAt), Instant.ofEpochSecond(expires));
        return issued.save(audit.toNewRow())
                .map(saved -> {
                    log.info("[mesh-token] ISSUED id={} mesh={} domain={} role={} shell={} issuer={} "
                                    + "preauthKeyId={} node={} by={} expires={}",
                            id, props.getMesh(), a.domain().domain(), a.role(), a.shell(), issuerKey.fingerprint(),
                            key.id(), a.nodeName(), actor, expires);
                    return new IssueResult(token, id, expires, issuerKey.fingerprint(),
                            describe(a.role(), a.domain().domain(), props.getMesh(), a.shell(), expires));
                });
    }

    /** One line for the UI, the same words as the tray's {@code MeshGrant.describe()} (times in UTC). */
    static String describe(String role, String domain, String mesh, boolean shell, long expires) {
        return role + " in " + domain + " (mesh " + mesh + "), " + (shell ? "shell access" : "no shell access")
                + ", expires " + WHEN.format(Instant.ofEpochSecond(expires));
    }

    private byte[] randomBytes(int n) {
        byte[] b = new byte[n];
        random.nextBytes(b);
        return b;
    }

    static String b64u(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    // ── audit list ──────────────────────────────────────────────────────────────────

    /** The audit trail this caller may see: all for SUPERADMIN, the brand's domains for ADMIN. Works while dark. */
    public Flux<MeshTokenIssued> list(PrincipalDomain scope) {
        if (scope != null && scope.superadmin()) {
            return issued.findTop200ByOrderByIssuedAtDesc().map(MeshTokenIssuedRow::toDomain);
        }
        String brand = scope == null ? PrincipalDomain.NO_DOMAIN : scope.domain();
        List<String> own = brandDomains(brand);
        if (own.isEmpty()) {
            return Flux.empty();
        }
        return issued.findTop200ByDomainInOrderByIssuedAtDesc(own).map(MeshTokenIssuedRow::toDomain);
    }

    /** Access domains a brand owns, read from configuration even while dark (so the list works). */
    private List<String> brandDomains(String brand) {
        List<MeshTokenProperties.DomainEntry> table;
        try {
            table = domains.isEmpty() ? props.domains() : domains;
        } catch (IllegalStateException e) {
            return List.of();
        }
        return table.stream().filter(d -> d.brand().equals(brand)).map(MeshTokenProperties.DomainEntry::domain).toList();
    }
}
