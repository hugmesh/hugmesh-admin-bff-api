package net.hugmesh.adminbff.directory;

import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.authcore.account.AccountStore;
import net.hugmesh.authcore.casdoor.CasdoorAdminClient;
import net.hugmesh.commons.security.PrincipalDomain;

import java.util.Comparator;
import java.util.List;
import java.util.Locale;

/**
 * The DOMAIN-SCOPED user directory search behind every admin console's user typeahead.
 *
 * <h3>Why this exists at all (and is not just the allowlist read)</h3>
 * {@code GET /bff/admin/allowlist} already returns the caller's own brand's invite
 * handles, so a picker COULD have been built on it. Three things make that the wrong
 * shape for a typeahead and are the reason this service exists:
 * <ol>
 *   <li>It returns the RAW handles ({@code alice@example.org}), but every write surface
 *       — {@code /bff/admin/roles/{roleName}/{user}},
 *       {@code /bff/admin/access-roles/{role}/{user}},
 *       {@code /bff/admin/domain-lock/{role}/{user}} — is keyed on the CASDOOR USERNAME.
 *       The derivation ({@link CasdoorAdminClient#usernameOf}) is a service-side rule; a
 *       picker that guessed it in the browser would drift from the mint path.</li>
 *   <li>It is UNCAPPED. A typeahead that pulls the whole brand's directory into the
 *       browser on page load scales with the tenant, not with what the admin typed.</li>
 *   <li>The MATCH must happen server-side. Filtering a full client-side list is exactly
 *       the enumeration hole this endpoint is meant to close — the cap and the domain
 *       predicate have to be applied before the bytes leave the BFF.</li>
 * </ol>
 *
 * <h3>Scoping — derived from the token, never from the request</h3>
 * The caller's brand comes from {@link PrincipalDomain} (resolved from the
 * cryptographically-validated JWT issuer at the controller boundary). There is
 * deliberately NO {@code domain} request parameter: a brand-X ADMIN searching for a
 * brand-Y user gets zero rows because the underlying query never reads brand Y's
 * {@code allowlist} rows, not because the UI hid them. A SUPERADMIN is unscoped (the
 * cross-brand infra role) and searches every brand — the same asymmetry
 * {@code AdminController#allowlistOut} already applies to the plain list read.
 */
@Service
public class UserDirectoryService {

    /**
     * Hard server-side ceiling on returned rows. A typeahead only ever renders a handful;
     * this exists so a one-character query can never turn the picker into a bulk export,
     * and so the cap is enforced where it counts (before serialization) rather than by
     * whatever the client asked for.
     */
    public static final int MAX_LIMIT = 25;

    /** The two identity providers the allowlist carries — the whole searchable universe. */
    private static final List<String> PROVIDERS = List.of("google", "discord");

    private final AccountStore store;

    public UserDirectoryService(AccountStore store) {
        this.store = store;
    }

    /**
     * Search the caller's visible slice of the user directory.
     *
     * @param scope the caller's tenant scope, resolved from their validated JWT issuer.
     *              A scoped ADMIN reads ONLY their own brand's rows; a SUPERADMIN is
     *              unscoped. A {@code null} scope fails closed to
     *              {@link PrincipalDomain#NO_DOMAIN}, which matches no real brand.
     * @param query the typed prefix/substring. Blank yields an EMPTY result rather than
     *              the whole directory — the picker's "keep typing" state is a real
     *              server contract, not a client-side courtesy.
     * @param limit the caller's requested cap, clamped into {@code [1, MAX_LIMIT]}.
     * @return at most {@code limit} matches, best-match first.
     */
    public Mono<List<DirectoryUser>> search(PrincipalDomain scope, String query, int limit) {
        String q = query == null ? "" : query.trim().toLowerCase(Locale.ROOT);
        if (q.isEmpty()) {
            return Mono.just(List.of());
        }
        int cap = Math.max(1, Math.min(limit, MAX_LIMIT));
        PrincipalDomain effective = scope == null
                ? PrincipalDomain.forDomain(PrincipalDomain.NO_DOMAIN) : scope;
        return Flux.fromIterable(PROVIDERS)
                .flatMap(provider -> handles(effective, provider)
                        .map(handle -> toUser(provider, handle, effective)))
                .filter(u -> matches(u, q))
                .collectList()
                // Rank AFTER collecting: a prefix hit on either the Casdoor username or the
                // handle is what the admin almost always meant, so it must outrank a
                // mid-string hit from the other provider's stream — which per-provider
                // ordering alone cannot express.
                .map(all -> all.stream()
                        .sorted(rankFor(q))
                        .limit(cap)
                        .toList());
    }

    /**
     * The domain predicate. A scoped principal reads the {@code AndDomain} finder (SQL
     * {@code WHERE domain = :domain}); only a SUPERADMIN takes the unscoped variant. This
     * is the single place brand isolation is enforced for the picker.
     */
    private Flux<String> handles(PrincipalDomain scope, String provider) {
        if ("discord".equals(provider)) {
            return scope.scoped() ? store.allowedDiscord(scope.domain()) : store.allowedDiscord();
        }
        return scope.scoped() ? store.allowedEmails(scope.domain()) : store.allowedEmails();
    }

    /**
     * Project an invite handle into a picker row, deriving the Casdoor username with the
     * SAME rule the mint path uses so the value the picker submits is the value the write
     * endpoints resolve.
     *
     * <p>The row's {@code domain} is the CALLER's scope, not a per-row read: the scoped
     * finder already guarantees every row belongs to {@code scope.domain()}, and the
     * unscoped (SUPERADMIN) finder returns bare handles with no domain attached — so
     * claiming a per-row brand there would be inventing one. A superadmin therefore sees
     * their own home brand on every row; that is honest about what the underlying read
     * actually carries.
     */
    private DirectoryUser toUser(String provider, String handle, PrincipalDomain scope) {
        return new DirectoryUser(
                CasdoorAdminClient.usernameOf(provider, handle), handle, provider, scope.domain());
    }

    /** Case-insensitive substring match on either the derived username or the raw handle. */
    private static boolean matches(DirectoryUser u, String q) {
        return u.username().toLowerCase(Locale.ROOT).contains(q)
                || u.handle().toLowerCase(Locale.ROOT).contains(q);
    }

    /**
     * Best-match-first ordering: prefix hits before substring hits, then alphabetical by
     * username so the list is stable across identical queries (an unstable typeahead
     * reorders under the user's cursor between keystrokes).
     */
    private static Comparator<DirectoryUser> rankFor(String q) {
        return Comparator
                .comparingInt((DirectoryUser u) -> prefixRank(u, q))
                .thenComparing(DirectoryUser::username)
                .thenComparing(DirectoryUser::handle);
    }

    /** 0 when the query prefixes the username or handle, 1 otherwise (lower sorts first). */
    private static int prefixRank(DirectoryUser u, String q) {
        boolean prefix = u.username().toLowerCase(Locale.ROOT).startsWith(q)
                || u.handle().toLowerCase(Locale.ROOT).startsWith(q);
        return prefix ? 0 : 1;
    }
}
