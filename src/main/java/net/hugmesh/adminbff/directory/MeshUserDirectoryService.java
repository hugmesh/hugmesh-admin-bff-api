package net.hugmesh.adminbff.directory;

import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.PrincipalDomain;

import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * The directory a SIGNED-IN MEMBER's pickers autofill from (start a chat, invite to a room or a
 * game): registered accounts on the member's OWN domain, or every domain for a SUPERADMIN.
 *
 * <p>The scope is the point, exactly as for the admin typeahead ({@link UserDirectoryService}):
 * <ul>
 *   <li>the domain predicate is applied by the QUERY (the caller's domain's issuers go in the
 *       {@code WHERE}), never by filtering after a wider read;</li>
 *   <li>a scope that resolves to no issuer FAILS CLOSED (empty list, no query);</li>
 *   <li>only a SUPERADMIN scope reaches the unscoped finder;</li>
 *   <li>the row cap is the SQL {@code LIMIT}, and a fragment shorter than {@link #MIN_QUERY} returns
 *       nothing, so the endpoint answers "who is named like this" and cannot be walked to list everyone;</li>
 *   <li>rows carry NO e-mail/handle ({@link MeshUser}).</li>
 * </ul>
 */
@Service
public class MeshUserDirectoryService {

    /** Shortest fragment that searches at all. */
    public static final int MIN_QUERY = 2;
    /** Hard cap on rows, whatever the caller asks for. */
    public static final int MAX_LIMIT = 25;

    private final MeshUserDirectoryRepository repo;
    private final DomainRegistry domains;

    public MeshUserDirectoryService(MeshUserDirectoryRepository repo, DomainRegistry domains) {
        this.repo = repo;
        this.domains = domains;
    }

    public Mono<List<MeshUser>> search(PrincipalDomain scope, String query, int limit) {
        String q = query == null ? "" : query.trim().toLowerCase(Locale.ROOT);
        if (q.length() < MIN_QUERY) {
            return Mono.just(List.of());
        }
        int cap = Math.max(1, Math.min(limit, MAX_LIMIT));
        String escaped = escapeLike(q);
        String contains = "%" + escaped + "%";
        String prefix = escaped + "%";
        PrincipalDomain effective = scope == null ? PrincipalDomain.forDomain(PrincipalDomain.NO_DOMAIN) : scope;

        if (effective.superadmin()) {
            return repo.searchAll(contains, prefix, cap).map(this::toUser).collectList();
        }
        Set<String> issuers = domains.trustedIssuers().stream()
                .filter(i -> effective.domain().equals(domains.domainOf(i)))
                .collect(Collectors.toUnmodifiableSet());
        if (issuers.isEmpty()) {
            return Mono.just(List.of());
        }
        var rows = domains.isMultiIssuer()
                ? repo.searchInIssuers(issuers, contains, prefix, cap)
                : repo.searchInIssuersOrUnstamped(issuers, contains, prefix, cap);
        return rows.map(this::toUser).collectList();
    }

    private MeshUser toUser(MeshUserRow row) {
        String domain = row.accountIssuer() == null ? null : domains.domainOf(row.accountIssuer());
        return new MeshUser(row.casdoorUsername(), row.localpart(), domain);
    }

    /** Escape the LIKE metacharacters so a typed {@code %} or {@code _} matches itself. */
    static String escapeLike(String s) {
        return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_");
    }
}
