package net.hugmesh.adminbff.directory;

import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;

import java.util.Collection;

/**
 * The member-facing directory's reads. BOTH the domain predicate and the row cap are in the SQL:
 * a scoped caller's query names its issuers in the {@code WHERE}, so another domain's rows are
 * never read, and {@code LIMIT} bounds what a typeahead can pull. Only fully registered accounts
 * with a Casdoor username are listed — an invite that was never accepted is not a mesh user.
 *
 * <p>{@code :contains} and {@code :prefix} are pre-escaped LIKE patterns (the service escapes
 * {@code % _ \}); {@code :prefix} only orders prefix hits ahead of mid-string hits.
 */
public interface MeshUserDirectoryRepository extends ReactiveCrudRepository<MeshUserRow, String> {

    String VISIBLE = "registration_complete = TRUE AND casdoor_username IS NOT NULL AND casdoor_username <> '' "
            + "AND (LOWER(casdoor_username) LIKE :contains ESCAPE '\\' OR LOWER(COALESCE(localpart, '')) LIKE :contains ESCAPE '\\') ";
    String ORDER = "ORDER BY CASE WHEN LOWER(casdoor_username) LIKE :prefix ESCAPE '\\' "
            + "OR LOWER(COALESCE(localpart, '')) LIKE :prefix ESCAPE '\\' THEN 0 ELSE 1 END, casdoor_username LIMIT :limit";

    /** A scoped caller: only accounts stamped with one of the caller's own domain's issuers. */
    @Query("SELECT id, casdoor_username, localpart, account_issuer FROM account WHERE " + VISIBLE
            + "AND account_issuer IN (:issuers) " + ORDER)
    Flux<MeshUserRow> searchInIssuers(@Param("issuers") Collection<String> issuers,
                                      @Param("contains") String contains,
                                      @Param("prefix") String prefix,
                                      @Param("limit") int limit);

    /** Single-issuer deployments stamp nothing on older rows: those belong to the one domain. */
    @Query("SELECT id, casdoor_username, localpart, account_issuer FROM account WHERE " + VISIBLE
            + "AND (account_issuer IN (:issuers) OR account_issuer IS NULL) " + ORDER)
    Flux<MeshUserRow> searchInIssuersOrUnstamped(@Param("issuers") Collection<String> issuers,
                                                 @Param("contains") String contains,
                                                 @Param("prefix") String prefix,
                                                 @Param("limit") int limit);

    /** SUPERADMIN only: every domain. */
    @Query("SELECT id, casdoor_username, localpart, account_issuer FROM account WHERE " + VISIBLE + ORDER)
    Flux<MeshUserRow> searchAll(@Param("contains") String contains,
                                @Param("prefix") String prefix,
                                @Param("limit") int limit);
}
