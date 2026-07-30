package systems.hugmesh.adminbff.account;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

/**
 * Reactive (R2DBC) Spring Data store for the {@code account.casdoor_sub} column
 * (Liquibase changeset 292) — see {@link AccountCasdoorSubRow} for why this is a
 * narrow projection over the SAME {@code account} table auth-core's
 * {@code AccountRowRepository} already maps, rather than a field added there.
 */
public interface AccountCasdoorSubRepository extends ReactiveCrudRepository<AccountCasdoorSubRow, String> {

    /** Targeted single-column write — never touches the other {@code account} columns
     *  (those belong to auth-core's {@code AccountRowRepository} and the localpart
     *  projection). Returns the affected-row count (0 for an unknown account id). */
    @Modifying
    @Query("UPDATE account SET casdoor_sub = :casdoorSub WHERE id = :id")
    Mono<Long> updateCasdoorSub(@Param("id") String id, @Param("casdoorSub") String casdoorSub);
}
