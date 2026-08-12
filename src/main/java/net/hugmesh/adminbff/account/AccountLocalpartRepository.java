package net.hugmesh.adminbff.account;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

/**
 * Reactive (R2DBC) Spring Data store for the {@code account.localpart} column
 * (Liquibase changeset 290) — see {@link AccountLocalpartRow} for why this is a
 * narrow projection over the SAME {@code account} table auth-core's
 * {@code AccountRowRepository} already maps, rather than a field added there.
 */
public interface AccountLocalpartRepository extends ReactiveCrudRepository<AccountLocalpartRow, String> {

    /**
     * Does {@code localpart} already belong to some OTHER account row (id != {@code
     * excludeId})? The {@code idNot} exclusion is what makes a repeat {@code
     * ensureAccount} call for an EXISTING account idempotent — the row's own
     * already-persisted localpart must never collide with itself.
     */
    Mono<Boolean> existsByLocalpartAndIdNot(String localpart, String excludeId);

    /**
     * Does {@code mastodonLocalpart} already belong to some OTHER account row? The
     * Mastodon-fold sibling of {@link #existsByLocalpartAndIdNot} (Liquibase changeset
     * 291) — the residual half of the account-takeover-by-collision guard.
     */
    Mono<Boolean> existsByMastodonLocalpartAndIdNot(String mastodonLocalpart, String excludeId);

    /** Targeted single-column write — never touches the other {@code account} columns
     *  (those are auth-core's {@code AccountRowRepository}'s to write). */
    @Modifying
    @Query("UPDATE account SET localpart = :localpart WHERE id = :id")
    Mono<Long> updateLocalpart(@Param("id") String id, @Param("localpart") String localpart);

    /**
     * Write BOTH resolved localpart columns in one statement (the Matrix fold and its
     * coarser Mastodon fold) — still only ever the two columns this projection owns,
     * never auth-core's. Used by {@link AccountLocalpartService#resolveAndPersist} so a
     * single account-creation resolves both folds atomically.
     */
    @Modifying
    @Query("UPDATE account SET localpart = :localpart, mastodon_localpart = :mastodonLocalpart WHERE id = :id")
    Mono<Long> updateLocalparts(@Param("id") String id, @Param("localpart") String localpart,
                                @Param("mastodonLocalpart") String mastodonLocalpart);
}
