package net.hugmesh.adminbff.mfa;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.Collection;

/**
 * Reactive (R2DBC) Spring Data store for {@code role_mfa_policy} (changeSet 150). Reads are
 * derived finders; the single write is an idempotent {@code @Query} UPSERT keyed on the
 * {@code (domain, role)} UNIQUE constraint — the changelog's own GRANT comment says the table
 * is "upsert per (domain,role); never DELETEd", and the runtime role {@code adminbff_app}
 * holds exactly SELECT/INSERT/UPDATE, so no {@code delete*} finder is declared here on
 * purpose (it would compile, pass on the superuser test container, and 42501 in production).
 */
public interface RoleMfaPolicyR2dbcRepository extends ReactiveCrudRepository<RoleMfaPolicyRow, String> {

    /** Every configured row for a domain, role-ordered. */
    Flux<RoleMfaPolicyRow> findByDomainOrderByRole(String domain);

    /** The one row for a (domain, role), or empty (UNIQUE guarantees at most one). */
    Mono<RoleMfaPolicyRow> findByDomainAndRole(String domain, String role);

    /** Rows for a domain restricted to the given roles — the resolver's batch read. */
    Flux<RoleMfaPolicyRow> findByDomainAndRoleIn(String domain, Collection<String> roles);

    /**
     * INSERT-or-UPDATE one (domain, role) policy. {@code id} is only consumed on the INSERT
     * arm (no DB default on this PK — see {@link RoleMfaPolicyRow}); on conflict the existing
     * id is kept and required / methods / grace_seconds / updated_by / updated_at converge on
     * the supplied values. {@code created_at} takes its column DEFAULT. Returns rows updated
     * (Postgres reports 1 for either arm).
     */
    String UPSERT = """
            INSERT INTO role_mfa_policy \
            (id, domain, role, required, methods, grace_seconds, updated_by, updated_at) \
            VALUES (:id, :domain, :role, :required, :methods, :grace_seconds, :updated_by, now()) \
            ON CONFLICT (domain, role) DO UPDATE SET \
              required = EXCLUDED.required, \
              methods = EXCLUDED.methods, \
              grace_seconds = EXCLUDED.grace_seconds, \
              updated_by = EXCLUDED.updated_by, \
              updated_at = now()""";

    @Modifying
    @Query(UPSERT)
    Mono<Long> upsert(@Param("id") String id,
                      @Param("domain") String domain,
                      @Param("role") String role,
                      @Param("required") boolean required,
                      @Param("methods") String methods,
                      @Param("grace_seconds") long graceSeconds,
                      @Param("updated_by") String updatedBy);
}
