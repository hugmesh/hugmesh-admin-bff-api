package systems.hugmesh.adminbff.egressvpn;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Reactive (R2DBC) Spring Data store for {@code vpn_config} (changeset 080). Derived
 * finders cover the idempotency lookup + the scoped/unscoped ordered lists; the
 * MAX(generation) aggregate, the CAS-on-state audited revoke (scoped + unscoped), and the
 * partial propagation-state UPDATE are {@code @Query} static-final constants. The {@link
 * VpnConfigRepository} facade maps rows to/from {@link VpnConfig}.
 *
 * <p>DB-GENERATED PK (changelog 200): the varchar(36) {@code id} carries a
 * {@code (gen_random_uuid())::text} DEFAULT; the INSERT OMITS {@code id} and appends
 * {@code RETURNING id} to read the database-generated string back ({@code Mono<String>}).
 */
public interface VpnConfigRowRepository extends ReactiveCrudRepository<VpnConfigRow, String> {

    /**
     * Insert a new config with a DB-generated id (id OMITTED → filled from the column DEFAULT;
     * {@code RETURNING id} reads the generated varchar(36) back). The nullable {@code
     * revoked_at}/{@code revoked_by} are OMITTED (default NULL — the fresh-config shape). The
     * supplied columns match the {@link VpnConfigRow} column order (id + revoke-audit
     * columns excluded).
     */
    String INSERT_RETURNING_ID = """
            INSERT INTO vpn_config \
            (domain, name, kind, provider, endpoint, secret_ref, state, created_by, \
             created_at, propagation_state, generation) \
            VALUES (:domain, :name, :kind, :provider, :endpoint, :secret_ref, :state, \
             :created_by, :created_at, :propagation_state, :generation) \
            RETURNING id""";

    @Query(INSERT_RETURNING_ID)
    Mono<String> insertReturningId(@Param("domain") String domain,
                                   @Param("name") String name,
                                   @Param("kind") String kind,
                                   @Param("provider") String provider,
                                   @Param("endpoint") String endpoint,
                                   @Param("secret_ref") String secretRef,
                                   @Param("state") String state,
                                   @Param("created_by") String createdBy,
                                   @Param("created_at") Instant createdAt,
                                   @Param("propagation_state") String propagationState,
                                   @Param("generation") long generation);

    Mono<VpnConfigRow> findByDomainAndNameAndState(String domain, String name, String state);

    Flux<VpnConfigRow> findByDomainOrderByNameAscCreatedAtDesc(String domain);

    Flux<VpnConfigRow> findAllByOrderByDomainAscNameAscCreatedAtDesc();

    Flux<VpnConfigRow> findByStateOrderByDomainAscNameAsc(String state);

    String MAX_GENERATION = "SELECT COALESCE(MAX(generation), 0) AS g FROM vpn_config";

    @Query(MAX_GENERATION)
    Mono<Long> maxGeneration();

    String REVOKE_SCOPED =
            "UPDATE vpn_config SET state = 'revoked', revoked_at = now(), revoked_by = :by, "
            + "generation = :gen, propagation_state = 'pending' "
            + "WHERE id = :id AND state = 'active' AND domain = :domain";

    @Modifying
    @Query(REVOKE_SCOPED)
    Mono<Long> revokeScoped(String id, String by, long gen, String domain);

    String REVOKE_UNSCOPED =
            "UPDATE vpn_config SET state = 'revoked', revoked_at = now(), revoked_by = :by, "
            + "generation = :gen, propagation_state = 'pending' "
            + "WHERE id = :id AND state = 'active'";

    @Modifying
    @Query(REVOKE_UNSCOPED)
    Mono<Long> revokeUnscoped(String id, String by, long gen);

    String UPDATE_PROP = "UPDATE vpn_config SET propagation_state = :ps WHERE id = :id";

    @Modifying
    @Query(UPDATE_PROP)
    Mono<Long> updatePropagationState(String id, String ps);
}
