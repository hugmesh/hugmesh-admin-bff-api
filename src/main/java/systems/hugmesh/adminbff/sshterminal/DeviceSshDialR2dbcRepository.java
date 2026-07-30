package systems.hugmesh.adminbff.sshterminal;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Reactive (R2DBC) Spring Data store for {@code device_ssh_dial} (changeset 170). The
 * per-device / per-id lookups are derived finders; the scope JOIN onto {@code device_registry}
 * and the status setters / compare-and-swap transitions are {@code @Query} static-final
 * constants (a cross-table JOIN and CAS-on-status UPDATEs are not derivable). The
 * {@link DeviceSshDialRepository} facade maps rows to/from the {@link DeviceSshDial} domain
 * record.
 */
public interface DeviceSshDialR2dbcRepository
        extends ReactiveCrudRepository<DeviceSshDialRow, String> {

    /**
     * Seed a new dial-key row with a DB-generated id (changelog 200): {@code id} is OMITTED →
     * filled from the {@code (gen_random_uuid())::text} column DEFAULT; {@code RETURNING id} reads
     * the generated varchar(36) back ({@code Mono<String>}). The not-yet-set {@code rotated_at} is
     * OMITTED (default NULL — the fresh-row shape). Only NON-SECRET material lands here. Columns
     * match the {@link DeviceSshDialRow} order (id + rotated_at excluded).
     */
    String INSERT_RETURNING_ID = """
            INSERT INTO device_ssh_dial \
            (device_id, dial_user, host_key_pub, host_key_fp, dial_pub_fp, vault_ref, \
             k8s_secret_name, seeded_by_build_id, status, generation, created_at) \
            VALUES (:deviceId, :dialUser, :hostKeyPub, :hostKeyFp, :dialPubFp, :vaultRef, \
             :k8sSecretName, :seededByBuildId, :status, :generation, :createdAt) \
            RETURNING id""";

    @Query(INSERT_RETURNING_ID)
    Mono<String> insertReturningId(@Param("deviceId") String deviceId,
                                   @Param("dialUser") String dialUser,
                                   @Param("hostKeyPub") String hostKeyPub,
                                   @Param("hostKeyFp") String hostKeyFp,
                                   @Param("dialPubFp") String dialPubFp,
                                   @Param("vaultRef") String vaultRef,
                                   @Param("k8sSecretName") String k8sSecretName,
                                   @Param("seededByBuildId") String seededByBuildId,
                                   @Param("status") String status,
                                   @Param("generation") long generation,
                                   @Param("createdAt") Instant createdAt);

    /** The dial-key row for this device, if any (UNIQUE(device_id) => at most one). */
    Mono<DeviceSshDialRow> findByDeviceId(String deviceId);

    String COLS =
            "id, device_id, dial_user, host_key_pub, host_key_fp, dial_pub_fp, vault_ref, "
            + "k8s_secret_name, seeded_by_build_id, status, generation, created_at, rotated_at";

    /** Dial rows for a brand (scoped) — JOIN the owning device's residency domain. */
    String LIST_SCOPED = """
            SELECT d.id, d.device_id, d.dial_user, d.host_key_pub, d.host_key_fp,
                   d.dial_pub_fp, d.vault_ref, d.k8s_secret_name, d.seeded_by_build_id, d.status,
                   d.generation, d.created_at, d.rotated_at
            FROM device_ssh_dial d JOIN device_registry r ON r.id = d.device_id
            WHERE r.domain = :domain ORDER BY d.device_id
            """;

    @Query(LIST_SCOPED)
    Flux<DeviceSshDialRow> listScoped(String domain);

    /** All dial rows (unscoped / SUPERADMIN), device-ordered. */
    String LIST_ALL = """
            SELECT id, device_id, dial_user, host_key_pub, host_key_fp, dial_pub_fp, vault_ref,
                   k8s_secret_name, seeded_by_build_id, status, generation, created_at, rotated_at
            FROM device_ssh_dial ORDER BY device_id
            """;

    @Query(LIST_ALL)
    Flux<DeviceSshDialRow> listAll();

    /** UNGUARDED status set, stamping {@code rotated_at}. Returns rows updated (0 = absent). */
    String UPDATE_STATUS =
            "UPDATE device_ssh_dial SET status = :status, rotated_at = now() WHERE id = :id";

    @Modifying
    @Query(UPDATE_STATUS)
    Mono<Long> updateStatus(String id, String status);

    /** CAS {@code PENDING -> ACTIVE} at a new generation, requiring a pinned host_key_fp. */
    String ACTIVATE =
            "UPDATE device_ssh_dial SET status = 'ACTIVE', generation = :gen, rotated_at = now() "
            + "WHERE id = :id AND status = 'PENDING' "
            + "AND host_key_fp IS NOT NULL AND host_key_fp <> ''";

    @Modifying
    @Query(ACTIVATE)
    Mono<Long> activate(String id, long gen);

    /** CAS {@code ACTIVE -> REVOKED} at a new generation. */
    String REVOKE =
            "UPDATE device_ssh_dial SET status = 'REVOKED', generation = :gen, rotated_at = now() "
            + "WHERE id = :id AND status = 'ACTIVE'";

    @Modifying
    @Query(REVOKE)
    Mono<Long> revoke(String id, long gen);
}
