package net.hugmesh.adminbff.sshterminal;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Reactive (R2DBC) Spring Data store for {@code image_build} (changeset 171). The recent
 * list is a derived top-N finder; the terminal/non-terminal status UPDATE and the COALESCE
 * artifact UPDATE are {@code @Query} static-final constants (a stamping/COALESCE partial
 * UPDATE is not derivable). The {@link ImageBuildRepository} facade maps rows to/from the
 * {@link ImageBuild} domain record.
 */
public interface ImageBuildR2dbcRepository
        extends ReactiveCrudRepository<ImageBuildRow, String> {

    /**
     * Queue a new build with a DB-generated id (changelog 200): {@code id} is OMITTED → filled
     * from the {@code (gen_random_uuid())::text} column DEFAULT; {@code RETURNING id} reads the
     * generated varchar(36) back ({@code Mono<String>}). The not-yet-set {@code started_at}/
     * {@code finished_at}/{@code error} are OMITTED (default NULL — the fresh-build shape). Columns
     * match the {@link ImageBuildRow} order (id + those three excluded).
     */
    String INSERT_RETURNING_ID = """
            INSERT INTO image_build \
            (created_at, requested_by, target_user, domain, image_type, hardware_class, \
             device_id, status, ssh_keys_allowed, job_name, image_ref, keys_ref, image_spec_json) \
            VALUES (:createdAt, :requestedBy, :targetUser, :domain, :imageType, :hardwareClass, \
             :deviceId, :status, :sshKeysAllowed, :jobName, :imageRef, :keysRef, :imageSpecJson) \
            RETURNING id""";

    @Query(INSERT_RETURNING_ID)
    Mono<String> insertReturningId(@Param("createdAt") Instant createdAt,
                                   @Param("requestedBy") String requestedBy,
                                   @Param("targetUser") String targetUser,
                                   @Param("domain") String domain,
                                   @Param("imageType") String imageType,
                                   @Param("hardwareClass") String hardwareClass,
                                   @Param("deviceId") String deviceId,
                                   @Param("status") String status,
                                   @Param("sshKeysAllowed") boolean sshKeysAllowed,
                                   @Param("jobName") String jobName,
                                   @Param("imageRef") String imageRef,
                                   @Param("keysRef") String keysRef,
                                   @Param("imageSpecJson") String imageSpecJson);

    /** The {@code limit} most-recent builds, newest first — the admin console list scan. */
    Flux<ImageBuildRow> findByOrderByCreatedAtDesc(org.springframework.data.domain.Limit limit);

    /** The {@code limit} most-recent builds FOR ONE DOMAIN, newest first — the tenant-scoped
     *  list a non-superadmin admin sees (own-domain wall; superadmin uses the unscoped finder). */
    Flux<ImageBuildRow> findByDomainOrderByCreatedAtDesc(String domain,
                                                         org.springframework.data.domain.Limit limit);

    /** Set status only (non-terminal transition). Returns rows updated (0 = absent). */
    String UPDATE_STATUS =
            "UPDATE image_build SET status = :status WHERE id = :id";

    @Modifying
    @Query(UPDATE_STATUS)
    Mono<Long> updateStatus(String id, String status);

    /** Set status and stamp {@code finished_at} (terminal transition). */
    String UPDATE_STATUS_TERMINAL =
            "UPDATE image_build SET status = :status, finished_at = now() WHERE id = :id";

    @Modifying
    @Query(UPDATE_STATUS_TERMINAL)
    Mono<Long> updateStatusTerminal(String id, String status);

    /**
     * Record NON-SECRET artifact pointers + terminal error, COALESCE-preserving an existing
     * value when the argument is null. Returns rows updated (0 = absent).
     */
    String RECORD_ARTIFACTS =
            "UPDATE image_build SET "
            + "image_ref = COALESCE(:imageRef, image_ref), "
            + "keys_ref = COALESCE(:keysRef, keys_ref), "
            + "error = COALESCE(:error, error) "
            + "WHERE id = :id";

    @Modifying
    @Query(RECORD_ARTIFACTS)
    Mono<Long> recordArtifacts(String id, String imageRef, String keysRef, String error);
}
