package net.hugmesh.adminbff.sshterminal;

import org.springframework.data.domain.Limit;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Reactive (R2DBC) store for {@code image_build} — the image-generation request catalog
 * (schema in Liquibase {@code db/changelog/171-image-build.xml}).
 *
 * <p>Backed by the Spring Data {@link ImageBuildR2dbcRepository} (no raw
 * {@code DatabaseClient}); maps the {@link ImageBuildRow} entity to the {@link ImageBuild}
 * domain record.
 *
 * <p>SHIPS DARK: no caller wires this repository at runtime yet — the generator Job
 * effector that consumes a QUEUED row is a LATER PR. These methods are the trivial
 * insert / read / list-recent / status surface that later PR will use.
 */
@Repository
public class ImageBuildRepository {

    private final ImageBuildR2dbcRepository repo;

    public ImageBuildRepository(ImageBuildR2dbcRepository repo) {
        this.repo = repo;
    }

    /**
     * Queue a new image build (app-generated id), returning it. The caller (the service)
     * has resolved {@code requestedBy} / {@code targetUser} (owner == subject) and the
     * validated-issuer {@code domain} before this insert. status starts {@code QUEUED};
     * {@code sshKeysAllowed} defaults to the record value (fail-closed false).
     */
    public Mono<ImageBuild> insert(ImageBuild b) {
        String status = b.status() == null ? ImageBuild.STATUS_QUEUED : b.status();
        Instant createdAt = Instant.now();
        // INSERT omits id (filled from the (gen_random_uuid())::text column DEFAULT, changelog
        // 200) and the not-yet-set started_at/finished_at/error (default NULL); RETURNING id hands
        // back the generated string, mapped into the persisted build with the SAME field
        // order/values as before.
        return repo.insertReturningId(createdAt, b.requestedBy(), b.targetUser(), b.domain(),
                        b.imageType(), b.hardwareClass(), b.deviceId(), status, b.sshKeysAllowed(),
                        b.jobName(), b.imageRef(), b.keysRef(), b.imageSpecJson())
                .map(genId -> new ImageBuild(genId, createdAt, b.requestedBy(), b.targetUser(),
                        b.domain(), b.imageType(), b.hardwareClass(), b.deviceId(), status,
                        b.sshKeysAllowed(), b.jobName(), b.imageRef(), b.keysRef(),
                        null, null, null, b.imageSpecJson()));
    }

    /** The build with this id, if any. */
    public Mono<ImageBuild> findById(String id) {
        return repo.findById(id).map(ImageBuildRow::toDomain);
    }

    /** The {@code limit} most-recent builds, newest first — the admin console list scan
     *  (SUPERADMIN, cross-brand). Non-superadmin callers MUST use {@link #listRecentForDomain}. */
    public Flux<ImageBuild> listRecent(int limit) {
        return repo.findByOrderByCreatedAtDesc(Limit.of(limit)).map(ImageBuildRow::toDomain);
    }

    /** The {@code limit} most-recent builds OWNED BY {@code domain}, newest first — the
     *  tenant-scoped console list a non-superadmin admin sees (own-domain wall; the domain
     *  predicate is applied in SQL so the LIMIT is over the caller's own rows, not the
     *  global set). */
    public Flux<ImageBuild> listRecentForDomain(String domain, int limit) {
        return repo.findByDomainOrderByCreatedAtDesc(domain, Limit.of(limit)).map(ImageBuildRow::toDomain);
    }

    /**
     * Set the lifecycle status for a build by id ({@code QUEUED -> RUNNING -> COMPLETED |
     * FAILED | ERROR}), stamping {@code finished_at} for the terminal states. Returns the
     * rows-updated count (0 = absent). The valid status vocabulary is the
     * {@code ck_image_build_status} CHECK backstop.
     */
    public Mono<Long> updateStatus(String id, String status) {
        boolean terminal = ImageBuild.STATUS_COMPLETED.equals(status)
                || ImageBuild.STATUS_FAILED.equals(status)
                || ImageBuild.STATUS_ERROR.equals(status);
        return terminal
                ? repo.updateStatusTerminal(id, status)
                : repo.updateStatus(id, status);
    }

    /**
     * Record the NON-SECRET artifact POINTERS ({@code image_ref} / {@code keys_ref}) and the
     * terminal {@code error} text the in-cluster Job reported, preserving an existing value when
     * the corresponding argument is null (COALESCE). NEVER writes any secret material —
     * {@code keysRef} is a pointer to the PUBLIC keys bundle, never a private key. Returns the
     * rows-updated count (0 = absent).
     */
    public Mono<Long> recordArtifacts(String id, String imageRef, String keysRef, String error) {
        return repo.recordArtifacts(id, imageRef, keysRef, error);
    }
}
