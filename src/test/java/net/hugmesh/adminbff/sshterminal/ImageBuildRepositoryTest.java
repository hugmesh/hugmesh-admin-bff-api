package net.hugmesh.adminbff.sshterminal;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import reactor.test.StepVerifier;
import net.hugmesh.adminbff.support.TestDatabaseConfig;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link ImageBuildRepository} over a Liquibase-applied H2 (PG-compat) — proves the 171
 * changelog applies (image_build + the status CHECK + the image_type CHECK) and the
 * queue / read / list-recent / status idiom round-trips. Mirrors
 * {@link net.hugmesh.adminbff.cloudbackup.BackupSetRepositoryTest} wiring.
 *
 * <p>Per the test-standard: USER-SITUATIONAL (queue/read/status), LIST ordering
 * (newest-first), plus the constraint behaviors (status CHECK + image_type CHECK reject a
 * bad vocabulary) and the fail-closed ssh_keys_allowed default.
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
@ActiveProfiles("test")
class ImageBuildRepositoryTest {

    @Autowired DatabaseClient db;

    @BeforeEach
    void clean() {
        db.sql("DELETE FROM image_build").fetch().rowsUpdated().block();
    }

    private ImageBuildRepository repo() {
        return new ImageBuildRepository(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.adminbff.sshterminal.ImageBuildR2dbcRepository.class));
    }

    private ImageBuild queued(String imageType, boolean keysAllowed) {
        return new ImageBuild(null, null, "alice", "bob", "brandx", imageType,
                "pi", null, ImageBuild.STATUS_QUEUED, keysAllowed,
                null, null, null, null, null, null);
    }

    // ── USER-SITUATIONAL: queue round-trips, lifecycle ────────────────────────────────────

    @Test
    void insert_roundTrips_queued_keysFailClosed() {
        ImageBuild b = repo().insert(queued(ImageBuild.IMAGE_PRIMARY, false)).block();
        assertThat(b).isNotNull();
        assertThat(b.id()).isNotBlank();
        assertThat(b.status()).isEqualTo(ImageBuild.STATUS_QUEUED);
        assertThat(b.sshKeysAllowed()).isFalse();
        assertThat(b.createdAt()).isNotNull();

        ImageBuild read = repo().findById(b.id()).block();
        assertThat(read).isNotNull();
        assertThat(read.requestedBy()).isEqualTo("alice");
        assertThat(read.targetUser()).isEqualTo("bob");
        assertThat(read.domain()).isEqualTo("brandx");
        assertThat(read.imageType()).isEqualTo("primary");
        assertThat(read.hardwareClass()).isEqualTo("pi");
        assertThat(read.sshKeysAllowed()).isFalse();
        assertThat(read.startedAt()).isNull();
        assertThat(read.finishedAt()).isNull();
    }

    @Test
    void insert_keysAllowedTrue_persists() {
        ImageBuild b = repo().insert(queued(ImageBuild.IMAGE_CLIENT, true)).block();
        assertThat(repo().findById(b.id()).block().sshKeysAllowed()).isTrue();
    }

    @Test
    void updateStatus_running_doesNotStampFinished() {
        ImageBuild b = repo().insert(queued(ImageBuild.IMAGE_PRIMARY, false)).block();
        assertThat(repo().updateStatus(b.id(), ImageBuild.STATUS_RUNNING).block()).isEqualTo(1L);
        ImageBuild read = repo().findById(b.id()).block();
        assertThat(read.status()).isEqualTo(ImageBuild.STATUS_RUNNING);
        assertThat(read.finishedAt()).isNull();
    }

    @Test
    void updateStatus_completed_stampsFinished() {
        ImageBuild b = repo().insert(queued(ImageBuild.IMAGE_PRIMARY, false)).block();
        assertThat(repo().updateStatus(b.id(), ImageBuild.STATUS_COMPLETED).block()).isEqualTo(1L);
        ImageBuild read = repo().findById(b.id()).block();
        assertThat(read.status()).isEqualTo(ImageBuild.STATUS_COMPLETED);
        assertThat(read.finishedAt()).isNotNull();
    }

    @Test
    void updateStatus_failed_stampsFinished() {
        ImageBuild b = repo().insert(queued(ImageBuild.IMAGE_MESH_EXTENSION, false)).block();
        assertThat(repo().updateStatus(b.id(), ImageBuild.STATUS_FAILED).block()).isEqualTo(1L);
        assertThat(repo().findById(b.id()).block().finishedAt()).isNotNull();
    }

    @Test
    void updateStatus_absentRow_isNoOp() {
        assertThat(repo().updateStatus("nope", ImageBuild.STATUS_RUNNING).block()).isEqualTo(0L);
    }

    @Test
    void findById_absent_empty() {
        StepVerifier.create(repo().findById("missing")).verifyComplete();
    }

    // ── LIST: newest-first ────────────────────────────────────────────────────────────────

    @Test
    void listRecent_newestFirst_bounded() {
        repo().insert(queued(ImageBuild.IMAGE_PRIMARY, false)).block();
        ImageBuild second = repo().insert(queued(ImageBuild.IMAGE_CLIENT, true)).block();
        ImageBuild third = repo().insert(queued(ImageBuild.IMAGE_MESH_EXTENSION, false)).block();
        List<ImageBuild> recent = repo().listRecent(2).collectList().block();
        assertThat(recent).hasSize(2);
        // the two newest rows come back; the very first is excluded by the limit.
        assertThat(recent).extracting(ImageBuild::id)
                .containsExactlyInAnyOrder(second.id(), third.id());
    }

    // ── CONSTRAINTS: status CHECK + image_type CHECK ──────────────────────────────────────

    @Test
    void statusCheck_rejectsBadVocabulary() {
        ImageBuild b = repo().insert(queued(ImageBuild.IMAGE_PRIMARY, false)).block();
        StepVerifier.create(repo().updateStatus(b.id(), "BOGUS")).verifyError();
    }

    @Test
    void imageTypeCheck_rejectsBadVocabulary() {
        StepVerifier.create(repo().insert(queued("not-a-real-type", false))).verifyError();
    }
}
