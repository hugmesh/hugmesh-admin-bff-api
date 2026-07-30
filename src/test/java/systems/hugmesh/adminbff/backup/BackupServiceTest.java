package systems.hugmesh.adminbff.backup;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import systems.hugmesh.adminbff.support.TestDatabaseConfig;
import systems.hugmesh.commons.security.PrincipalDomain;
import systems.hugmesh.commons.web.ApiException;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Service-layer rules over the real H2-backed repository + real crypto + the
 * orchestrator (whose k8s-apply is a no-op seam): start-backup persists a QUEUED
 * row and returns its id; an encrypted backup stores a verifier (never the
 * password) and the right password later restores while a WRONG password is a 403
 * that never reveals the key; a USB target with an unknown device id is a 404; an
 * unknown scope is a 400. Tenant scope is SUPERADMIN here (the per-brand isolation
 * is covered in {@link BackupRepositoryTest}).
 */
@DataR2dbcTest
@Import({TestDatabaseConfig.class, BackupRepository.class, BackupCrypto.class,
        BackupOrchestrator.class, BackupServiceTest.Beans.class})
class BackupServiceTest {

    /** Unscoped (SUPERADMIN) tenant scope for the non-isolation service rules. */
    private static final PrincipalDomain SUPER = PrincipalDomain.superadminFor("default");

    @Autowired BackupService service;
    @Autowired BackupRepository repo;

    static class Beans {
        /** A USB provider with exactly one writable + one read-only device. */
        @Bean
        UsbDeviceProvider usbDeviceProvider() {
            UsbDevice ok = new UsbDevice("usb-1", "BACKUP", "/mnt/usb", 64_000_000_000L,
                    32_000_000_000L, true, List.of());
            UsbDevice ro = new UsbDevice("usb-ro", "READONLY", "/mnt/usb-ro", 1L, 1L, false, List.of());
            return new UsbDeviceProvider() {
                @Override public Mono<List<UsbDevice>> list() { return Mono.just(List.of(ok, ro)); }
            };
        }

        @Bean
        BackupService backupService(BackupRepository repo, BackupCrypto crypto,
                                    BackupOrchestrator orch, UsbDeviceProvider usb) {
            return new BackupService(repo, crypto, orch, usb);
        }
    }

    @Test
    void startBackup_clusterUnencrypted_persistsQueuedRow() {
        String id = service.startBackup("admin@x", List.of("etcd", "postgres"),
                "cluster", null, false, null, SUPER).block();
        assertThat(id).isNotBlank();
        BackupRecord rec = repo.find(id, SUPER).block();
        assertThat(rec.scope()).isEqualTo("etcd,postgres");
        assertThat(rec.target()).isEqualTo("CLUSTER");
        assertThat(rec.encrypted()).isFalse();
        assertThat(rec.verifier()).isNull();
    }

    @Test
    void startBackup_encrypted_storesVerifierNotPassword_andRestoreVerifiesPassword() {
        String id = service.startBackup("admin@x", List.of("secrets"),
                "CLUSTER", null, true, "super-secret-pw", SUPER).block();
        BackupRecord rec = repo.find(id, SUPER).block();
        assertThat(rec.encrypted()).isTrue();
        assertThat(rec.verifier()).isNotBlank();
        // The stored verifier is NOT the password.
        assertThat(rec.verifier()).doesNotContain("super-secret-pw");

        // Right password → restore proceeds (returns a restore job id).
        String restoreId = service.startRestore(id, null, "super-secret-pw", SUPER).block();
        assertThat(restoreId).isNotBlank();
    }

    @Test
    void startRestore_wrongPassword_is403_andNeverRevealsKey() {
        String id = service.startBackup("admin@x", List.of("secrets"),
                "CLUSTER", null, true, "the-right-pw", SUPER).block();

        StepVerifier.create(service.startRestore(id, null, "the-WRONG-pw", SUPER))
                .expectErrorSatisfies(e -> {
                    assertThat(e).isInstanceOf(ApiException.class);
                    assertThat(((ApiException) e).status()).isEqualTo(HttpStatus.FORBIDDEN);
                    assertThat(e.getMessage()).isEqualTo("incorrect decryption password");
                })
                .verify();
    }

    @Test
    void startBackup_usbTargetUnknownDevice_is404() {
        StepVerifier.create(service.startBackup("admin@x", List.of("config"),
                        "USB", "no-such-usb", false, null, SUPER))
                .expectErrorSatisfies(e -> {
                    assertThat(e).isInstanceOf(ApiException.class);
                    assertThat(((ApiException) e).status()).isEqualTo(HttpStatus.NOT_FOUND);
                })
                .verify();
    }

    @Test
    void startBackup_usbTargetReadOnlyDevice_is422() {
        StepVerifier.create(service.startBackup("admin@x", List.of("config"),
                        "USB", "usb-ro", false, null, SUPER))
                .expectErrorSatisfies(e ->
                        assertThat(((ApiException) e).status()).isEqualTo(HttpStatus.UNPROCESSABLE_CONTENT))
                .verify();
    }

    @Test
    void startBackup_usbTargetWritableDevice_succeeds() {
        String id = service.startBackup("admin@x", List.of("config"),
                "USB", "usb-1", false, null, SUPER).block();
        assertThat(repo.find(id, SUPER).block().target()).isEqualTo("USB");
    }

    @Test
    void startBackup_unknownScope_is400() {
        StepVerifier.create(service.startBackup("admin@x", List.of("nope"),
                        "CLUSTER", null, false, null, SUPER))
                .expectErrorSatisfies(e ->
                        assertThat(((ApiException) e).status()).isEqualTo(HttpStatus.BAD_REQUEST))
                .verify();
    }

    @Test
    void startBackup_encryptWithoutPassword_is400() {
        StepVerifier.create(service.startBackup("admin@x", List.of("etcd"),
                        "CLUSTER", null, true, null, SUPER))
                .expectErrorSatisfies(e ->
                        assertThat(((ApiException) e).status()).isEqualTo(HttpStatus.BAD_REQUEST))
                .verify();
    }
}
