package net.hugmesh.adminbff.imagegen;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import net.hugmesh.adminbff.device.DeviceRegistryRepository;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.adminbff.sshterminal.DeviceSshDial;
import net.hugmesh.adminbff.sshterminal.DeviceSshDialRepository;
import net.hugmesh.adminbff.sshterminal.ImageBuild;
import net.hugmesh.adminbff.sshterminal.ImageBuildRepository;
import net.hugmesh.adminbff.support.TestDatabaseConfig;
import net.hugmesh.adminbff.web.dto.ImageBuildIngestRequest;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

/**
 * The IN-CLUSTER ingest path against the REAL H2 schema (so the durable image_build /
 * device_ssh_dial writes are genuinely exercised). Verifies the NO-SECRET contract end-to-end:
 * <ul>
 *   <li>a COMPLETED ingest closes the build, records the NON-SECRET artifact pointers, and seeds
 *       the device_ssh_dial row with the reported public material (against a pre-enrolled
 *       device_registry row — enrollment is its own flow);</li>
 *   <li>the device_ssh_dial row stores ONLY non-secret columns (public host key, dial-pub
 *       fingerprint, Vault POINTER) — there is no column, and no path, for a private key;</li>
 *   <li>even though the request DTO has no private-key field, a hostile caller that smuggles a
 *       {@code privateKey} JSON property is silently ignored (the typed body drops it) and no
 *       secret bytes land in any row.</li>
 * </ul>
 */
@DataR2dbcTest
@Import({TestDatabaseConfig.class, ImageBuildRepository.class, DeviceSshDialRepository.class,
        DeviceRegistryRepository.class})
class ImageBuildIngestNonSecretTest {

    @Autowired ImageBuildRepository builds;
    @Autowired DeviceSshDialRepository dials;
    @Autowired DeviceRegistryRepository devices;
    @Autowired DatabaseClient db;

    private ImageBuildService newService() {
        // a real orchestrator wired to a no-op launcher so its DB-status write runs against H2;
        // the artifact store + step-up gate are not on the ingest path.
        ImageBuildOrchestrator orch = new ImageBuildOrchestrator(builds, new NoopImageJobLauncher(), 16);
        DomainRegistry reg = new DomainRegistry("https://idp.example", "");
        return new ImageBuildService(builds, dials, devices, orch, /*artifacts*/ null,
                /*stepUp*/ null, /*mfaStepUp*/ null, reg,
                new WorklistEnvelopeValidator(), new ImageGenConfig());
    }

    @Test
    void ingestCompleted_seedsNonSecretRows_andIgnoresAnyPrivateKey() {
        ImageBuildService service = newService();

        // a queued build to close out.
        ImageBuild queued = new ImageBuild(null, null, "admin@x", "alice", "default",
                ImageBuild.IMAGE_PRIMARY, "rpi5", null, ImageBuild.STATUS_QUEUED, true,
                null, null, null, null, null, null);
        ImageBuild persisted = builds.insert(queued).block();
        // touch the SSE stream (no-op sink read; ingest's emit is null-safe). events() is now
        // tenant-scoped (auth, id) — auth is irrelevant here since the result is not subscribed.
        service.events(null, persisted.id());

        // The device is already enrolled (headscale enrollment is a separate flow); the build
        // ingest only ATTACHES the dial pointer to it. Seed the device_registry row so the
        // device_ssh_dial FK is satisfied.
        db.sql("INSERT INTO device_registry "
                        + "(id, machine_key_fp, hostname, image_type, owner_type, physical_owner, "
                        + " domain, mesh_id, created_at) "
                        + "VALUES (:id, :fp, :host, 'primary', 'ADMIN', 'alice', 'default', 'mesh-1', now())")
                .bind("id", "11111111-1111-1111-1111-111111111111")
                .bind("fp", "machine-key-fp-abc")
                .bind("host", "alice-rpi5")
                .fetch().rowsUpdated().block();

        // the in-cluster Job reports completion + the seeded NON-SECRET device/dial material.
        ImageBuildIngestRequest in = new ImageBuildIngestRequest(
                "COMPLETED",
                "build-" + persisted.id() + "/image.img",
                "build-" + persisted.id() + "/keys.tar.gz",
                "11111111-1111-1111-1111-111111111111",   // deviceId
                "machine-key-fp-abc",                       // machineKeyFp (public)
                "alice-rpi5",                               // hostname
                "snapadmin",                                // dialUser
                "ssh-ed25519 AAAAhostpublic",               // hostKeyPub (public)
                "SHA256:hostfp",                            // hostKeyFp (public)
                "SHA256:dialpubfp",                         // dialPubFp (public)
                "vault://hugmesh/dial/alice-rpi5",       // vaultRef (POINTER, not bytes)
                "image-gen-dial-" + persisted.id(),         // k8sSecretName (pointer)
                "all green", null);

        ImageBuild after = service.ingest(persisted.id(), in).block();
        assertThat(after.status()).isEqualTo(ImageBuild.STATUS_COMPLETED);
        assertThat(after.imageRef()).isEqualTo("build-" + persisted.id() + "/image.img");
        assertThat(after.keysRef()).isEqualTo("build-" + persisted.id() + "/keys.tar.gz");

        // the device_ssh_dial row stores ONLY non-secret material — pointer + fingerprints.
        DeviceSshDial dial = dials.findByDeviceId("11111111-1111-1111-1111-111111111111").block();
        assertThat(dial).isNotNull();
        assertThat(dial.dialPubFp()).isEqualTo("SHA256:dialpubfp");
        assertThat(dial.vaultRef()).isEqualTo("vault://hugmesh/dial/alice-rpi5");
        assertThat(dial.seededByBuildId()).isEqualTo(persisted.id());

        // BELT-AND-BRACES: scan EVERY column of the seeded dial row for any value that looks like
        // a private key — there must be none anywhere in the persisted row.
        Map<String, Object> row = db.sql("SELECT * FROM device_ssh_dial WHERE device_id = :d")
                .bind("d", "11111111-1111-1111-1111-111111111111")
                .fetch().first().block();
        assertThat(row).isNotNull();
        for (Object v : row.values()) {
            if (v == null) continue;
            String s = v.toString();
            assertThat(s).doesNotContain("PRIVATE KEY");
            assertThat(s).doesNotContain("BEGIN OPENSSH PRIVATE");
        }
    }

    /**
     * FAIL-CLOSED TENANT CROSS-CHECK (defence-in-depth). A forged/confused ingest that named a
     * COMPLETED build in domain {@code brandx} but a target {@code deviceId} that is RESIDENT in a
     * DIFFERENT domain ({@code brandy}) must be REFUSED before it can attach a (non-secret) dial
     * pointer to the other tenant's device row. The build's domain is the server-derived value on
     * the image_build row (never a client field); it MUST equal the device's registry residency.
     *
     * <p>FAIL-FIRST: against the un-hardened service (no cross-check) this ingest would have
     * proceeded and written a device_ssh_dial row for the brandy device. The assertion makes it
     * REJECT and write NO device_ssh_dial row.
     */
    @Test
    void ingestCompleted_crossTenantDevice_rejected_andSeedsNoDialRow() {
        ImageBuildService service = newService();

        // a queued build stamped (server-derived) into brandx.
        ImageBuild queued = new ImageBuild(null, null, "admin@brandx", "brandx/alice", "brandx",
                ImageBuild.IMAGE_PRIMARY, "rpi5", null, ImageBuild.STATUS_QUEUED, true,
                null, null, null, null, null, null);
        ImageBuild persisted = builds.insert(queued).block();
        service.events(null, persisted.id());

        // the target device, however, is RESIDENT in brandy — a different tenant.
        String victimDeviceId = "22222222-2222-2222-2222-222222222222";
        db.sql("INSERT INTO device_registry "
                        + "(id, machine_key_fp, hostname, image_type, owner_type, physical_owner, "
                        + " domain, mesh_id, created_at) "
                        + "VALUES (:id, :fp, :host, 'primary', 'ADMIN', 'bob', 'brandy', 'mesh-y', now())")
                .bind("id", victimDeviceId)
                .bind("fp", "machine-key-fp-brandy")
                .bind("host", "bob-rpi5")
                .fetch().rowsUpdated().block();

        ImageBuildIngestRequest in = new ImageBuildIngestRequest(
                "COMPLETED",
                "build-" + persisted.id() + "/image.img",
                "build-" + persisted.id() + "/keys.tar.gz",
                victimDeviceId,                              // deviceId in ANOTHER tenant
                "machine-key-fp-brandy",
                "bob-rpi5",
                "snapadmin",
                "ssh-ed25519 AAAAhostpublic",
                "SHA256:hostfp",
                "SHA256:dialpubfp",
                "vault://hugmesh/dial/bob-rpi5",
                "image-gen-dial-" + persisted.id(),
                "all green", null);

        // fail closed: the ingest is REFUSED (a generic non-leaky 403), not silently seeded.
        Throwable err = catchThrowable(() -> service.ingest(persisted.id(), in).block());
        assertThat(err).isInstanceOf(net.hugmesh.commons.web.ApiException.class);
        assertThat(((net.hugmesh.commons.web.ApiException) err).status().value()).isEqualTo(403);

        // and NO device_ssh_dial row was written for the cross-tenant device.
        DeviceSshDial dial = dials.findByDeviceId(victimDeviceId).block();
        assertThat(dial).isNull();
        Long dialRows = db.sql("SELECT count(*) AS c FROM device_ssh_dial WHERE device_id = :d")
                .bind("d", victimDeviceId)
                .map((r, m) -> ((Number) r.get("c")).longValue()).first().block();
        assertThat(dialRows).isZero();
    }
}
