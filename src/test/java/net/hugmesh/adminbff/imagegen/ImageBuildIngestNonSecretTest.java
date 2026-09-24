package net.hugmesh.adminbff.imagegen;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
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

import java.util.List;
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

    // Captures ImageBuildService's WARN lines so each refusal's EXACT reason is pinned.
    private ListAppender<ILoggingEvent> warnings;
    private ch.qos.logback.classic.Logger serviceLogger;

    @BeforeEach
    void captureWarnings() {
        LoggerContext ctx = (LoggerContext) LoggerFactory.getILoggerFactory();
        serviceLogger = ctx.getLogger(ImageBuildService.class);
        serviceLogger.setLevel(Level.INFO);
        warnings = new ListAppender<>();
        warnings.list = new java.util.concurrent.CopyOnWriteArrayList<>();
        warnings.start();
        serviceLogger.addAppender(warnings);
    }

    @AfterEach
    void releaseWarnings() {
        serviceLogger.detachAppender(warnings);
        warnings.stop();
    }

    /** The WARN lines that mention this build (other tests may share the logger). */
    private List<String> warnsFor(String buildId) {
        return warnings.list.stream()
                .filter(e -> e.getLevel() == Level.WARN)
                .map(ILoggingEvent::getFormattedMessage)
                .filter(m -> m.contains(buildId))
                .toList();
    }

    private ImageBuild queuedBuild(String domain) {
        ImageBuild queued = new ImageBuild(null, null, "admin@x", "alice", domain,
                ImageBuild.IMAGE_PRIMARY, "rpi5", null, ImageBuild.STATUS_QUEUED, true,
                null, null, null, null, null, null);
        return builds.insert(queued).block();
    }

    private void enroll(String deviceId, String domain) {
        db.sql("INSERT INTO device_registry "
                        + "(id, machine_key_fp, hostname, image_type, owner_type, physical_owner, "
                        + " domain, mesh_id, created_at) "
                        + "VALUES (:id, :fp, :host, 'primary', 'ADMIN', 'alice', :dom, 'mesh-1', now())")
                .bind("id", deviceId)
                .bind("fp", "machine-key-fp-" + deviceId)
                .bind("host", "host-" + deviceId)
                .bind("dom", domain)
                .fetch().rowsUpdated().block();
    }

    /**
     * A body shaped EXACTLY like the terminal report hugmesh-generator docker/build-image.sh
     * (send_ingest) emits for a COMPLETED build with a dial key mounted: deviceId, dialUser and
     * dialPubFp set; machineKeyFp/hostname unset; hostKeyPub/hostKeyFp null (the admitted
     * host-key follow-up) unless supplied; vaultRef as supplied — and NO k8sSecretName field (the
     * DTO no longer has one; a body that still sends it is covered in ImageBuildIngestRequestJsonTest).
     */
    private static ImageBuildIngestRequest realShaped(String buildId, String deviceId,
                                                      String hostKeyPub, String hostKeyFp,
                                                      String vaultRef) {
        return new ImageBuildIngestRequest(
                "COMPLETED",
                "build-" + buildId + "/image.img",
                "build-" + buildId + "/keys.tar",
                deviceId,
                null, null,
                "bff-dial",
                hostKeyPub, hostKeyFp,
                "SHA256:dialpubfp",
                vaultRef,
                "image build completed: platform=rpi5", null);
    }

    private Long dialRows(String deviceId) {
        return db.sql("SELECT count(*) AS c FROM device_ssh_dial WHERE device_id = :d")
                .bind("d", deviceId)
                .map((r, m) -> ((Number) r.get("c")).longValue()).first().block();
    }

    /**
     * Decisions 73a/73b/73c (hugmesh-admin-bff-api#53): a report for the device id the BFF MINTED
     * for this build, echoing the Vault path the BFF passed, seeds a row whose Secret name the BFF
     * DERIVED — {@code device-ssh-<deviceId>} — never one the body named. The host keys are supplied
     * here only to show the Done-when "once the other NOT NULL fields are present"; the real Job
     * does not send them yet (see the residual test below).
     *
     * <p>RED on origin/main 86cdf79: the real-shaped body carries no Secret name, so the insert
     * violates k8s_secret_name NOT NULL, is swallowed at WARN, and NO row exists.
     */
    @Test
    void ingestCompleted_realShapedBody_seedsRowWithDerivedSecretName() {
        ImageBuildService service = newService();
        ImageBuild persisted = queuedBuild("default");
        service.events(null, persisted.id());
        String deviceId = DeviceDialIdentity.mintDeviceId(persisted.id());
        // The device is already enrolled under the minted id (enrollment is its own flow).
        enroll(deviceId, "default");

        ImageBuildIngestRequest in = realShaped(persisted.id(), deviceId,
                "ssh-ed25519 AAAAhostpublic", "SHA256:hostfp",
                DeviceDialIdentity.vaultRefFor(deviceId));

        ImageBuild after = service.ingest(persisted.id(), in).block();
        assertThat(after.status()).isEqualTo(ImageBuild.STATUS_COMPLETED);
        assertThat(after.imageRef()).isEqualTo("build-" + persisted.id() + "/image.img");
        assertThat(after.keysRef()).isEqualTo("build-" + persisted.id() + "/keys.tar");

        DeviceSshDial dial = dials.findByDeviceId(deviceId).block();
        assertThat(dial).isNotNull();
        assertThat(deviceId).matches("dev-[a-z0-9]{12}");
        assertThat(dial.k8sSecretName()).isEqualTo("device-ssh-" + deviceId);
        assertThat(dial.vaultRef()).isEqualTo("hugmesh/device/" + deviceId + "/ssh");
        assertThat(dial.dialPubFp()).isEqualTo("SHA256:dialpubfp");
        assertThat(dial.seededByBuildId()).isEqualTo(persisted.id());
        assertThat(warnsFor(persisted.id())).isEmpty();

        // BELT-AND-BRACES: scan EVERY column of the seeded dial row for any value that looks like
        // a private key — there must be none anywhere in the persisted row.
        Map<String, Object> row = db.sql("SELECT * FROM device_ssh_dial WHERE device_id = :d")
                .bind("d", deviceId)
                .fetch().first().block();
        assertThat(row).isNotNull();
        for (Object v : row.values()) {
            if (v == null) continue;
            String str = v.toString();
            assertThat(str).doesNotContain("PRIVATE KEY");
            assertThat(str).doesNotContain("BEGIN OPENSSH PRIVATE");
        }
    }

    /**
     * 73 RESIDUAL: the body the real Job sends TODAY — host keys null (build-image.sh does not
     * generate device host keys; no decision covers them) — cannot seed a row, and the WARN names
     * the exact NOT NULL columns instead of a generic R2DBC error. Neither the constraint is relaxed
     * nor a host key invented. RED on origin/main: only a generic constraint-violation WARN.
     */
    @Test
    void ingestCompleted_realShapedBody_nullHostKeys_noRow_exactReason() {
        ImageBuildService service = newService();
        ImageBuild persisted = queuedBuild("default");
        service.events(null, persisted.id());
        String deviceId = DeviceDialIdentity.mintDeviceId(persisted.id());
        enroll(deviceId, "default");

        ImageBuild after = service.ingest(persisted.id(), realShaped(persisted.id(), deviceId,
                null, null, DeviceDialIdentity.vaultRefFor(deviceId))).block();

        // the terminal status still lands; only the dial seed is skipped.
        assertThat(after.status()).isEqualTo(ImageBuild.STATUS_COMPLETED);
        assertThat(dialRows(deviceId)).isZero();
        assertThat(warnsFor(persisted.id())).singleElement().satisfies(w -> assertThat(w)
                .contains("non-secret dial seed for build " + persisted.id() + " skipped")
                .contains("missing NOT NULL field(s) host_key_pub, host_key_fp for device " + deviceId)
                .doesNotContain("vault_ref"));
    }

    /** 73c = B: a report with NO vaultRef (today's build-image.sh) seeds nothing and says so. */
    @Test
    void ingestCompleted_noVaultRef_noRow_namesVaultRef() {
        ImageBuildService service = newService();
        ImageBuild persisted = queuedBuild("default");
        service.events(null, persisted.id());
        String deviceId = DeviceDialIdentity.mintDeviceId(persisted.id());
        enroll(deviceId, "default");

        service.ingest(persisted.id(), realShaped(persisted.id(), deviceId,
                "ssh-ed25519 AAAAhostpublic", "SHA256:hostfp", null)).block();

        assertThat(dialRows(deviceId)).isZero();
        assertThat(warnsFor(persisted.id())).singleElement().satisfies(w -> assertThat(w)
                .contains("missing NOT NULL field(s) vault_ref for device " + deviceId));
    }

    /**
     * 73c = B: the Job must report back the Vault path the BFF passed it. A different path — even a
     * plausible one — is never stored. RED on origin/main: the body's vaultRef was stored verbatim.
     */
    @Test
    void ingestCompleted_mismatchedVaultRef_noRow() {
        ImageBuildService service = newService();
        ImageBuild persisted = queuedBuild("default");
        service.events(null, persisted.id());
        String deviceId = DeviceDialIdentity.mintDeviceId(persisted.id());
        enroll(deviceId, "default");

        service.ingest(persisted.id(), realShaped(persisted.id(), deviceId,
                "ssh-ed25519 AAAAhostpublic", "SHA256:hostfp",
                "secret/default/device/" + deviceId + "/ssh/dial_private_key")).block();

        assertThat(dialRows(deviceId)).isZero();
        assertThat(warnsFor(persisted.id())).singleElement().satisfies(w -> assertThat(w)
                .contains("reported vaultRef 'secret/default/device/" + deviceId)
                .contains("is not the Vault path minted for device " + deviceId)
                .contains("hugmesh/device/" + deviceId + "/ssh"));
    }

    /**
     * 73b = B: the BFF is the source of the device id. A report naming a DIFFERENT (enrolled,
     * same-tenant) device — one the BFF did not mint for this build — seeds nothing. RED on
     * origin/main: the row was attached to whatever device the body named.
     */
    @Test
    void ingestCompleted_deviceIdNotMintedForBuild_noRow() {
        ImageBuildService service = newService();
        ImageBuild persisted = queuedBuild("default");
        service.events(null, persisted.id());
        String other = "dev-000000000000";
        enroll(other, "default");

        service.ingest(persisted.id(), realShaped(persisted.id(), other,
                "ssh-ed25519 AAAAhostpublic", "SHA256:hostfp",
                DeviceDialIdentity.vaultRefFor(other))).block();

        assertThat(dialRows(other)).isZero();
        assertThat(warnsFor(persisted.id())).singleElement().satisfies(w -> assertThat(w)
                .contains("reported deviceId '" + other + "' is not the device id minted for this"
                        + " build ('" + DeviceDialIdentity.mintDeviceId(persisted.id()) + "')"));
    }

    /** A report for the minted id of a device that is not enrolled yet seeds nothing, with a WARN
     *  (previously a silent skip) — the first thing a real build hits until enrollment uses it. */
    @Test
    void ingestCompleted_mintedDeviceNotEnrolled_noRow_warns() {
        ImageBuildService service = newService();
        ImageBuild persisted = queuedBuild("default");
        service.events(null, persisted.id());
        String deviceId = DeviceDialIdentity.mintDeviceId(persisted.id());

        ImageBuild after = service.ingest(persisted.id(), realShaped(persisted.id(), deviceId,
                "ssh-ed25519 AAAAhostpublic", "SHA256:hostfp",
                DeviceDialIdentity.vaultRefFor(deviceId))).block();

        assertThat(after.status()).isEqualTo(ImageBuild.STATUS_COMPLETED);
        assertThat(dialRows(deviceId)).isZero();
        assertThat(warnsFor(persisted.id())).singleElement().satisfies(w -> assertThat(w)
                .contains("reported device '" + deviceId + "' is not enrolled"));
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

        // the target device, however, is RESIDENT in brandy — a different tenant. It carries the
        // id the BFF minted for THIS build, so every other seed rule would pass: the tenant wall
        // alone must refuse it (and it must stay a 403, not be downgraded to a WARN skip).
        String victimDeviceId = DeviceDialIdentity.mintDeviceId(persisted.id());
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
                DeviceDialIdentity.vaultRefFor(victimDeviceId),
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
