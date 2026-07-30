package systems.hugmesh.adminbff.phone;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import reactor.core.publisher.Mono;
import systems.hugmesh.adminbff.support.TestDatabaseConfig;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * {@link PhoneDeviceRepository} over the real Liquibase-applied Postgres. What is ACTUALLY
 * proven here (every assertion reads the STORE, never an in-memory echo — upsert() itself
 * re-reads after both branches):
 * <ul>
 *   <li>the 302 changelog applies and a first ingest round-trips every column;</li>
 *   <li>a re-ingest refreshes EVERY refreshable column (each one is varied and asserted
 *       individually — a dropped SET column fails its own assertion), bumps ingest_count,
 *       preserves first_ingested_at and the row identity, and never duplicates;</li>
 *   <li>{@code uq_phone_device_device_id} really fires (double raw INSERT), and the
 *       device_class CHECK really rejects a non-phone row;</li>
 *   <li>the concurrent-first-ingest race folds the losing INSERT into the refresh branch
 *       (deterministic mock interleave) instead of surfacing the DuplicateKeyException.</li>
 * </ul>
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
@ActiveProfiles("test")
class PhoneDeviceRepositoryTest {

    @Autowired DatabaseClient db;

    @BeforeEach
    void clear() {
        db.sql("DELETE FROM phone_device").fetch().rowsUpdated().block();
    }

    private PhoneDeviceRowRepository rowRepo() {
        return systems.hugmesh.adminbff.testutil.R2dbcRepos
                .of(db, PhoneDeviceRowRepository.class);
    }

    private PhoneDeviceRepository repo() {
        return new PhoneDeviceRepository(rowRepo());
    }

    private static PhoneIngest full(String deviceId) {
        return new PhoneIngest(deviceId, "phone", "1C291FDF3005A", "oriole", "Pixel 6",
                "GrapheneOS", "2026071400", "hugmesh.internal",
                "https://headscale.hugmesh.internal", "100.64.0.7", "phone-1c291fdf3005a",
                "user", "acme.hugmesh.systems", true, 10L, "vault-seed",
                true, "com.hmdm.launcher", "https://headwind.hugmesh.internal",
                "adb-device-owner", Instant.parse("2026-07-14T11:58:00Z"),
                "https://attestation.hugmesh.systems", "systems.hugmesh.auditor",
                "operator-paired", Instant.parse("2026-07-14T12:00:00Z"),
                Instant.parse("2026-07-14T12:05:00Z"),
                // Device-reported provider (307): a Headwind device, no Intune id.
                "headwind", null);
    }

    /** Every refreshable column different from {@link #full} — the re-ingest fixture (incl. a
     *  provider FLIP to azure-intune so the REFRESH SET of both 307 columns is proven). */
    private static PhoneIngest fullChanged(String deviceId) {
        return new PhoneIngest(deviceId, "phone", "NEWSERIAL9999", "raven", "Pixel 6 Pro",
                "unknown", "2026081500", "other.internal",
                "https://hs2.other.internal", "100.64.9.9", "phone-renamed",
                "admin", "beta.hugmesh.systems", false, null, null,
                false, "com.other.dpc", "https://headwind2.other.internal",
                "qr-provisioning", Instant.parse("2026-08-15T00:58:00Z"),
                "https://attest2.example", "app.attestation.auditor",
                "failed", Instant.parse("2026-08-15T01:00:00Z"),
                Instant.parse("2026-08-15T01:05:00Z"),
                // Provider FLIP: headwind -> azure-intune (+ a Graph device id) so the REFRESH
                // updating BOTH 307 columns fails its own assertion if either is dropped.
                "azure-intune", "intune-dev-xyz");
    }

    /** A no-USB operator-attested record: every live-probed fact absent (null). */
    private static PhoneIngest minimal(String deviceId) {
        return new PhoneIngest(deviceId, "phone", null, "oriole", null, null, null, null,
                null, null, null, null, null, false, null, null, false, null, null, null,
                null, null, null, null, null, null, "headwind", null);
    }

    @Test
    void firstIngest_inserts_countOne_idGenerated_valuesRoundTrip() {
        repo().upsert(full("phone-a")).block();
        // Assert on a FRESH read — proves the stored row, not any returned echo.
        PhoneDevice d = repo().findByDeviceId("phone-a").block();
        assertThat(d).isNotNull();
        assertThat(d.id()).isNotBlank();                       // DB-generated (RETURNING id)
        assertThat(d.deviceId()).isEqualTo("phone-a");
        assertThat(d.deviceClass()).isEqualTo("phone");
        assertThat(d.serial()).isEqualTo("1C291FDF3005A");
        assertThat(d.codename()).isEqualTo("oriole");
        assertThat(d.marketingName()).isEqualTo("Pixel 6");
        assertThat(d.os()).isEqualTo("GrapheneOS");
        assertThat(d.osVersion()).isEqualTo("2026071400");
        assertThat(d.superdomain()).isEqualTo("hugmesh.internal");
        assertThat(d.loginServer()).isEqualTo("https://headscale.hugmesh.internal");
        assertThat(d.tailscaleIp()).isEqualTo("100.64.0.7");
        assertThat(d.tailscaleHostname()).isEqualTo("phone-1c291fdf3005a");
        assertThat(d.role()).isEqualTo("user");
        assertThat(d.attachedDomain()).isEqualTo("acme.hugmesh.systems");
        assertThat(d.enterpriseProfilePresent()).isTrue();
        assertThat(d.enterpriseProfileUserId()).isEqualTo(10L);
        assertThat(d.enterpriseProfileCredentialCustody()).isEqualTo("vault-seed");
        assertThat(d.mdmEnrolled()).isTrue();
        assertThat(d.mdmDpcPackage()).isEqualTo("com.hmdm.launcher");
        assertThat(d.mdmHeadwindUrl()).isEqualTo("https://headwind.hugmesh.internal");
        assertThat(d.mdmSetVia()).isEqualTo("adb-device-owner");
        assertThat(d.mdmEnrolledAt()).isEqualTo(Instant.parse("2026-07-14T11:58:00Z"));
        assertThat(d.attestationUrl()).isEqualTo("https://attestation.hugmesh.systems");
        assertThat(d.auditorPackage()).isEqualTo("systems.hugmesh.auditor");
        assertThat(d.attestationVerdict()).isEqualTo("operator-paired");
        assertThat(d.enrolledAt()).isEqualTo(Instant.parse("2026-07-14T12:00:00Z"));
        assertThat(d.generatedAt()).isEqualTo(Instant.parse("2026-07-14T12:05:00Z"));
        // 307 device-reported provider columns are in the INSERT list (unlike owner/lock).
        assertThat(d.mdmProvider()).isEqualTo("headwind");
        assertThat(d.intuneDeviceId()).isNull();
        assertThat(d.ingestCount()).isEqualTo(1L);
        assertThat(d.firstIngestedAt()).isNotNull();           // DB-clock default fired
        assertThat(d.lastIngestedAt()).isEqualTo(d.firstIngestedAt());
    }

    @Test
    void reIngest_refreshesEveryColumn_bumpsCount_preservesFirstIngestedAt_singleRow() {
        PhoneDeviceRepository repo = repo();
        repo.upsert(full("phone-b")).block();
        PhoneDevice first = repo.findByDeviceId("phone-b").block();

        repo.upsert(fullChanged("phone-b")).block();
        PhoneDevice again = repo.findByDeviceId("phone-b").block();
        assertThat(again).isNotNull();
        // EVERY refreshable column changed AND is asserted — dropping any single SET
        // column from the REFRESH SQL fails exactly one assertion below.
        assertThat(again.serial()).isEqualTo("NEWSERIAL9999");
        assertThat(again.codename()).isEqualTo("raven");
        assertThat(again.marketingName()).isEqualTo("Pixel 6 Pro");
        assertThat(again.os()).isEqualTo("unknown");
        assertThat(again.osVersion()).isEqualTo("2026081500");
        assertThat(again.superdomain()).isEqualTo("other.internal");
        assertThat(again.loginServer()).isEqualTo("https://hs2.other.internal");
        assertThat(again.tailscaleIp()).isEqualTo("100.64.9.9");
        assertThat(again.tailscaleHostname()).isEqualTo("phone-renamed");
        assertThat(again.role()).isEqualTo("admin");
        assertThat(again.attachedDomain()).isEqualTo("beta.hugmesh.systems");
        assertThat(again.enterpriseProfilePresent()).isFalse();
        assertThat(again.enterpriseProfileUserId()).isNull();
        assertThat(again.enterpriseProfileCredentialCustody()).isNull();
        assertThat(again.mdmEnrolled()).isFalse();
        assertThat(again.mdmDpcPackage()).isEqualTo("com.other.dpc");
        assertThat(again.mdmHeadwindUrl()).isEqualTo("https://headwind2.other.internal");
        assertThat(again.mdmSetVia()).isEqualTo("qr-provisioning");
        assertThat(again.mdmEnrolledAt()).isEqualTo(Instant.parse("2026-08-15T00:58:00Z"));
        assertThat(again.attestationUrl()).isEqualTo("https://attest2.example");
        assertThat(again.auditorPackage()).isEqualTo("app.attestation.auditor");
        assertThat(again.attestationVerdict()).isEqualTo("failed");
        assertThat(again.enrolledAt()).isEqualTo(Instant.parse("2026-08-15T01:00:00Z"));
        assertThat(again.generatedAt()).isEqualTo(Instant.parse("2026-08-15T01:05:00Z"));
        // The 307 provider columns are in the REFRESH SET (device-reported telemetry) — the
        // re-ingest flipped headwind -> azure-intune and set the Graph device id.
        assertThat(again.mdmProvider()).isEqualTo("azure-intune");
        assertThat(again.intuneDeviceId()).isEqualTo("intune-dev-xyz");
        // Identity + history semantics.
        assertThat(again.ingestCount()).isEqualTo(2L);
        assertThat(again.firstIngestedAt()).isEqualTo(first.firstIngestedAt());
        assertThat(again.lastIngestedAt()).isAfterOrEqualTo(first.lastIngestedAt());
        assertThat(again.id()).isEqualTo(first.id());
        Long count = db.sql("SELECT COUNT(*) AS c FROM phone_device WHERE device_id = 'phone-b'")
                .map((r, m) -> r.get("c", Long.class)).first().block();
        assertThat(count).isEqualTo(1L);   // ONE row despite two ingests.
    }

    @Test
    void minimalNoUsbRecord_allOptionalFactsNull_ok() {
        repo().upsert(minimal("phone-c")).block();
        PhoneDevice d = repo().findByDeviceId("phone-c").block();
        assertThat(d).isNotNull();
        assertThat(d.serial()).isNull();
        assertThat(d.tailscaleIp()).isNull();
        assertThat(d.enterpriseProfilePresent()).isFalse();
        assertThat(d.enterpriseProfileUserId()).isNull();
        assertThat(d.mdmEnrolled()).isFalse();
        assertThat(d.mdmDpcPackage()).isNull();
        assertThat(d.mdmEnrolledAt()).isNull();
        assertThat(d.enrolledAt()).isNull();
        assertThat(d.ingestCount()).isEqualTo(1L);
    }

    @Test
    void listAll_newestIngestActivityFirst() {
        PhoneDeviceRepository repo = repo();
        repo.upsert(full("phone-old")).block();
        repo.upsert(minimal("phone-new")).block();
        // Re-ingesting the OLD phone bumps its last_ingested_at past the new one's.
        repo.upsert(full("phone-old")).block();
        List<PhoneDevice> fleet = repo.listAll().collectList().block();
        assertThat(fleet).extracting(PhoneDevice::deviceId)
                .containsExactly("phone-old", "phone-new");
    }

    @Test
    void uniqueDeviceId_reallyFires_onDoubleRawInsert() {
        PhoneDeviceRowRepository rows = rowRepo();
        PhoneIngest r = full("phone-dup");
        Mono<String> raw = rows.insertReturningId(r.deviceId(), r.deviceClass(), r.serial(),
                r.codename(), r.marketingName(), r.os(), r.osVersion(), r.superdomain(),
                r.loginServer(), r.tailscaleIp(), r.tailscaleHostname(), r.role(),
                r.attachedDomain(), r.enterpriseProfilePresent(), r.enterpriseProfileUserId(),
                r.enterpriseProfileCredentialCustody(), r.mdmEnrolled(), r.mdmDpcPackage(),
                r.mdmHeadwindUrl(), r.mdmSetVia(), r.mdmEnrolledAt(), r.attestationUrl(),
                r.auditorPackage(), r.attestationVerdict(), r.enrolledAt(), r.generatedAt(),
                r.mdmProvider(), r.intuneDeviceId());
        raw.block();
        assertThatThrownBy(raw::block)
                .isInstanceOf(DuplicateKeyException.class);    // uq_phone_device_device_id
    }

    @Test
    void deviceClassCheck_reallyRejects_nonPhoneRow() {
        PhoneIngest r = full("node-imposter");
        assertThatThrownBy(() -> rowRepo().insertReturningId(r.deviceId(), "node",
                r.serial(), r.codename(), r.marketingName(), r.os(), r.osVersion(),
                r.superdomain(), r.loginServer(), r.tailscaleIp(), r.tailscaleHostname(),
                r.role(), r.attachedDomain(), r.enterpriseProfilePresent(),
                r.enterpriseProfileUserId(), r.enterpriseProfileCredentialCustody(),
                r.mdmEnrolled(), r.mdmDpcPackage(), r.mdmHeadwindUrl(), r.mdmSetVia(),
                r.mdmEnrolledAt(), r.attestationUrl(), r.auditorPackage(),
                r.attestationVerdict(), r.enrolledAt(), r.generatedAt(),
                r.mdmProvider(), r.intuneDeviceId()).block())
                .isInstanceOf(DataIntegrityViolationException.class);   // ck_phone_device_class
    }

    /**
     * The concurrent-first-ingest race, deterministically: both callers observe an empty
     * find, the loser's INSERT hits the UNIQUE — the facade must fold that into the
     * refresh branch, not surface the DuplicateKeyException (the wizard's curl does not
     * retry). Mock interleave: find #1 empty (raced read), insert -> DuplicateKeyException,
     * refresh succeeds, find #2 returns the winner's row.
     */
    @Test
    void concurrentFirstIngest_loser_foldsIntoRefresh_insteadOf500() {
        PhoneDeviceRowRepository rows = mock(PhoneDeviceRowRepository.class);
        PhoneIngest r = minimal("phone-race");
        PhoneDeviceRow winner = new PhoneDeviceRow("pd-w", "phone-race", "phone", null,
                "oriole", null, null, null, null, null, null, null, null, null, false,
                null, null, false, null, null, null, null, null, null, null, null, null,
                Instant.now(), Instant.now(), 2L,
                "unmanaged", "unlocked", null, 0L, null, null, null, null, null, "headwind", null);
        when(rows.findByDeviceId("phone-race"))
                .thenReturn(Mono.empty())                       // raced read: not there yet
                .thenReturn(Mono.just(winner));                 // post-refresh re-read
        when(rows.insertReturningId(any(), any(), any(), any(), any(), any(), any(), any(),
                any(), any(), any(), any(), any(), org.mockito.ArgumentMatchers.anyBoolean(),
                any(), any(), org.mockito.ArgumentMatchers.anyBoolean(), any(), any(),
                any(), any(), any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(Mono.error(new DuplicateKeyException("uq_phone_device_device_id")));
        when(rows.refresh(any(), any(), any(), any(), any(), any(), any(), any(), any(),
                any(), any(), any(), any(), org.mockito.ArgumentMatchers.anyBoolean(),
                any(), any(), org.mockito.ArgumentMatchers.anyBoolean(), any(), any(),
                any(), any(), any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(Mono.just(1L));

        PhoneDevice out = new PhoneDeviceRepository(rows).upsert(r).block();
        assertThat(out).isNotNull();
        assertThat(out.deviceId()).isEqualTo("phone-race");
        assertThat(out.ingestCount()).isEqualTo(2L);            // the winner's row came back
    }
}
