package systems.hugmesh.adminbff.phone;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import systems.hugmesh.adminbff.support.TestDatabaseConfig;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The changeset-305 owner+domain tenancy wall at the DB level (every assertion reads the STORE) —
 * the SOLE boundary between two fleet owners on the public {@code /bff/admin/phone-fleet/**}
 * surface. Seeds four devices: {@code (alice, acme)}, {@code (alice, beta)}, {@code (bob, acme)},
 * and a NULL-owner device, then proves:
 * <ul>
 *   <li>{@code listOwned}/{@code findByDeviceIdOwned} return ONLY rows matching BOTH
 *       {@code physical_owner} AND {@code owner_domain} — a matching owner in the WRONG domain, a
 *       matching domain with the WRONG owner, and the NULL-owner row are all invisible;</li>
 *   <li>{@code lockManagedOwned}/{@code unlockOwned} match 0 rows (empty Mono) for a cross-owner,
 *       cross-domain, or unmanaged target, and exactly one for the right owner+domain+mesh_owned;</li>
 *   <li><b>TRUST BOUNDARY:</b> the ingest INSERT + REFRESH column lists OMIT the owner columns
 *       (static assertion), and a re-ingest leaves {@code physical_owner}/{@code owner_domain}
 *       exactly as the owner-assignment set them (or NULL) while refreshing telemetry.</li>
 * </ul>
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
@ActiveProfiles("test")
class PhoneFleetOwnerRepositoryTest {

    private static final String ALICE = "alice-subject";
    private static final String BOB = "bob-subject";
    private static final String ACME = "acme.hugmesh.systems";
    private static final String BETA = "beta.hugmesh.systems";

    @Autowired DatabaseClient db;

    @BeforeEach
    void clear() {
        db.sql("DELETE FROM phone_device").fetch().rowsUpdated().block();
    }

    private PhoneDeviceRepository repo() {
        return new PhoneDeviceRepository(systems.hugmesh.adminbff.testutil.R2dbcRepos
                .of(db, PhoneDeviceRowRepository.class));
    }

    private static PhoneIngest ingest(String deviceId) {
        return new PhoneIngest(deviceId, "phone", "SER-" + deviceId, "oriole", "Pixel 6",
                "GrapheneOS", "2026071400", "hugmesh.internal", "https://hs.internal",
                "100.64.0.7", "phone-host", "user", "acme.hugmesh.systems", true, 10L,
                "vault-seed", true, "com.hmdm.launcher", "https://headwind.internal",
                "adb-device-owner", Instant.parse("2026-07-14T11:58:00Z"),
                "https://attest", "auditor", "operator-paired",
                Instant.parse("2026-07-14T12:00:00Z"), Instant.parse("2026-07-14T12:05:00Z"),
                "headwind", null);
    }

    /** A telemetry-changed re-ingest of the SAME device_id (serial/os differ). */
    private static PhoneIngest reIngest(String deviceId) {
        return new PhoneIngest(deviceId, "phone", "NEWSERIAL", "raven", "Pixel 6 Pro",
                "unknown", "2026081500", "other.internal", "https://hs2.internal",
                "100.64.9.9", "phone-renamed", "admin", "beta.hugmesh.systems",
                false, null, null, false, null, null, null, null, null, null, null, null, null,
                "headwind", null);
    }

    /** Seed the four-device fixture and assign owners on three of them (NULL owner on the 4th). */
    private PhoneDeviceRepository seedFixture() {
        PhoneDeviceRepository repo = repo();
        for (String d : new String[]{"dev-1", "dev-2", "dev-3", "dev-4"}) {
            repo.upsert(ingest(d)).block();
        }
        // Owner assignment is the SUPERADMIN plane (setOwner); the 4th stays NULL-owner.
        assertThat(repo.setOwner("dev-1", ALICE, ACME).block()).isNotNull();
        assertThat(repo.setOwner("dev-2", ALICE, BETA).block()).isNotNull();
        assertThat(repo.setOwner("dev-3", BOB, ACME).block()).isNotNull();
        return repo;
    }

    @Test
    void freshIngest_ownerColumnsDefaultNull() {
        PhoneDeviceRepository repo = repo();
        repo.upsert(ingest("dev-x")).block();
        PhoneDevice d = repo.findByDeviceId("dev-x").block();
        assertThat(d).isNotNull();
        assertThat(d.physicalOwner()).isNull();
        assertThat(d.ownerDomain()).isNull();
    }

    // ── listOwned: BOTH predicates, NULL-owner invisible ─────────────────────────────
    @Test
    void listOwned_returnsOnlyRowsMatchingBothOwnerAndDomain() {
        PhoneDeviceRepository repo = seedFixture();

        var aliceAcme = repo.listOwned(ALICE, ACME).collectList().block();
        assertThat(aliceAcme).hasSize(1);
        assertThat(aliceAcme.get(0).deviceId()).isEqualTo("dev-1");
        assertThat(aliceAcme.get(0).physicalOwner()).isEqualTo(ALICE);
        assertThat(aliceAcme.get(0).ownerDomain()).isEqualTo(ACME);

        // Same owner, other domain -> its own row only (dev-2), never dev-1.
        assertThat(repo.listOwned(ALICE, BETA).map(PhoneDevice::deviceId).collectList().block())
                .containsExactly("dev-2");
        // Other owner, same domain -> its own row only (dev-3), never dev-1.
        assertThat(repo.listOwned(BOB, ACME).map(PhoneDevice::deviceId).collectList().block())
                .containsExactly("dev-3");

        // A scope no one owns -> empty (cross-owner AND cross-domain).
        assertThat(repo.listOwned(BOB, BETA).collectList().block()).isEmpty();
        // The NULL-owner device is invisible to EVERY owner+domain scope.
        assertThat(repo.listOwned(ALICE, ACME).map(PhoneDevice::deviceId).collectList().block())
                .doesNotContain("dev-4");
    }

    // ── findByDeviceIdOwned: 404-source for cross-owner / cross-domain / NULL ─────────
    @Test
    void findByDeviceIdOwned_emptyForCrossOwnerCrossDomainAndNull() {
        PhoneDeviceRepository repo = seedFixture();

        assertThat(repo.findByDeviceIdOwned("dev-1", ALICE, ACME).block()).isNotNull();   // owned
        assertThat(repo.findByDeviceIdOwned("dev-1", BOB, ACME).block()).isNull();        // wrong owner
        assertThat(repo.findByDeviceIdOwned("dev-1", ALICE, BETA).block()).isNull();      // wrong domain
        assertThat(repo.findByDeviceIdOwned("dev-2", ALICE, ACME).block()).isNull();      // dev-2 is BETA
        assertThat(repo.findByDeviceIdOwned("dev-4", ALICE, ACME).block()).isNull();      // NULL owner
        assertThat(repo.findByDeviceIdOwned("nope", ALICE, ACME).block()).isNull();       // unknown
    }

    // ── owner-scoped lock CAS: matches 0 rows off-scope, exactly 1 on-scope ───────────
    @Test
    void lockManagedOwned_matchesOnlyOwnerDomainManagedTarget() {
        PhoneDeviceRepository repo = seedFixture();
        repo.setManagementMode("dev-1", "mesh_owned").block();   // dev-1 owned by (alice, acme)

        // Cross-owner / cross-domain locks match NO row and leave state untouched.
        assertThat(repo.lockManagedOwned("dev-1", "x", "attacker", BOB, ACME).block()).isNull();
        assertThat(repo.lockManagedOwned("dev-1", "x", "attacker", ALICE, BETA).block()).isNull();
        PhoneDevice stillUnlocked = repo.findByDeviceId("dev-1").block();
        assertThat(stillUnlocked.lockState()).isEqualTo("unlocked");
        assertThat(stillUnlocked.lockGeneration()).isEqualTo(0L);

        // The right owner+domain+mesh_owned locks — emits the bumped generation.
        assertThat(repo.lockManagedOwned("dev-1", "stolen", "alice-op", ALICE, ACME).block())
                .isEqualTo(1L);
        PhoneDevice locked = repo.findByDeviceId("dev-1").block();
        assertThat(locked.lockState()).isEqualTo("locked");
        assertThat(locked.lockReason()).isEqualTo("stolen");
        assertThat(locked.lockActor()).isEqualTo("alice-op");
    }

    @Test
    void lockManagedOwned_ownedButUnmanaged_matchesNoRow() {
        PhoneDeviceRepository repo = seedFixture();
        // dev-3 is owned by (bob, acme) but UNMANAGED (BYOD) — the mesh_owned CAS guard rejects it.
        assertThat(repo.lockManagedOwned("dev-3", "x", "bob-op", BOB, ACME).block()).isNull();
        assertThat(repo.findByDeviceId("dev-3").block().lockState()).isEqualTo("unlocked");
    }

    @Test
    void unlockOwned_matchesOnlyOwnerDomain() {
        PhoneDeviceRepository repo = seedFixture();
        repo.setManagementMode("dev-1", "mesh_owned").block();
        repo.lockManagedOwned("dev-1", "stolen", "alice-op", ALICE, ACME).block();   // gen 1, locked

        // Cross-owner / cross-domain unlock matches NO row.
        assertThat(repo.unlockOwned("dev-1", "attacker", BOB, ACME).block()).isNull();
        assertThat(repo.unlockOwned("dev-1", "attacker", ALICE, BETA).block()).isNull();
        assertThat(repo.findByDeviceId("dev-1").block().lockState()).isEqualTo("locked");   // untouched

        // The owner+domain unlock lands — monotonic generation 2.
        assertThat(repo.unlockOwned("dev-1", "alice-op", ALICE, ACME).block()).isEqualTo(2L);
        assertThat(repo.findByDeviceId("dev-1").block().lockState()).isEqualTo("unlocked");
    }

    // ── TRUST BOUNDARY: ingest can NEVER write the owner columns ──────────────────────
    @Test
    void ingestColumnLists_omitTheOwnerColumns() {
        // Static guard: neither the first-ingest INSERT nor the re-ingest REFRESH may reference
        // physical_owner / owner_domain — a spoofable ingest must never touch the tenancy wall.
        assertThat(PhoneDeviceRowRepository.INSERT_RETURNING_ID)
                .doesNotContain("physical_owner").doesNotContain("owner_domain");
        assertThat(PhoneDeviceRowRepository.REFRESH)
                .doesNotContain("physical_owner").doesNotContain("owner_domain");
    }

    @Test
    void reIngest_preservesOwnerColumns_refreshesTelemetry() {
        PhoneDeviceRepository repo = seedFixture();

        // A spoofable re-ingest of an OWNED device: telemetry refreshes, owner is UNTOUCHED.
        repo.upsert(reIngest("dev-1")).block();
        PhoneDevice d = repo.findByDeviceId("dev-1").block();
        assertThat(d.physicalOwner()).isEqualTo(ALICE);    // owner preserved
        assertThat(d.ownerDomain()).isEqualTo(ACME);       // domain preserved
        assertThat(d.serial()).isEqualTo("NEWSERIAL");     // telemetry refreshed
        assertThat(d.os()).isEqualTo("unknown");
        assertThat(d.ingestCount()).isEqualTo(2L);

        // And a re-ingest of the NULL-owner device never conjures an owner.
        repo.upsert(reIngest("dev-4")).block();
        PhoneDevice n = repo.findByDeviceId("dev-4").block();
        assertThat(n.physicalOwner()).isNull();
        assertThat(n.ownerDomain()).isNull();
    }
}
