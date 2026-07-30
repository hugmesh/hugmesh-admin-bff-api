package systems.hugmesh.adminbff.sshterminal;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import systems.hugmesh.commons.security.PrincipalDomain;

import java.time.Instant;

/**
 * Reactive (R2DBC) store for {@code device_ssh_dial} — the per-device dial-key registry
 * pointer (schema in Liquibase {@code db/changelog/170-device-ssh-keys.xml}).
 *
 * <p>Backed by the Spring Data {@link DeviceSshDialR2dbcRepository} (no raw
 * {@code DatabaseClient}); maps the {@link DeviceSshDialRow} entity to/from the
 * {@link DeviceSshDial} domain record.
 *
 * <p>WIRED AT RUNTIME: the host-key-pinned {@code SshjDeviceSshChannelFactory} READS the ACTIVE
 * row (terminal + remote-install dial), and the SUPERADMIN {@code DesktopDialService} drives the
 * {@code PENDING -> ACTIVE -> REVOKED} lifecycle via the {@link #activate}/{@link #revoke}
 * compare-and-swap methods. These rows carry NO security-sensitive bytes themselves (the
 * connect-time gates live in the handler; the private dial key lives in Vault, referenced by
 * {@code vault_ref}).
 */
@Repository
public class DeviceSshDialRepository {

    private final DeviceSshDialR2dbcRepository repo;

    public DeviceSshDialRepository(DeviceSshDialR2dbcRepository repo) {
        this.repo = repo;
    }

    /**
     * The dial-key row for this device, if any. The per-device lookup the dial factory uses
     * (one row per device — the UNIQUE(device_id) backstop guarantees at most one).
     */
    public Mono<DeviceSshDial> findByDeviceId(String deviceId) {
        return repo.findByDeviceId(deviceId).map(DeviceSshDialRow::toDomain);
    }

    /** The dial-key row with this id, if any. */
    public Mono<DeviceSshDial> findById(String id) {
        return repo.findById(id).map(DeviceSshDialRow::toDomain);
    }

    /**
     * The dial rows VISIBLE to the given tenant scope — the SUPERADMIN dial-management list. The
     * dial table itself has no domain column (one row per device), so scope is applied by JOINing
     * the owning {@code device_registry} row's residency domain. A scoped principal sees ONLY their
     * brand's devices' dial rows; an unscoped (SUPERADMIN) caller sees all. Defence-in-depth: the
     * controller gates this SUPERADMIN-only (unscoped is the live path), but a scoped call here
     * never leaks a foreign-domain dial row. Ordered by device for a stable list.
     */
    public Flux<DeviceSshDial> list(PrincipalDomain scope) {
        if (scope == null || scope.scoped()) {
            String domain = scope == null ? PrincipalDomain.NO_DOMAIN : scope.domain();
            return repo.listScoped(domain).map(DeviceSshDialRow::toDomain);
        }
        return repo.listAll().map(DeviceSshDialRow::toDomain);
    }

    /**
     * Seed a new dial-key row (app-generated id) at generation 1, returning it. The caller
     * has already placed the PRIVATE key in Vault and references it via {@code vaultRef} /
     * {@code k8sSecretName} — only NON-SECRET material lands here. status starts
     * {@code PENDING}.
     */
    public Mono<DeviceSshDial> insert(DeviceSshDial d) {
        long gen = d.generation() <= 0 ? 1L : d.generation();
        String status = d.status() == null ? DeviceSshDial.STATUS_PENDING : d.status();
        Instant createdAt = Instant.now();
        // INSERT omits id (filled from the (gen_random_uuid())::text column DEFAULT, changelog
        // 200) and the not-yet-set rotated_at (default NULL); RETURNING id hands back the generated
        // string, mapped into the persisted dial row with the SAME field order/values as before.
        return repo.insertReturningId(d.deviceId(), d.dialUser(), d.hostKeyPub(), d.hostKeyFp(),
                        d.dialPubFp(), d.vaultRef(), d.k8sSecretName(), d.seededByBuildId(), status,
                        gen, createdAt)
                .map(genId -> new DeviceSshDial(genId, d.deviceId(), d.dialUser(), d.hostKeyPub(),
                        d.hostKeyFp(), d.dialPubFp(), d.vaultRef(), d.k8sSecretName(),
                        d.seededByBuildId(), status, gen, createdAt, null));
    }

    /**
     * Set the lifecycle status for a dial row by id ({@code PENDING -> ACTIVE -> REVOKED}),
     * stamping {@code rotated_at}. Returns the rows-updated count (0 = absent). The valid
     * status vocabulary is the {@code ck_device_ssh_dial_status} CHECK backstop.
     *
     * <p>This UNGUARDED setter is the low-level seed/rotate primitive. The
     * {@code DesktopDialService} lifecycle (PENDING-&gt;ACTIVE / ACTIVE-&gt;REVOKED) uses the
     * COMPARE-AND-SWAP variants below ({@link #activate}/{@link #revoke}) so exactly one writer
     * wins a transition and the generation is bumped.
     */
    public Mono<Long> updateStatus(String id, String status) {
        return repo.updateStatus(id, status);
    }

    /**
     * COMPARE-AND-SWAP {@code PENDING -> ACTIVE} for one row id at a NEW generation, stamping
     * {@code rotated_at}, guarded on the row still being {@code PENDING} AND having a present
     * pinned {@code host_key_fp} (a row with no pin is refused HERE too — defence-in-depth behind
     * the service's explicit 422). Returns rows-updated (1 = this caller won, 0 = not PENDING /
     * unpinned / absent — idempotent re-activate is a no-op). Never deletes.
     */
    public Mono<Long> activate(String id, long newGeneration) {
        return repo.activate(id, newGeneration);
    }

    /**
     * COMPARE-AND-SWAP {@code ACTIVE -> REVOKED} for one row id at a NEW generation, stamping
     * {@code rotated_at}, guarded on the row still being {@code ACTIVE} so only ONE writer wins
     * (1 = revoked, 0 = already revoked / not active / absent). The row is NEVER deleted — it is
     * the audit trail. The factory reads {@code status='ACTIVE'} so a revoke immediately disables
     * the dial.
     */
    public Mono<Long> revoke(String id, long newGeneration) {
        return repo.revoke(id, newGeneration);
    }
}
