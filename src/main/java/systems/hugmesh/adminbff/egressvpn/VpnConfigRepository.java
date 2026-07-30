package systems.hugmesh.adminbff.egressvpn;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.security.PrincipalDomain;

import java.time.Instant;

/**
 * Reactive (R2DBC) store for {@code vpn_config} — one imported provider VPN config per
 * (domain, name) for the egress-VPN optional service (schema in Liquibase
 * {@code db/changelog/080-egress-vpn-configs.xml}).
 *
 * <p>Backed by the Spring Data {@link VpnConfigRowRepository} (no raw {@code DatabaseClient});
 * maps the {@link VpnConfigRow} entity to the {@link VpnConfig} domain record. The row holds
 * ONLY a {@code secret_ref} + metadata — never the {@code .conf} bytes / the private key.
 * Revoke is a CAS {@code active -> revoked} at a monotonic generation that NEVER deletes.
 */
@Repository
public class VpnConfigRepository {

    private final VpnConfigRowRepository repo;

    public VpnConfigRepository(VpnConfigRowRepository repo) {
        this.repo = repo;
    }

    /** The active config for (domain, name), if any — the idempotency / conflict check. */
    public Mono<VpnConfig> findActiveByName(String domain, String name) {
        return repo.findByDomainAndNameAndState(domain, name, VpnConfig.STATE_ACTIVE)
                .map(VpnConfigRow::toDomain);
    }

    /** A single config by id. UNSCOPED — used by the assign flow + export. */
    public Mono<VpnConfig> findById(String id) {
        return repo.findById(id).map(VpnConfigRow::toDomain);
    }

    /** Insert a new ACTIVE config (DB-generated id) at the given monotonic generation. The
     *  INSERT omits {@code id} (filled from the {@code (gen_random_uuid())::text} column
     *  DEFAULT, changelog 200) and {@code RETURNING id} hands back the generated string, which
     *  we read back by that id to return the persisted row (same field order/values as
     *  before; the freshly-inserted row's revoke-audit columns are NULL). */
    public Mono<VpnConfig> insertActive(VpnConfig c, long generation) {
        return repo.insertReturningId(c.domain(), c.name(), c.kind(), c.provider(), c.endpoint(),
                        c.secretRef(), VpnConfig.STATE_ACTIVE, c.createdBy(), Instant.now(),
                        VpnConfig.PROP_PENDING, generation)
                .flatMap(genId -> repo.findById(genId).map(VpnConfigRow::toDomain));
    }

    /** ALL configs VISIBLE to the given tenant scope — the ADMIN read surface. */
    public Flux<VpnConfig> list(PrincipalDomain scope) {
        if (scope == null || scope.scoped()) {
            String domain = scope == null ? PrincipalDomain.NO_DOMAIN : scope.domain();
            return repo.findByDomainOrderByNameAscCreatedAtDesc(domain).map(VpnConfigRow::toDomain);
        }
        return repo.findAllByOrderByDomainAscNameAscCreatedAtDesc().map(VpnConfigRow::toDomain);
    }

    /** ALL active configs (every brand). UNSCOPED — the signed export's working set (PR5). */
    public Flux<VpnConfig> listActiveAll() {
        return repo.findByStateOrderByDomainAscNameAsc(VpnConfig.STATE_ACTIVE).map(VpnConfigRow::toDomain);
    }

    /** The current maximum {@code generation} across ALL config rows (0 when empty). */
    public Mono<Long> maxGeneration() {
        return repo.maxGeneration().defaultIfEmpty(0L);
    }

    /** CAS {@code active -> revoked} for one config id at a NEW generation (1 = won, 0 = lost). */
    public Mono<Long> revoke(String id, String revokedBy, long newGeneration, PrincipalDomain scope) {
        if (scope == null || scope.scoped()) {
            String domain = scope == null ? PrincipalDomain.NO_DOMAIN : scope.domain();
            return repo.revokeScoped(id, revokedBy, newGeneration, domain);
        }
        return repo.revokeUnscoped(id, revokedBy, newGeneration);
    }

    /** Record the push-with-ack propagation outcome for a row. UNSCOPED. */
    public Mono<Long> updatePropagationState(String id, String propagationState) {
        return repo.updatePropagationState(id, propagationState);
    }
}
