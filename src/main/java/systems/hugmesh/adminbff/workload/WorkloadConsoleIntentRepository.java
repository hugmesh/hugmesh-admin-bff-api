package systems.hugmesh.adminbff.workload;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.security.PrincipalDomain;

import java.time.Instant;

/**
 * Reactive (R2DBC) store for {@code workload_console_intent} — the GitOps-PR OUTBOX. A
 * GitOps-authoritative lifecycle verb writes one desired-state intent row (SHIPS DARK: the
 * ArgoCD-PR effect is STUBBED/LOGGED by {@link WorkloadGitOpsEmitter}). The UI surfaces the
 * pending intent.
 *
 * <p>Backed by the Spring Data {@link WorkloadConsoleIntentR2dbcRepository} (no raw
 * {@code DatabaseClient}); maps the {@link WorkloadConsoleIntentRow} entity to/from the
 * {@link WorkloadConsoleIntent} domain record.
 */
@Repository
public class WorkloadConsoleIntentRepository {

    private final WorkloadConsoleIntentR2dbcRepository repo;

    public WorkloadConsoleIntentRepository(WorkloadConsoleIntentR2dbcRepository repo) {
        this.repo = repo;
    }

    public Mono<WorkloadConsoleIntent> insert(WorkloadConsoleIntent i, long generation) {
        Instant requestedAt = Instant.now();
        // INSERT omits id (filled from the (gen_random_uuid())::text column DEFAULT, changelog
        // 200); RETURNING id hands back the generated string, mapped into the persisted intent
        // with the SAME field order/values as before.
        return repo.insertReturningId(i.kind(), i.namespace(), i.workload(), i.imageRef(),
                        i.replicas(), i.requestedBy(), requestedAt, i.domain(),
                        WorkloadConsoleIntent.PROP_PENDING, generation)
                .map(genId -> new WorkloadConsoleIntent(genId, i.kind(), i.namespace(), i.workload(),
                        i.imageRef(), i.replicas(), i.requestedBy(), requestedAt, i.domain(),
                        WorkloadConsoleIntent.PROP_PENDING, generation));
    }

    /** Pending intents VISIBLE to the given scope — surfaced as "pending sync" in the UI.
     *  Scoped admin sees only their brand's rows; SUPERADMIN sees all. */
    public Flux<WorkloadConsoleIntent> listPending(PrincipalDomain scope) {
        if (scope == null || scope.scoped()) {
            String domain = scope == null ? PrincipalDomain.NO_DOMAIN : scope.domain();
            return repo.findByPropagationStateAndDomainOrderByRequestedAtDesc(
                            WorkloadConsoleIntent.PROP_PENDING, domain)
                    .map(WorkloadConsoleIntentRow::toDomain);
        }
        return repo.findByPropagationStateOrderByRequestedAtDesc(WorkloadConsoleIntent.PROP_PENDING)
                .map(WorkloadConsoleIntentRow::toDomain);
    }

    public Mono<Long> maxGeneration() {
        return repo.maxGeneration().defaultIfEmpty(0L);
    }
}
