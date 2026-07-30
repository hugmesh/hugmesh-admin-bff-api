package systems.hugmesh.adminbff.servicecatalog;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.security.PrincipalDomain;
import systems.hugmesh.commons.web.ApiException;

import java.time.Instant;

/**
 * The write/read surface for {@code service_deployment} — the per-domain lifecycle
 * accounting table (App-Store PR1 data layer). The SUPERADMIN control plane
 * {@link #create}s / {@link #list}s / {@link #end}s deployments FOR an explicit
 * {@code domain} (the brand is a method argument, NEVER read from a request body); a
 * scoped list is also offered for any principal via {@link PrincipalDomain}.
 *
 * <p>Records the accounting facts: {@code created_at} (now, at insert), the
 * {@code ending_at} single expiry clock (null = no-expiry), and the opaque
 * {@code enforce_actions} list emitted at end-of-lease. A deployment ENDS via a CAS
 * {@code active -> ended} (the {@code ServiceDeploymentExpiryAction} is the scheduled
 * single-writer twin; this service's {@link #end} is the manual path). NO infra effect —
 * PR1 ships dark; the ArgoCD/Casdoor/cert teardown is a later increment.
 */
@Service
public class ServiceDeploymentService {

    private static final Logger log = LoggerFactory.getLogger(ServiceDeploymentService.class);

    private final ServiceDeploymentRepository repo;

    public ServiceDeploymentService(ServiceDeploymentRepository repo) {
        this.repo = repo;
    }

    /**
     * Create an ACTIVE deployment of {@code serviceKey} in {@code domain} (SUPERADMIN; the
     * domain is the explicit target). Records {@code created_at} (now), the
     * {@code endingAt} expiry clock (null = no-expiry), the {@code profileRef} (nullable
     * soft app_profile name) and the opaque {@code enforceActions}. Stamps the superadmin's
     * subject.
     */
    public Mono<ServiceDeployment> create(String domain, String serviceKey, String profileRef,
                                          Instant endingAt, String enforceActions,
                                          String createdBySubject) {
        if (domain == null || domain.isBlank()) {
            return Mono.error(ApiException.badRequest("domain is required"));
        }
        if (serviceKey == null || serviceKey.isBlank()) {
            return Mono.error(ApiException.badRequest("serviceKey is required"));
        }
        return repo.insertActive(domain.trim(), serviceKey.trim(), profileRef, endingAt,
                        enforceActions, createdBySubject)
                .doOnNext(d -> log.info("[deployment] created {} in {} by {} (id={}, endingAt={})",
                        d.serviceKey(), d.domain(), createdBySubject, d.id(), d.endingAt()));
    }

    /**
     * Every deployment VISIBLE to the acting principal's tenant scope. A scoped admin sees
     * ONLY their own brand's rows; SUPERADMIN sees all. The domain comes from the validated
     * JWT issuer (via the scope), NEVER from the request.
     */
    public Flux<ServiceDeployment> list(PrincipalDomain scope) {
        return repo.listForScope(scope);
    }

    /** Every deployment for an EXPLICIT {@code domain} (the SUPERADMIN per-domain list). */
    public Flux<ServiceDeployment> listForDomain(String domain) {
        if (domain == null || domain.isBlank()) {
            return Flux.error(ApiException.badRequest("domain is required"));
        }
        return repo.findByDomain(domain.trim());
    }

    /**
     * End a deployment by id (SUPERADMIN; CAS active->ended, stamps {@code ended_at}). A 404
     * if no such deployment exists; idempotent — ending an already-ended deployment is a
     * no-op that returns the current row. SHIPS DARK: NO real teardown here — the
     * enforce_actions are the recorded intent the later effector resolves.
     */
    public Mono<ServiceDeployment> end(String id) {
        return repo.findById(id)
                .switchIfEmpty(Mono.error(ApiException.notFound("no deployment '" + id + "'")))
                .flatMap(current -> repo.markEnded(id)
                        .doOnNext(n -> log.info("[deployment] ended id={} (rows={})", id, n))
                        // Re-read so the response reflects the CAS result (ended + ended_at),
                        // whether this call won the transition or it was already ended.
                        .then(repo.findById(id)));
    }
}
