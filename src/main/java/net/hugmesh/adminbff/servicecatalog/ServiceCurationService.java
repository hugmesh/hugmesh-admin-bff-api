package net.hugmesh.adminbff.servicecatalog;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.security.PrincipalDomain;
import net.hugmesh.commons.web.ApiException;

/**
 * The write/read surface for {@code service_curation} — the per-domain TWO-TIER offered
 * catalog (App-Store PR1 data layer). Two tiers, two surfaces:
 * <ul>
 *   <li>SUPERADMIN (cross-domain) {@link #offer}/{@link #withdraw}/{@link #listForDomain}
 *       a service_key FOR an EXPLICIT {@code domain} (the infra control plane picks the
 *       brand — the domain is a method argument, NEVER read from a request body).</li>
 *   <li>a brand ADMIN {@link #offeredCatalog} reads ONLY their own issuer-derived domain's
 *       offered rows (scoped by {@link PrincipalDomain}). This is the two-tier proof: an admin
 *       sees only what the superadmin offered to THEIR domain.</li>
 * </ul>
 *
 * <p>Desired-state (the {@code access_suspension} convention): an offer is idempotent (an
 * existing offered row is returned unchanged); a withdraw is a CAS {@code offered ->
 * withdrawn} (never a hard delete). NO infra effect here — PR1 is the data/accounting layer
 * only; later increments materialise an offered service into a real catalog entry the admin
 * can deploy.
 */
@Service
public class ServiceCurationService {

    private static final Logger log = LoggerFactory.getLogger(ServiceCurationService.class);

    private final ServiceCurationRepository repo;

    public ServiceCurationService(ServiceCurationRepository repo) {
        this.repo = repo;
    }

    /**
     * Offer {@code serviceKey} to {@code domain}'s admins (SUPERADMIN; the domain is the
     * explicit target, never a body field). Idempotent: an existing OFFERED row for the
     * (domain, service_key) is returned unchanged; otherwise a new offered row is written,
     * stamped with the superadmin's subject.
     */
    public Mono<ServiceCuration> offer(String domain, String serviceKey, String curatedBySubject) {
        if (domain == null || domain.isBlank()) {
            return Mono.error(ApiException.badRequest("domain is required"));
        }
        if (serviceKey == null || serviceKey.isBlank()) {
            return Mono.error(ApiException.badRequest("serviceKey is required"));
        }
        String d = domain.trim();
        String key = serviceKey.trim();
        return repo.findOffered(d, key)
                .doOnNext(existing -> log.info("[curation] {} already offered to {} (id={}) — no-op",
                        key, d, existing.id()))
                .switchIfEmpty(Mono.defer(() -> repo.insertOffered(d, key, curatedBySubject)
                        .doOnNext(c -> log.info("[curation] offered {} to {} by {} (id={})",
                                key, d, curatedBySubject, c.id()))));
    }

    /**
     * Withdraw {@code serviceKey} from {@code domain}'s offered catalog (SUPERADMIN; CAS
     * offered->withdrawn). A no-op (404) if there is no live offer for that (domain,
     * service_key).
     */
    public Mono<ServiceCuration> withdraw(String domain, String serviceKey, String curatedBySubject) {
        if (domain == null || domain.isBlank() || serviceKey == null || serviceKey.isBlank()) {
            return Mono.error(ApiException.badRequest("domain and serviceKey are required"));
        }
        String d = domain.trim();
        String key = serviceKey.trim();
        return repo.findOffered(d, key)
                .switchIfEmpty(Mono.error(ApiException.notFound(
                        "no offered service '" + key + "' for domain '" + d + "'")))
                .flatMap(active -> repo.markWithdrawn(active.id())
                        .doOnNext(n -> log.info("[curation] withdrew {} from {} by {} (id={}, rows={})",
                                key, d, curatedBySubject, active.id(), n))
                        .thenReturn(new ServiceCuration(active.id(), active.domain(), active.serviceKey(),
                                ServiceCuration.STATE_WITHDRAWN, active.curatedBySubject(),
                                active.createdAt(), active.updatedAt())));
    }

    /** Every curation row (offered + withdrawn) for an EXPLICIT {@code domain} — the
     *  SUPERADMIN per-domain catalog view. */
    public Flux<ServiceCuration> listForDomain(String domain) {
        if (domain == null || domain.isBlank()) {
            return Flux.error(ApiException.badRequest("domain is required"));
        }
        return repo.findByDomain(domain.trim());
    }

    /**
     * The OFFERED catalog VISIBLE to the acting principal's tenant scope — the brand-ADMIN
     * read surface ({@code /bff/admin/service-store}). A scoped admin sees ONLY their own
     * brand's offered rows; SUPERADMIN sees all. The domain comes from the validated JWT
     * issuer (via the scope), NEVER from the request.
     */
    public Flux<ServiceCuration> offeredCatalog(PrincipalDomain scope) {
        return repo.offeredForScope(scope);
    }
}
