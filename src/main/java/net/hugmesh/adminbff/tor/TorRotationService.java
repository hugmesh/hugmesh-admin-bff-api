package net.hugmesh.adminbff.tor;

import net.hugmesh.adminbff.capability.DomainCapability;
import net.hugmesh.adminbff.capability.DomainCapabilityRepository;
import net.hugmesh.commons.security.PrincipalDomain;
import net.hugmesh.commons.web.ApiException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.List;

/**
 * "A new Tor address for this domain" (hugmesh-generator#652): records the request; the
 * signed per-node Tor export carries it, and each Tor node moves that domain's key aside
 * and mints a new onion address (hugmesh-tor-reconcile, step 4b), then reports it.
 *
 * <p>Refusals, in this order, nothing written by any of them:
 * <ol>
 *   <li>422: not a Tor domain key name, or {@code default} (the mesh's own address is not
 *       replaced from the console);</li>
 *   <li>403: a domain ADMIN asking for another domain (a SUPERADMIN may ask for any);</li>
 *   <li>422: the typed confirmation is not the domain's key name;</li>
 *   <li>409: the domain has no Tor address of its own (the platform-wide {@code tor-onion}
 *       switch is off, or this domain's row is not active).</li>
 * </ol>
 */
@Service
public class TorRotationService {

    private static final Logger log = LoggerFactory.getLogger(TorRotationService.class);

    private final TorRotationRowRepository rotations;
    private final DomainCapabilityRepository capabilities;

    public TorRotationService(TorRotationRowRepository rotations, DomainCapabilityRepository capabilities) {
        this.rotations = rotations;
        this.capabilities = capabilities;
    }

    /** The answer: the domain and how many new addresses it has been asked for so far. */
    public record TorRotationResult(String domain, long requestCount, String status) {
    }

    public Mono<TorRotationResult> request(String domain, String confirm, PrincipalDomain scope,
                                           String actor) {
        if (domain == null || !TorOnionRules.isSlug(domain) || TorOnionRules.DEFAULT_DOMAIN.equals(domain)) {
            return Mono.error(ApiException.unprocessable(
                    "Only a domain's own Tor address can be replaced here; the mesh's own address is not."));
        }
        if (scope == null || (!scope.superadmin() && !domain.equals(scope.domain()))) {
            return Mono.error(ApiException.forbidden("Not your domain."));
        }
        if (!domain.equals(confirm)) {
            return Mono.error(ApiException.unprocessable(
                    "Type the domain's key name to confirm; the old address stops working for everyone."));
        }
        return capabilities.listAll()
                .filter(c -> DomainCapability.TOR_ONION.equals(c.capability()))
                .collectList()
                .flatMap(rows -> {
                    if (!torDomainIsLive(domain, rows)) {
                        return Mono.error(ApiException.conflict(
                                "This domain has no Tor address of its own, so there is nothing to replace."));
                    }
                    return rotations.increment(domain, actor)
                            .then(rotations.findById(domain))
                            .map(r -> {
                                log.info("[tor-rotation] domain={} request={} by={}", domain,
                                        r.rotationCount(), actor);
                                return new TorRotationResult(domain, r.rotationCount(), "requested");
                            });
                });
    }

    /** The same rule the export uses: the global row granted, and this domain's row active. */
    static boolean torDomainIsLive(String domain, List<DomainCapability> torRows) {
        boolean globalOn = false;
        boolean rowOn = false;
        for (DomainCapability c : torRows) {
            if (DomainCapability.GLOBAL_DOMAIN.equals(c.domain())) {
                globalOn = c.granted();
            } else if (domain.equals(c.domain())) {
                rowOn = c.active();
            }
        }
        return globalOn && rowOn;
    }
}
