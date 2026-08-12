package net.hugmesh.adminbff.desktop;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.security.PrincipalDomain;

/**
 * Write/read surface for {@code desktop_install_request} — a non-sudo user's allow/install
 * request and the admin decision over it.
 *
 * <h3>owner == subject (fail-closed)</h3>
 * Submit stamps {@code requester} = the JWT subject and {@code domain} = the validated
 * issuer (both controller-derived, never body fields). The user read is double-scoped
 * (requester + domain) so a user only ever sees their OWN requests. The admin decide is a
 * brand-scoped CAS {@code pending -> terminal} (single-winner; never deleted = audit).
 */
@Service
public class DesktopInstallRequestService {

    private static final Logger log = LoggerFactory.getLogger(DesktopInstallRequestService.class);

    private final DesktopInstallRequestRepository repo;

    public DesktopInstallRequestService(DesktopInstallRequestRepository repo) {
        this.repo = repo;
    }

    /** Submit a new PENDING request. {@code requester}/{@code domain} are caller-derived. */
    public Mono<DesktopInstallRequest> submit(String requester, String appRef, String deviceId,
                                              String domain) {
        return repo.insertPending(requester, appRef, deviceId, domain)
                .doOnNext(r -> log.info("[desktop-install-req] submit requester={} ref={} device={} domain={} id={}",
                        requester, appRef, deviceId, domain, r.id()));
    }

    /** The requester's OWN requests (owner == subject). */
    public Flux<DesktopInstallRequest> listMine(String requester, String domain) {
        return repo.listForRequester(requester, domain);
    }

    /** ALL requests VISIBLE to the acting admin (own brand; SUPERADMIN all) — the inbox. */
    public Flux<DesktopInstallRequest> listForAdmin(PrincipalDomain scope) {
        return repo.list(scope);
    }

    /** Decide a request (CAS {@code pending -> newStatus}, brand-scoped, single-winner).
     *  Returns rows-updated (1 = decided, 0 = already decided / absent / out of scope). */
    public Mono<Long> decide(String id, String newStatus, String decidedBy, PrincipalDomain scope) {
        return repo.decide(id, newStatus, decidedBy, scope)
                .doOnNext(n -> log.info("[desktop-install-req] decide id={} -> {} by={} rows={}",
                        id, newStatus, decidedBy, n));
    }
}
