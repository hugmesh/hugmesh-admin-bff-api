package systems.hugmesh.adminbff.argocd;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

/**
 * The SHIPS-DARK default {@link ArgoCdClient}: logs the would-be Application create/delete
 * and reports success WITHOUT dialing any ArgoCD API. In force whenever the effector is not
 * enabled ({@code app.appstore.effector.enabled=false}, the DEFAULT) — a dev / test / CI run
 * or an in-cluster deployment that has not opted the effector in.
 *
 * <p>The {@code AddService} effector's full contract (route-access rows + Casdoor role +
 * the Application create/delete CALL SEQUENCE) is exercisable against this no-op, so the
 * effector is fully unit-testable without a live ArgoCD — and a ships-dark test can assert
 * {@code isReal()==false} structurally.
 */
public class NoopArgoCdClient implements ArgoCdClient {

    private static final Logger log = LoggerFactory.getLogger(NoopArgoCdClient.class);

    @Override
    public Mono<String> createApplication(String name, String repoUrl, String path,
                                          String targetRevision, String destNamespace) {
        log.info("[argocd] (noop, SHIPS DARK) would create Application '{}' repo={} path={} rev={} ns={} "
                        + "(no ArgoCD call)", name, repoUrl, path, targetRevision, destNamespace);
        return Mono.just(name);
    }

    @Override
    public Mono<Boolean> deleteApplication(String name) {
        log.info("[argocd] (noop, SHIPS DARK) would delete Application '{}' (no ArgoCD call)", name);
        return Mono.just(true);
    }

    @Override
    public boolean isReal() {
        return false;
    }
}
