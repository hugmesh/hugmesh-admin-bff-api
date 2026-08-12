package net.hugmesh.adminbff.servicecatalog.federation;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

/**
 * The SHIPS-DARK default {@link FederationModuleClient}: logs the would-be module register/
 * unregister and reports success WITHOUT dialing federation-api. In force whenever the federate
 * leg is not enabled ({@code app.appstore.federation.enabled=false}, the DEFAULT) — a dev / test /
 * CI run or an in-cluster deployment that has not opted the federate leg in.
 *
 * <p>The federate flow (deployment load + domain guard + metadata assembly + the register CALL)
 * is fully exercisable against this no-op, so it is unit-testable without a live federation-api —
 * and a ships-dark test asserts {@code isReal()==false} structurally (which the federate outcome
 * surfaces as {@code federationReal:false}).
 */
public class NoopFederationModuleClient implements FederationModuleClient {

    private static final Logger log = LoggerFactory.getLogger(NoopFederationModuleClient.class);

    @Override
    public Mono<String> registerModule(String slug, String displayName, String kind, String remoteEntryUrl,
                                       String exposedModule, String version, String visibility,
                                       boolean enabled, String metadata) {
        log.info("[federation] (noop, SHIPS DARK) would register module slug={} kind={} remoteEntryUrl={} "
                        + "exposed={} visibility={} enabled={} (no federation-api call)",
                slug, kind, remoteEntryUrl, exposedModule, visibility, enabled);
        return Mono.just(slug);
    }

    @Override
    public Mono<Boolean> unregisterModule(String slug) {
        log.info("[federation] (noop, SHIPS DARK) would soft-disable module slug={} (no federation-api call)",
                slug);
        return Mono.just(true);
    }

    @Override
    public boolean isReal() {
        return false;
    }
}
