package net.hugmesh.adminbff.desktop;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

/**
 * The SHIPS-DARK default {@link DesktopRegistryClient}: logs the would-be upstream fetch and
 * returns a placeholder descriptor WITHOUT dialing any Flathub-OCI / upstream registry. In
 * force whenever {@code app.desktop.registry.enabled=false} (the DEFAULT) — a dev / test /
 * CI run or an in-cluster deployment that has not opted the upstream proxy in.
 *
 * <p>The discover-registry FILTERING + authz (domain-locked, enabled-only) run their full
 * sequence against this no-op, so they are fully unit-testable without a live registry — and
 * a ships-dark test can assert {@code isReal() == false} structurally.
 */
public class NoopDesktopRegistryClient implements DesktopRegistryClient {

    private static final Logger log = LoggerFactory.getLogger(NoopDesktopRegistryClient.class);

    @Override
    public Mono<String> fetchRefIndex(String appRef, String source) {
        log.info("[desktop-registry] (noop, SHIPS DARK) would fetch upstream index for ref='{}' source={} "
                + "(no upstream call)", appRef, source);
        return Mono.just("{\"ref\":\"" + appRef + "\",\"source\":\"" + source
                + "\",\"dark\":true,\"note\":\"upstream proxy ships dark\"}");
    }

    @Override
    public boolean isReal() {
        return false;
    }
}
