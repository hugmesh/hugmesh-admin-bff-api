package systems.hugmesh.adminbff.desktop;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

/**
 * The SHIPS-DARK default {@link DesktopSshClient}: logs the would-be remote-install SSH exec
 * and returns a placeholder WITHOUT dialing any host. In force whenever
 * {@code app.desktop.remote-install.enabled=false} (the DEFAULT). The remote-install
 * AUTHORIZATION (active own-domain ssh-license for the target device) runs its full sequence
 * against this no-op, so it is fully unit-testable without a live mesh — and a ships-dark
 * test can assert {@code isReal() == false} structurally.
 */
public class NoopDesktopSshClient implements DesktopSshClient {

    private static final Logger log = LoggerFactory.getLogger(NoopDesktopSshClient.class);

    @Override
    public Mono<String> remoteInstall(String deviceId, String hostname, String appRef, String operator) {
        log.info("[desktop-remote-install] (noop, SHIPS DARK) would SSH to device={} host={} and install "
                + "ref='{}' as operator={} (no SSH call)", deviceId, hostname, appRef, operator);
        return Mono.just("{\"deviceId\":\"" + deviceId + "\",\"appRef\":\"" + appRef
                + "\",\"dark\":true,\"note\":\"remote-install SSH exec ships dark\"}");
    }

    @Override
    public boolean isReal() {
        return false;
    }
}
