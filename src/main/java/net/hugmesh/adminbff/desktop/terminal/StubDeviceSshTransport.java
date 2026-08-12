package net.hugmesh.adminbff.desktop.terminal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;

/**
 * The SHIPS-DARK default {@link DeviceSshTransport} — wired whenever
 * {@code app.device-terminal.enabled} is false/absent ({@code @ConditionalOnProperty(havingValue
 * ="false", matchIfMissing=true)}), mutually exclusive with the REAL
 * {@link SshDeviceTerminalTransport} (flag on). The same Noop/Rest shape as
 * {@code NoopDesktopSshClient}.
 *
 * <p>It does NOT dial any host, open any SSH channel, or read any key material. {@link #open} emits
 * a {@link Session} that streams a single canned banner explaining the feature ships dark, then
 * completes — so even on the ALLOW path (authenticated + licensed + valid step-up + flag-on) NO
 * real device is ever reached while only this bean is present. This keeps the PR safe to merge.
 *
 * <p>The REAL transport is {@link SshDeviceTerminalTransport} (flag on). It owns the session
 * lifecycle (idle-timeout, max-sessions, PTY framing) and dials through the
 * {@link DeviceSshChannelFactory} seam — whose only shipped impl
 * ({@link UnconfiguredDeviceSshChannelFactory}) still fails closed, because a managed device
 * host-key (known-hosts) source and the dial credential are an UNRESOLVED, FLAGGED decision. None
 * of that key material lands here.
 */
public class StubDeviceSshTransport implements DeviceSshTransport {

    private static final Logger log = LoggerFactory.getLogger(StubDeviceSshTransport.class);

    static final String DARK_BANNER =
            "\r\n[hugmesh] device terminal transport not enabled (ships dark).\r\n"
            + "The interactive SSH channel is a follow-on increment; authorization is live but no\r\n"
            + "device is reached while the stub transport is active.\r\n";

    @Override
    public Mono<Session> open(String deviceId, String hostname, String operator, int cols, int rows) {
        // No real connection — log + hand back a banner-only session. TODO(follow-on): the real
        // SSH client impl replaces this bean (flag on + real bean present); it MUST NOT change the
        // handler's connect-time gates, only the transport.
        log.info("[device-terminal] (stub, SHIPS DARK) open requested device={} operator={} {}x{} "
                + "— no SSH dialed", deviceId, operator, cols, rows);
        return Mono.just(new StubSession());
    }

    @Override
    public boolean isReal() {
        return false;
    }

    /** A banner-only session: emits the dark banner once, accepts (and drops) any stdin/resize. */
    private static final class StubSession implements Session {
        @Override
        public void writeStdin(byte[] data) {
            // ships dark — nothing is forwarded anywhere
        }

        @Override
        public void resize(int cols, int rows) {
            // ships dark — no PTY to resize
        }

        @Override
        public Flux<byte[]> output() {
            return Flux.just(DARK_BANNER.getBytes(StandardCharsets.UTF_8));
        }

        @Override
        public void close() {
            // nothing to tear down
        }
    }
}
