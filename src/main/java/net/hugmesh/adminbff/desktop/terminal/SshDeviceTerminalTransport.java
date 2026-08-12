package net.hugmesh.adminbff.desktop.terminal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.publisher.Sinks;
import reactor.core.scheduler.Scheduler;
import reactor.core.scheduler.Schedulers;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * The REAL {@link DeviceSshTransport} — the LIVE in-UI SSH-terminal transport leg on top of the
 * #75 foundation. Wired ONLY when {@code app.device-terminal.enabled=true} (see {@link
 * DeviceTerminalConfig}); the no-dial {@link StubDeviceSshTransport} is the ships-dark default, and
 * the two are mutually exclusive (mirrors the {@code DesktopSshClient} Noop/Rest idiom).
 *
 * <p>This bean owns the SESSION LIFECYCLE the foundation left as bound-but-unenforced seams:
 * <ul>
 *   <li><b>max-sessions</b> ({@code app.device-terminal.max-sessions}): a per-replica live-session
 *       counter. {@link #open} beyond the cap is REJECTED ({@link Mono#error}) before any channel
 *       is dialed, so a flood cannot exhaust the replica;</li>
 *   <li><b>idle-timeout</b> ({@code app.device-terminal.idle-timeout}): a session with no I/O
 *       (no stdin, no resize, no output) for longer than the configured idle is torn down and its
 *       output stream completed, freeing the slot.</li>
 * </ul>
 *
 * <p>It does NOT authorize anything (the handler's 5 connect-time gates already passed) and it does
 * NOT touch key material: the actual dial + device HOST-KEY verification + PTY request live behind
 * the narrow {@link DeviceSshChannelFactory} seam. The shipped {@link
 * UnconfiguredDeviceSshChannelFactory} fails closed (never dials, never TOFU-trusts) because the
 * host-key-storage decision is FLAGGED and unresolved — so even flag-on this transport reaches no
 * real device until a concrete factory lands. {@link #isReal()} reports {@code true} (the real
 * lifecycle is live); whether a device is actually dialed is {@link DeviceSshChannelFactory#canDial()}.
 */
public class SshDeviceTerminalTransport implements DeviceSshTransport {

    private static final Logger log = LoggerFactory.getLogger(SshDeviceTerminalTransport.class);

    private final DeviceSshChannelFactory channels;
    private final Duration idleTimeout;
    private final int maxSessions;
    private final Scheduler timeoutScheduler;

    /** Live (open) session count on THIS replica — the max-sessions backstop. */
    private final AtomicInteger live = new AtomicInteger();

    public SshDeviceTerminalTransport(DeviceSshChannelFactory channels, DeviceTerminalProperties props) {
        this(channels, props.getIdleTimeout(), props.getMaxSessions(), Schedulers.parallel());
    }

    SshDeviceTerminalTransport(DeviceSshChannelFactory channels, Duration idleTimeout,
                               int maxSessions, Scheduler timeoutScheduler) {
        this.channels = channels;
        this.idleTimeout = idleTimeout == null ? Duration.ZERO : idleTimeout;
        this.maxSessions = maxSessions;
        this.timeoutScheduler = timeoutScheduler;
    }

    @Override
    public Mono<Session> open(String deviceId, String hostname, String operator, int cols, int rows) {
        // Reserve a session slot then dial; release the slot on any dial failure.
        return Mono.defer(() -> openWithSlot(deviceId, hostname, operator, cols, rows));
    }

    /** Check the session cap, reserve a slot, dial, then release the slot on error. */
    private Mono<Session> openWithSlot(String deviceId, String hostname, String operator,
                                        int cols, int rows) {
        // max-sessions: reserve a slot BEFORE dialing; reject (and unreserve) past the cap so a
        // flood never reaches the channel factory. CAS-free: increment then bounds-check.
        int n = live.incrementAndGet();
        if (maxSessions > 0 && n > maxSessions) {
            live.decrementAndGet();
            log.warn("[device-terminal] max-sessions={} reached — rejecting open device={} operator={}",
                    maxSessions, deviceId, operator);
            return Mono.error(new MaxSessionsExceededException(
                    "device-terminal session cap reached (" + maxSessions + ")"));
        }
        log.info("[device-terminal] (real) opening PTY device={} host={} operator={} {}x{} "
                + "(live={}/{}, canDial={})", deviceId, hostname, operator, cols, rows, n,
                maxSessions, channels.canDial());
        return channels.open(deviceId, hostname, operator, cols, rows)
                .<Session>map(ch -> new IdleGuardedSession(deviceId, operator, ch))
                // Release the reserved slot if the dial fails (host-key refusal, unconfigured factory…).
                .doOnError(e -> live.decrementAndGet());
    }

    @Override
    public boolean isReal() {
        return true;
    }

    /** Visible for tests: the current live-session count on this replica. */
    int liveSessions() {
        return live.get();
    }

    /**
     * A {@link Session} that enforces the idle-timeout and releases the max-sessions slot on close.
     * Any I/O (stdin / resize / a produced output chunk) is an ACTIVITY signal that RESETS the idle
     * window; if no activity occurs for {@link #idleTimeout} the session is torn down and its output
     * flux completed. The idle window is driven entirely by {@link #timeoutScheduler}'s clock
     * (a {@code switchMap} over {@link Mono#delay} restarts on each activity) — never wall-clock —
     * so it is correct under back-pressure and deterministically testable with virtual time.
     */
    private final class IdleGuardedSession implements Session {

        private final String deviceId;
        private final String operator;
        private final DeviceSshChannelFactory.Channel channel;
        private final AtomicBoolean closed = new AtomicBoolean(false);
        // Activity ticks: emit on every stdin/resize/output. multicast so the idle timer and the
        // (potentially absent) output subscriber share one source; onBackpressureBuffer-free since
        // we only care about the LATEST activity (switchMap drops stale delays).
        private final Sinks.Many<Long> activity =
                Sinks.many().multicast().onBackpressureBuffer(1, false);

        IdleGuardedSession(String deviceId, String operator, DeviceSshChannelFactory.Channel channel) {
            this.deviceId = deviceId;
            this.operator = operator;
            this.channel = channel;
        }

        @Override
        public void writeStdin(byte[] data) {
            touch();
            channel.writeStdin(data);
        }

        @Override
        public void resize(int cols, int rows) {
            touch();
            channel.resize(cols, rows);
        }

        @Override
        public Flux<byte[]> output() {
            Flux<byte[]> upstream = channel.output().doOnNext(b -> touch());
            if (idleTimeout.isZero() || idleTimeout.isNegative()) {
                return upstream.doFinally(sig -> close());
            }
            // Reset-on-activity idle timer: each activity tick (seeded with one immediate tick so
            // the window starts at open) restarts a delay(idleTimeout); when a delay completes
            // un-interrupted, the session has been idle for the full window → stop the stream.
            Flux<byte[]> idleStop = activity.asFlux()
                    .startWith(0L)
                    .switchMap(t -> Mono.delay(idleTimeout, timeoutScheduler))
                    .next()
                    .doOnNext(t -> log.info("[device-terminal] idle-timeout ({}s) — closing session "
                            + "device={} operator={}", idleTimeout.toSeconds(), deviceId, operator))
                    .flux()
                    .map(t -> new byte[0]); // type-carrier only; takeUntilOther ignores the value
            return upstream.takeUntilOther(idleStop).doFinally(sig -> close());
        }

        @Override
        public void close() {
            if (closed.compareAndSet(false, true)) {
                try {
                    activity.tryEmitComplete();
                    channel.close();
                } finally {
                    int remaining = live.decrementAndGet();
                    log.info("[device-terminal] session closed device={} operator={} (live={}/{})",
                            deviceId, operator, remaining, maxSessions);
                }
            }
        }

        private void touch() {
            // Best-effort activity signal; a dropped tick (no current subscriber) is harmless —
            // the next real activity or the timer itself governs the window.
            activity.tryEmitNext(System.nanoTime());
        }
    }

    /** Rejected because the replica is at its live-session cap. */
    public static class MaxSessionsExceededException extends RuntimeException {
        public MaxSessionsExceededException(String message) {
            super(message);
        }
    }
}
