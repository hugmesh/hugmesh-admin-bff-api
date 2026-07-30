package systems.hugmesh.adminbff.desktop.terminal;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Scheduler;
import reactor.core.scheduler.Schedulers;
import reactor.test.StepVerifier;
import reactor.test.scheduler.VirtualTimeScheduler;
import systems.hugmesh.adminbff.desktop.terminal.DeviceSshChannelFactory.Channel;
import systems.hugmesh.adminbff.desktop.terminal.DeviceSshTransport.Session;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The REAL transport leg's lifecycle proof: the {@link SshDeviceTerminalTransport} opens a PTY
 * EXACTLY ONCE through the {@link DeviceSshChannelFactory} on an authorized open, wires
 * stdin/resize, ENFORCES idle-timeout + max-sessions, and FAILS CLOSED (never opens a session) when
 * the factory refuses (unconfigured / host-key verification). The SSH client is always MOCKED — no
 * test ever dials a real device.
 */
class SshDeviceTerminalTransportTest {

    private static final String DEVICE = "dev-1";
    private static final String HOST = "dev-1.mesh";
    private static final String OP = "admin-x";

    // ──────────────────────── PTY-once + stdin/resize wiring ────────────────────

    @Test
    void open_opensChannelExactlyOnce_andWiresStdinResize() {
        DeviceSshChannelFactory factory = mock(DeviceSshChannelFactory.class);
        Channel ch = mock(Channel.class);
        when(ch.output()).thenReturn(Flux.never()); // a live shell that has not produced output yet
        when(factory.open(eq(DEVICE), eq(HOST), eq(OP), anyInt(), anyInt())).thenReturn(Mono.just(ch));
        when(factory.canDial()).thenReturn(true);

        var transport = new SshDeviceTerminalTransport(factory, Duration.ZERO, 16, Schedulers.parallel());
        Session s = transport.open(DEVICE, HOST, OP, 120, 40).block();

        assertThat(s).isNotNull();
        // PTY opened EXACTLY once on the authorized open.
        verify(factory, times(1)).open(eq(DEVICE), eq(HOST), eq(OP), eq(120), eq(40));
        assertThat(transport.isReal()).isTrue();

        // stdin + resize are wired straight through to the channel.
        s.writeStdin("ls\n".getBytes());
        s.resize(200, 50);
        verify(ch, times(1)).writeStdin(eq("ls\n".getBytes()));
        verify(ch, times(1)).resize(eq(200), eq(50));
    }

    @Test
    void output_isStreamedFromChannel() {
        DeviceSshChannelFactory factory = mock(DeviceSshChannelFactory.class);
        Channel ch = mock(Channel.class);
        when(ch.output()).thenReturn(Flux.just("hi".getBytes()));
        when(factory.open(anyString(), anyString(), anyString(), anyInt(), anyInt()))
                .thenReturn(Mono.just(ch));

        var transport = new SshDeviceTerminalTransport(factory, Duration.ZERO, 16, Schedulers.parallel());
        Session s = transport.open(DEVICE, HOST, OP, 80, 24).block();

        byte[] first = s.output().blockFirst();
        assertThat(new String(first)).isEqualTo("hi");
    }

    // ──────────────────────── fail-closed: factory refuses ──────────────────────

    @Test
    void open_failsClosed_whenChannelFactoryUnconfigured_neverYieldsSession() {
        // The shipped fail-closed factory (FLAGGED decision): refuses to dial.
        DeviceSshChannelFactory factory = new UnconfiguredDeviceSshChannelFactory();
        assertThat(factory.canDial()).isFalse();

        var transport = new SshDeviceTerminalTransport(factory, Duration.ZERO, 16, Schedulers.parallel());

        StepVerifier.create(transport.open(DEVICE, HOST, OP, 80, 24))
                .expectError(IllegalStateException.class)
                .verify();
        // The reserved max-sessions slot is RELEASED on the dial failure (no leak).
        assertThat(transport.liveSessions()).isZero();
    }

    @Test
    void open_failsClosed_onHostKeyVerificationFailure_neverYieldsSession() {
        DeviceSshChannelFactory factory = mock(DeviceSshChannelFactory.class);
        when(factory.open(anyString(), anyString(), anyString(), anyInt(), anyInt()))
                .thenReturn(Mono.error(new DeviceSshChannelFactory.HostKeyVerificationException(
                        "device host key not pinned / mismatch")));

        var transport = new SshDeviceTerminalTransport(factory, Duration.ZERO, 16, Schedulers.parallel());

        StepVerifier.create(transport.open(DEVICE, HOST, OP, 80, 24))
                .expectError(DeviceSshChannelFactory.HostKeyVerificationException.class)
                .verify();
        assertThat(transport.liveSessions()).isZero();
    }

    // ──────────────────────── max-sessions ──────────────────────────────────────

    @Test
    void maxSessions_rejectsOpenBeyondCap_withoutDialing() {
        AtomicInteger opens = new AtomicInteger();
        DeviceSshChannelFactory factory = mock(DeviceSshChannelFactory.class);
        when(factory.open(anyString(), anyString(), anyString(), anyInt(), anyInt()))
                .thenAnswer(inv -> {
                    opens.incrementAndGet();
                    Channel ch = mock(Channel.class);
                    when(ch.output()).thenReturn(Flux.never());
                    return Mono.just(ch);
                });

        var transport = new SshDeviceTerminalTransport(factory, Duration.ZERO, 2, Schedulers.parallel());

        Session a = transport.open(DEVICE, HOST, OP, 80, 24).block();
        Session b = transport.open(DEVICE, HOST, OP, 80, 24).block();
        assertThat(a).isNotNull();
        assertThat(b).isNotNull();
        assertThat(transport.liveSessions()).isEqualTo(2);

        // The third open is REJECTED at the cap — and the channel factory is NOT dialed for it.
        StepVerifier.create(transport.open(DEVICE, HOST, OP, 80, 24))
                .expectError(SshDeviceTerminalTransport.MaxSessionsExceededException.class)
                .verify();
        assertThat(opens.get()).isEqualTo(2); // only the two admitted opens dialed

        // Closing one frees a slot so a new open is admitted again.
        a.close();
        assertThat(transport.liveSessions()).isEqualTo(1);
        Session c = transport.open(DEVICE, HOST, OP, 80, 24).block();
        assertThat(c).isNotNull();
        assertThat(transport.liveSessions()).isEqualTo(2);
    }

    @Test
    void close_isIdempotent_releasesSlotExactlyOnce() {
        DeviceSshChannelFactory factory = mock(DeviceSshChannelFactory.class);
        Channel ch = mock(Channel.class);
        when(ch.output()).thenReturn(Flux.never());
        when(factory.open(anyString(), anyString(), anyString(), anyInt(), anyInt()))
                .thenReturn(Mono.just(ch));

        var transport = new SshDeviceTerminalTransport(factory, Duration.ZERO, 4, Schedulers.parallel());
        Session s = transport.open(DEVICE, HOST, OP, 80, 24).block();
        assertThat(transport.liveSessions()).isEqualTo(1);

        s.close();
        s.close(); // idempotent — must not double-decrement
        assertThat(transport.liveSessions()).isZero();
        verify(ch, times(1)).close();
    }

    // ──────────────────────── idle-timeout ──────────────────────────────────────

    @Test
    void idleTimeout_closesSessionAndCompletesOutput_afterIdle() {
        VirtualTimeScheduler vts = VirtualTimeScheduler.create();
        DeviceSshChannelFactory factory = mock(DeviceSshChannelFactory.class);
        Channel ch = mock(Channel.class);
        AtomicReference<Boolean> closed = new AtomicReference<>(false);
        // A shell that produces NO output (idle) — output never completes on its own.
        when(ch.output()).thenReturn(Flux.never());
        org.mockito.Mockito.doAnswer(inv -> {
            closed.set(true);
            return null;
        }).when(ch).close();
        when(factory.open(anyString(), anyString(), anyString(), anyInt(), anyInt()))
                .thenReturn(Mono.just(ch));

        Duration idle = Duration.ofSeconds(30);
        var transport = new SshDeviceTerminalTransport(factory, idle, 16, vts);
        Session s = transport.open(DEVICE, HOST, OP, 80, 24).block();

        // Before idle elapses the output stream stays open; after it elapses it COMPLETES.
        StepVerifier.withVirtualTime(s::output, () -> vts, Long.MAX_VALUE)
                .expectSubscription()
                .expectNoEvent(idle.minusSeconds(1))
                .thenAwait(idle.plusSeconds(2))
                .verifyComplete();

        assertThat(closed.get()).isTrue();
        assertThat(transport.liveSessions()).isZero();
    }

    @Test
    void idleTimeout_doesNotFire_whileOutputIsFlowing() {
        VirtualTimeScheduler vts = VirtualTimeScheduler.create();
        DeviceSshChannelFactory factory = mock(DeviceSshChannelFactory.class);
        Channel ch = mock(Channel.class);
        // Output every 5s for a while, then complete — activity keeps the idle guard from firing.
        when(ch.output()).thenReturn(
                Flux.interval(Duration.ofSeconds(5), vts).take(5).map(i -> ("x" + i).getBytes()));
        when(factory.open(anyString(), anyString(), anyString(), anyInt(), anyInt()))
                .thenReturn(Mono.just(ch));

        var transport = new SshDeviceTerminalTransport(factory, Duration.ofSeconds(30), 16, vts);
        Session s = transport.open(DEVICE, HOST, OP, 80, 24).block();

        // 5 chunks at 5s spacing (< 30s idle) all arrive, then natural completion — NOT an idle cut.
        StepVerifier.withVirtualTime(s::output, () -> vts, Long.MAX_VALUE)
                .expectSubscription()
                .thenAwait(Duration.ofSeconds(60))
                .expectNextCount(5)
                .verifyComplete();
    }

    // sanity: the scheduler ctor convenience path uses the bean properties.
    @Test
    void propertiesConstructor_usesIdleAndMaxFromProps() {
        DeviceTerminalProperties props = new DeviceTerminalProperties();
        props.setMaxSessions(1);
        props.setIdleTimeout(Duration.ZERO);
        DeviceSshChannelFactory factory = mock(DeviceSshChannelFactory.class);
        Channel ch = mock(Channel.class);
        when(ch.output()).thenReturn(Flux.never());
        when(factory.open(anyString(), anyString(), anyString(), anyInt(), anyInt()))
                .thenReturn(Mono.just(ch));

        var transport = new SshDeviceTerminalTransport(factory, props);
        assertThat(transport.open(DEVICE, HOST, OP, 80, 24).block()).isNotNull();
        StepVerifier.create(transport.open(DEVICE, HOST, OP, 80, 24))
                .expectError(SshDeviceTerminalTransport.MaxSessionsExceededException.class)
                .verify();
    }

    @SuppressWarnings("unused")
    private static Scheduler unused() {
        return null;
    }
}
