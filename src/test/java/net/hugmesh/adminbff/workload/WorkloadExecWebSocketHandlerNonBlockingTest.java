package net.hugmesh.adminbff.workload;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.web.reactive.socket.HandshakeInfo;
import org.springframework.web.reactive.socket.WebSocketMessage;
import org.springframework.web.reactive.socket.WebSocketSession;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.net.URI;
import java.security.Principal;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * {@code handle()} must never block — it is invoked on the Netty event loop.
 *
 * <p>The handler used to resolve the principal with
 * {@code session.getHandshakeInfo().getPrincipal()...block()}. Reactor's {@code block()}
 * checks {@code Schedulers.isInNonBlockingThread()} and throws <em>before</em> it looks at
 * whether a value is already available, so an eagerly-resolved principal did not save it:
 * every upgrade on {@code /exec-tty/} raised
 * {@code IllegalStateException: block()/blockFirst()/blockLast() are blocking, which is not
 * supported in thread reactor-http-nio-N}. The handler carried NO tests at all, which is
 * exactly why it survived.
 *
 * <p>These tests run {@code handle()} on {@link Schedulers#parallel()}, whose workers
 * implement Reactor's {@code NonBlocking} marker — the same property the event loop has, and
 * the one {@code block()} refuses.
 *
 * <p><b>What counts as proof.</b> The handler ends in {@code onErrorResume(... session.close())},
 * so a downstream failure never escapes {@code handle()} — "nothing was thrown" is therefore
 * far too weak a signal, and would pass even if the handler had given up early. Each test
 * instead verifies that {@code openTty} was reached <em>with the resolved actor</em>, which can
 * only happen if the principal was resolved without blocking, and separately fails loudly if
 * Reactor's blocking guard fired.
 */
class WorkloadExecWebSocketHandlerNonBlockingTest {

    private static final URI EXEC_URI =
            URI.create("http://bff/bff/superadmin/workloads/exec-tty/ns-a/pod-b?container=app");

    /** The exec service used by the most recent {@link #handleOnNonBlockingThread} call. */
    private WorkloadExecService exec;

    private WebSocketSession sessionWithPrincipal(Mono<Principal> principal) {
        HandshakeInfo hi = new HandshakeInfo(EXEC_URI, new HttpHeaders(), principal, null);
        WebSocketSession session = mock(WebSocketSession.class);
        when(session.getHandshakeInfo()).thenReturn(hi);
        when(session.receive()).thenReturn(Flux.empty());
        when(session.send(any())).thenReturn(Mono.empty());
        when(session.close()).thenReturn(Mono.empty());
        when(session.textMessage(anyString())).thenReturn(mock(WebSocketMessage.class));
        return session;
    }

    /**
     * The sentinel the stubbed TTY open fails with. Deliberately NOT an
     * {@link IllegalStateException}: that is the type Reactor throws for a blocking call, and
     * reusing it would leave the assertions unable to tell "the handler blocked" from "my own
     * stub errored".
     */
    private static final class NoClusterHere extends RuntimeException {
        NoClusterHere() {
            super("no cluster in this test");
        }
    }

    private WorkloadExecService execServiceThatFailsToOpen() {
        WorkloadExecService svc = mock(WorkloadExecService.class);
        when(svc.newTranscript(anyString(), anyString()))
                .thenReturn(mock(WorkloadExecService.Transcript.class));
        // Opening the TTY is out of scope: the assertion is about the THREAD, not k8s.
        when(svc.openTty(anyString(), anyString(), anyString(), any(), any()))
                .thenReturn(Mono.error(new NoClusterHere()));
        when(svc.rescheduleAfter(anyString(), anyString())).thenReturn(Mono.empty());
        return svc;
    }

    /** Runs handle() to completion on a Reactor NonBlocking worker. */
    private Throwable handleOnNonBlockingThread(Mono<Principal> principal) {
        exec = execServiceThatFailsToOpen();
        WorkloadExecWebSocketHandler handler =
                new WorkloadExecWebSocketHandler(exec, new ObjectMapper());
        WebSocketSession session = sessionWithPrincipal(principal);
        AtomicReference<Throwable> escaped = new AtomicReference<>();

        Mono.fromCallable(() -> {
                    // Assert the premise: without this the test could pass on a blocking thread.
                    assertThat(Schedulers.isInNonBlockingThread())
                            .as("this must run on a NonBlocking worker or it proves nothing")
                            .isTrue();
                    return handler.handle(session);
                })
                .subscribeOn(Schedulers.parallel())
                .flatMap(m -> m)
                .onErrorResume(e -> {
                    escaped.set(e);
                    return Mono.empty();
                })
                .block();   // test-side only; the assertion is about the handler's thread
        return escaped.get();
    }

    /** Reactor's blocking guard, matched on its own text so no other ISE is mistaken for it. */
    private void assertBlockingGuardDidNotFire(Throwable t) {
        if (t instanceof IllegalStateException && String.valueOf(t.getMessage()).contains("are blocking")) {
            throw new AssertionError("handle() called block() on a non-blocking thread: " + t.getMessage());
        }
    }

    @Test
    void handle_resolvesThePrincipalWithoutBlocking() {
        Principal p = () -> "admin@brandx.example";
        assertBlockingGuardDidNotFire(handleOnNonBlockingThread(Mono.just(p)));
        // Reaching openTty with the resolved name is the positive proof: it cannot happen
        // unless the principal was resolved, on this non-blocking worker, without block().
        verify(exec).openTty(eq("admin@brandx.example"), eq("ns-a"), eq("pod-b"), any(), any());
    }

    @Test
    void handle_fallsBackToSuperadminWithoutBlocking_whenThePrincipalIsAbsent() {
        // The empty case is what the old `actor == null -> "superadmin"` fallback covered, and
        // block() on an EMPTY Mono is where a non-blocking thread bites hardest.
        assertBlockingGuardDidNotFire(handleOnNonBlockingThread(Mono.empty()));
        verify(exec).openTty(eq("superadmin"), eq("ns-a"), eq("pod-b"), any(), any());
    }
}
