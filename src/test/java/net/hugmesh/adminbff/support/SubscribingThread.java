package net.hugmesh.adminbff.support;

import java.util.concurrent.atomic.AtomicReference;

/**
 * Subscribe to a {@code Mono} from a thread with a KNOWN, distinctive name, so a test can assert
 * that the work actually moved OFF it.
 *
 * <p>This is how the {@code boundedElastic} offloads in the k8s seams and in the two Job
 * orchestrators are pinned. Asserting only "the work ran on a boundedElastic thread" is weaker
 * than it looks when the test itself already runs on {@code main}; naming the subscribing thread
 * makes the assertion say the real thing — <em>the blocking work did not run on the thread that
 * subscribed</em>, which in production is an R2DBC/Netty event loop.
 */
public final class SubscribingThread {

    /** The stand-in for the R2DBC/Netty event loop that subscribes in production. */
    public static final String NAME = "pretend-r2dbc-event-loop";

    private SubscribingThread() {
    }

    /**
     * Run {@code body} (typically a {@code mono.block()}) on a thread named {@link #NAME} and
     * wait for it. Any throwable the body raises is rethrown to the calling test thread, so
     * {@code assertThatThrownBy} still works around this helper.
     */
    public static void run(ThrowingRunnable body) throws Throwable {
        AtomicReference<Throwable> failure = new AtomicReference<>();
        Thread t = new Thread(() -> {
            try {
                body.run();
            } catch (Throwable e) {
                failure.set(e);
            }
        }, NAME);
        t.start();
        t.join(60_000);
        if (t.isAlive()) {
            t.interrupt();
            throw new AssertionError("subscription on '" + NAME + "' did not finish within 60s");
        }
        if (failure.get() != null) {
            throw failure.get();
        }
    }

    /** Like {@link #run} but wraps a raised throwable in an {@link AssertionError}. */
    public static void runExpectingSuccess(ThrowingRunnable body) {
        try {
            run(body);
        } catch (Throwable e) {
            throw new AssertionError("subscription on '" + NAME + "' failed", e);
        }
    }

    @FunctionalInterface
    public interface ThrowingRunnable {
        void run() throws Throwable;
    }
}
