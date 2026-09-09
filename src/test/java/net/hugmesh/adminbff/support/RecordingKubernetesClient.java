package net.hugmesh.adminbff.support;

import io.fabric8.kubernetes.client.KubernetesClient;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/**
 * A {@link KubernetesClient} stand-in that RECORDS its own lifecycle, so a seam expressed with
 * {@code Mono.usingWhen} can be asserted to actually CLOSE the client it acquired — the
 * always-closes guarantee try-with-resources used to give structurally and that the reactive
 * shape only gives if the cleanup arm is really wired.
 *
 * <p>Why a {@link Proxy} rather than a mock: {@code KubernetesClient} is an interface with a
 * very wide surface, but the seams only ever call a handful of methods on it and then
 * {@code close()}. Delegating everything to a real client (the fabric8 CRUD mock server's) keeps
 * the happy path genuinely exercised while still counting closes; {@link #failingWith} covers
 * the error arm without a server at all.
 *
 * <p>All counters are public and thread-safe on purpose: the seam runs on
 * {@code Schedulers.boundedElastic()}, so the assertions read them from a different thread than
 * the one that wrote them.
 */
public final class RecordingKubernetesClient implements InvocationHandler {

    /** The real client every non-close call is forwarded to; null for {@link #failingWith}. */
    private final KubernetesClient delegate;

    /** Thrown by every non-close call when {@link #delegate} is null. */
    private final RuntimeException failWith;

    private final KubernetesClient proxy;

    /** How many times {@code close()} was invoked. Exactly 1 is the contract. */
    public final AtomicInteger closeCount = new AtomicInteger();

    /** The thread name of the FIRST non-close use — i.e. where the blocking work ran. */
    public final AtomicReference<String> useThread = new AtomicReference<>();

    /** The thread name {@code close()} ran on. */
    public final AtomicReference<String> closeThread = new AtomicReference<>();

    private RecordingKubernetesClient(KubernetesClient delegate, RuntimeException failWith) {
        this.delegate = delegate;
        this.failWith = failWith;
        this.proxy = (KubernetesClient) Proxy.newProxyInstance(
                KubernetesClient.class.getClassLoader(),
                new Class<?>[]{KubernetesClient.class},
                this);
    }

    /** Forwards every call to {@code delegate} (a real client) and counts closes. */
    public static RecordingKubernetesClient delegatingTo(KubernetesClient delegate) {
        return new RecordingKubernetesClient(delegate, null);
    }

    /** Throws {@code boom} from every call EXCEPT close() — which must still happen. */
    public static RecordingKubernetesClient failingWith(RuntimeException boom) {
        return new RecordingKubernetesClient(null, boom);
    }

    /** The client handed to the seam under test. Stable identity across calls. */
    public KubernetesClient client() {
        return proxy;
    }

    @Override
    public Object invoke(Object self, Method method, Object[] args) throws Throwable {
        String name = method.getName();
        if (method.getParameterCount() == 0 && "close".equals(name)) {
            closeThread.set(Thread.currentThread().getName());
            closeCount.incrementAndGet();
            if (delegate != null) {
                delegate.close();
            }
            return null;
        }
        // Object methods must never reach the delegate/failure path: a toString() that throws
        // corrupts assertion messages, and equals/hashCode must follow proxy identity.
        if (method.getParameterCount() == 0 && "hashCode".equals(name)) {
            return System.identityHashCode(self);
        }
        if (method.getParameterCount() == 1 && "equals".equals(name)) {
            return self == args[0];
        }
        if (method.getParameterCount() == 0 && "toString".equals(name)) {
            return "RecordingKubernetesClient[closes=" + closeCount.get() + "]";
        }
        useThread.compareAndSet(null, Thread.currentThread().getName());
        if (delegate == null) {
            throw failWith;
        }
        try {
            return method.invoke(delegate, args);
        } catch (InvocationTargetException e) {
            throw e.getCause();
        }
    }
}
