package net.hugmesh.adminbff.optionalservices;

/**
 * The typed failure of an {@link OptionalServiceClient#setEnabled} spec write — the ONE seam
 * through which the superadmin toggle surface learns that a write did NOT happen.
 *
 * <p>Every other call in this package is best-effort and swallows its errors to a
 * {@code false}/empty return, because the reconcile tick must never die. A superadmin PUT is
 * the opposite: a toggle that did not land MUST be reported, or the endpoint becomes another
 * silently-inert control. So the spec write throws, carrying a {@link Kind} the
 * {@link OptionalServiceAdminService} maps to an HTTP status:
 *
 * <ul>
 *   <li>{@link Kind#NOT_WIRED} — the {@link NoopOptionalServiceClient} is in force
 *       ({@code app.optional-services.reconcile.enabled=false}, the shipped default). There is
 *       no cluster to write to; the surface answers 503 with a {@code dark:true} descriptor
 *       rather than pretending the toggle took.</li>
 *   <li>{@link Kind#REJECTED} — the API server refused the object (4xx), e.g. a slug outside
 *       the CRD {@code spec.slug} enum or a CEL immutability violation. 422.</li>
 *   <li>{@link Kind#FAILED} — a transport/5xx/conflict failure. 503; retry.</li>
 * </ul>
 */
public class OptionalServiceWriteException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /** Why the spec write did not land. */
    public enum Kind {
        /** No real cluster client is wired (the reconciler ships dark). */
        NOT_WIRED,
        /** The API server rejected the object (4xx) — e.g. the slug is not in the CRD enum. */
        REJECTED,
        /** The write could not be completed (transport, 5xx, optimistic-concurrency conflict). */
        FAILED
    }

    private final Kind kind;

    public OptionalServiceWriteException(Kind kind, String message) {
        super(message);
        this.kind = kind;
    }

    public OptionalServiceWriteException(Kind kind, String message, Throwable cause) {
        super(message, cause);
        this.kind = kind;
    }

    public Kind kind() {
        return kind;
    }
}
