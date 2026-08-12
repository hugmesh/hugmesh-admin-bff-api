package net.hugmesh.adminbff.workload;

/**
 * Raised by a {@link WorkloadClient} when the backing k8s client is ABSENT (the fail-closed
 * {@link NoopWorkloadClient} seam) or a k8s call errors. The controllers map this to a 503
 * (NoopWorkloadClient — never an empty 200) or a 502 (a real k8s error), NEVER coerced to an
 * ALLOW / empty success. {@link #unavailable} marks the deliberate no-client state (503);
 * any other instance is a runtime k8s failure (502).
 */
public final class WorkloadClientException extends RuntimeException {

    private final boolean unavailable;

    private WorkloadClientException(String message, boolean unavailable, Throwable cause) {
        super(message, cause);
        this.unavailable = unavailable;
    }

    /** The deliberate fail-closed no-client seam (maps to 503). */
    public static WorkloadClientException unavailable(String message) {
        return new WorkloadClientException(message, true, null);
    }

    /** A runtime k8s failure (maps to 502). */
    public static WorkloadClientException failed(String message, Throwable cause) {
        return new WorkloadClientException(message, false, cause);
    }

    public boolean isUnavailable() {
        return unavailable;
    }
}
