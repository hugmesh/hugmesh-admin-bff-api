package net.hugmesh.adminbff.workload;

import net.hugmesh.commons.web.ApiException;

/**
 * Shared error mapping for the WORKLOAD CONSOLE controllers. A {@link WorkloadClientException}
 * maps to an EXPLICIT 503 (the fail-closed Noop seam — never an empty 200) or 502 (a real k8s
 * failure), NEVER coerced to a success.
 */
public final class WorkloadErrors {

    private WorkloadErrors() {
    }

    public static RuntimeException map(Throwable t) {
        if (t instanceof ApiException ae) {
            return ae;
        }
        if (t instanceof WorkloadClientException wce) {
            return wce.isUnavailable()
                    ? ApiException.serviceUnavailable(wce.getMessage())
                    : ApiException.badGateway(wce.getMessage());
        }
        if (t instanceof WorkloadStepUpService.StepUpDeniedException
                || t instanceof WorkloadExecService.ExecDeniedException) {
            return ApiException.forbidden(t.getMessage());
        }
        if (t instanceof IllegalArgumentException) {
            return ApiException.unprocessable(t.getMessage());
        }
        return ApiException.badGateway(t.getMessage() == null ? "workload console error" : t.getMessage());
    }
}
