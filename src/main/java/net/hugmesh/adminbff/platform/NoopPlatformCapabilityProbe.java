package net.hugmesh.adminbff.platform;

import java.util.List;

/**
 * The DEFAULT, fail-closed probe used whenever the k8s seam is not enabled
 * ({@code app.platform-capabilities.k8s.enabled} unset/false) — cluster-less dev/test/CI, or any
 * deployment that has deliberately not opted into the in-cluster read. It dials NOTHING and
 * reports every runtime capability ABSENT, with a single warning so the UI can explain WHY the
 * infra-dependent consoles are gated off (the platform-capability probe is not wired on this
 * deployment) rather than faking a {@code true}.
 */
public class NoopPlatformCapabilityProbe implements PlatformCapabilityProbe {

    static final String NOT_WIRED_WARNING =
            "Platform-capability k8s probe is not enabled on this deployment "
            + "(app.platform-capabilities.k8s.enabled=false); ArgoCD / Velero / build-node "
            + "presence cannot be detected and are reported absent.";

    @Override
    public boolean isReal() {
        return false;
    }

    @Override
    public Result probe() {
        return new Result(false, false, false, List.of(NOT_WIRED_WARNING));
    }
}
