package net.hugmesh.adminbff.web.dto;

import jakarta.validation.constraints.Size;
import org.jspecify.annotations.Nullable;

/**
 * Body for the SUPERADMIN GitOps-authoritative lifecycle verbs
 * ({@code POST /bff/superadmin/workloads/lifecycle/{namespace}/{workload}/{verb}}). These are
 * NOT live k8s mutations — they record a {@code workload_console_intent} (the UI surfaces
 * "pending sync"). selfHeal is law.
 *
 * <ul>
 *   <li>SCALE — {@code replicas} (start/stop = scale up/down).</li>
 *   <li>DEPLOY — {@code imageRef} MUST be digest-pinned own-registry ({@code @sha256:}).</li>
 *   <li>REMOVE_SERVICE — the most destructive op; {@code confirm} must equal the workload
 *       name (strong-confirm, DECISION 3).</li>
 *   <li>EXPORT_MANIFEST — no extra fields.</li>
 * </ul>
 */
public record WorkloadLifecycleRequest(
        @Nullable
        Integer replicas,

        @Nullable
        @Size(max = 512, message = "imageRef is too long")
        String imageRef,

        @Nullable
        @Size(max = 253, message = "confirm is too long")
        String confirm) {
}
