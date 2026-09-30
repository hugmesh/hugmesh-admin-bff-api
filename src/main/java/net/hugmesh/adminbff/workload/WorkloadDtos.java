package net.hugmesh.adminbff.workload;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The PROJECTED workload DTOs returned to the UI. DELIBERATELY MINIMAL — the inspect DTO
 * carries NO env / annotations / managedFields / secrets (a projection, never the raw k8s
 * object) so the read surface cannot leak secret material or cross-tier metadata.
 */
public final class WorkloadDtos {

    private WorkloadDtos() {
    }

    /** A projected pod summary (the ps/ls view). */
    public record PodSummary(
            String namespace,
            String name,
            String workload,
            String phase,
            boolean ready,
            int restarts,
            String node,
            Instant startedAt,
            List<ContainerSummary> containers) {

        public PodSummary {
            containers = containers == null ? null : Collections.unmodifiableList(new ArrayList<>(containers));
        }
    }

    /** A projected container summary. */
    public record ContainerSummary(
            String name,
            String image,
            boolean ready,
            int restarts,
            String state) {
    }

    /** A projected, redacted pod inspect (NO env / annotations / managedFields). */
    public record PodInspect(
            String namespace,
            String name,
            String workload,
            String phase,
            String node,
            String serviceAccount,
            Instant startedAt,
            List<ContainerSummary> containers,
            Map<String, String> labels,
            String ownerKind,
            String ownerName) {

        public PodInspect {
            containers = containers == null ? null : Collections.unmodifiableList(new ArrayList<>(containers));
            labels = labels == null ? null : Collections.unmodifiableMap(new LinkedHashMap<>(labels));
        }
    }

    /** A single log line for the SSE live-tail (secret-redacted server-side). */
    public record LogLine(
            String container,
            String line,
            Instant ts) {
    }

    /** Coarse pod/container metrics (the stats view). */
    public record PodMetrics(
            String namespace,
            String name,
            String cpuMillicores,
            String memoryBytes) {
    }

    /** A namespace-filtered event row (the events view). */
    public record WorkloadEvent(
            String namespace,
            String type,
            String reason,
            String object,
            String message,
            Instant lastSeen,
            int count) {
    }

    /** A projected PVC / volume row (own-domain). */
    public record VolumeSummary(
            String namespace,
            String name,
            String phase,
            String capacity,
            String storageClass,
            List<String> accessModes) {

        public VolumeSummary {
            accessModes = accessModes == null ? null : Collections.unmodifiableList(new ArrayList<>(accessModes));
        }
    }

    /** A projected NetworkPolicy / Service / HTTPRoute view row. */
    public record NetworkSummary(
            String namespace,
            String kind,
            String name,
            String summary) {
    }

    /** The result of a one-shot read-only exec (non-TTY). */
    public record ExecResult(
            int exitCode,
            String stdout,
            String stderr) {
    }
}
