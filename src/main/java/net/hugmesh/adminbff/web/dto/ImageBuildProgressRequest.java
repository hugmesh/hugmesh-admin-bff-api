package net.hugmesh.adminbff.web.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Size;
import org.jspecify.annotations.Nullable;

/**
 * Body the IN-CLUSTER image-gen Job's progress tap
 * ({@code docker/progress-tap.py} / {@code docker/build-image.sh}'s {@code progress_tap_run},
 * hugmesh-generator repo) POSTs to
 * {@code POST /bff/internal/image-builds/{id}/progress} to report NON-TERMINAL progress while a
 * build runs. This is DISJOINT from the terminal {@code /ingest} leg: 0..N progress posts may
 * precede the single terminal {@code /ingest} that closes the build. A progress post fans an
 * SSE {@code progress} frame ({@code done=false}) and NEVER closes the sink or stamps
 * {@code finished_at}.
 *
 * <p><b>DESIGN NOTE (contract fix).</b> This record previously modelled a hypothetical
 * {@code percent}/{@code phase}/{@code message} shape that predates the worker that actually
 * ships it. The REAL producer is {@code docker/progress-tap.py}'s {@code _frame()}, which reuses
 * the vendored {@code hugmesh_studio.core.progress_parse.ProgressParser} and always emits
 * {@code buildId}/{@code percent}(nullable)/{@code phaseIndex}/{@code phaseCount}/
 * {@code phaseLabel}/{@code indeterminate} — this record now mirrors THAT shape exactly so a
 * real build's progress posts stop failing bean validation. {@code buildId} is intentionally
 * NOT a field here (same as {@link ImageBuildIngestRequest}, whose body also carries no
 * redundant id) — the path {@code {id}} stays authoritative; {@code @JsonIgnoreProperties}
 * tolerates that (and any other additive) field defensively, matching the
 * {@code ResolvedFindingDto} / {@code ModerationDecisionDto} convention for external-producer
 * payloads rather than relying on Spring's default unknown-property leniency.
 *
 * <p><b>NO-SECRET CONTRACT.</b> Like the terminal ingest, this body carries only non-secret
 * status text — no artifact bytes, no keys. Only public pointers ride the wire: a build id
 * (path only) and phase integers/label, never a key or path.
 *
 * <ul>
 *   <li>{@code percent} — coarse progress 0..99, or {@code null} while INDETERMINATE (no
 *       {@code ==>} phase banner matched yet). Never 100 — the terminal {@code /ingest} owns
 *       100.</li>
 *   <li>{@code phaseIndex} — 0-based index into the platform's phase table, or {@code -1}
 *       before the first matched banner.</li>
 *   <li>{@code phaseCount} — total phases in the platform's table.</li>
 *   <li>{@code phaseLabel} — the human phase label ({@code ""} before the first banner).</li>
 *   <li>{@code indeterminate} — {@code true} iff {@code percent} is {@code null}.</li>
 * </ul>
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ImageBuildProgressRequest(

        @Min(value = 0, message = "percent must be >= 0")
        @Max(value = 99, message = "percent must be <= 99 (100 is the terminal frame)")
        @Nullable
        Integer percent,

        int phaseIndex,

        int phaseCount,

        @Size(max = 128, message = "phaseLabel is too long")
        @Nullable
        String phaseLabel,

        boolean indeterminate) {
}
