package net.hugmesh.adminbff.web.dto;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.jspecify.annotations.Nullable;

import java.util.List;

/**
 * Body for {@code POST /bff/admin/image-builds/batch} — an ADMIN/SUPERADMIN worklist batch
 * trigger. This IS the frozen worklist v1 ENVELOPE ({@code {schema, base, entries}} per
 * {@code redesign/docs/schemas/worklist.v1.schema.json}) wrapped with a bounded-concurrency
 * knob:
 *
 * <ul>
 *   <li>{@code schema} — the mandatory version discriminator, MUST equal
 *       {@code hugmesh-worklist/v1} (a flat single-image ImageConfig carries NO schema key
 *       and is NOT accepted here — that is the single-trigger endpoint's shape).</li>
 *   <li>{@code base} — the shared {@code ImageConfig} (brand/org/domains/users/superdomain,
 *       CONTENT). Free-form JsonNode: NOT trusted, deep-validated by the fail-closed worklist.v1
 *       envelope validator BEFORE any write. Tenancy-bearing fields (cluster_domain/hostname)
 *       are SERVER-overwritten; a client can never pick a tenant.</li>
 *   <li>{@code entries} — 1..16 per-image {@link BatchImageSpec}s (one per role x platform).
 *       The {@code @Size} cap pairs with a HARD server-side {@code N<=16} re-assert: ONE
 *       step-up authorizes up to 16 real device images, so the bound is a security invariant,
 *       not a convenience.</li>
 *   <li>{@code maxConcurrent} — how many builds may launch at once, 1..16, DEFAULT 1
 *       (sequential). Bounds the blast radius of a single batch.</li>
 * </ul>
 */
public record BatchTriggerImageBuildRequest(

        @NotBlank(message = "schema is required")
        @Pattern(regexp = "hugmesh-worklist/v1",
                message = "schema must be hugmesh-worklist/v1")
        String schema,

        // The shared ImageConfig (CONTENT). Deep-validated by WorklistEnvelopeValidator; not a
        // frozen Java field set (the dataclass evolves — from_dict drops unknowns).
        @Nullable
        JsonNode base,

        @NotEmpty(message = "at least one entry is required")
        @Size(min = 1, max = 16, message = "a batch may build at most 16 images")
        @Valid
        List<BatchImageSpec> entries,

        @Nullable
        @Min(value = 1, message = "maxConcurrent must be at least 1")
        @Max(value = 16, message = "maxConcurrent must be at most 16")
        Integer maxConcurrent) {

    /** The hard upper bound on a batch — ONE step-up authorizes at most this many images.
     *  Enforced by {@code @Size(max=16)} here AND re-asserted server-side in the service. */
    public static final int MAX_ENTRIES = 16;

    /** Bounded launch concurrency, defaulting to 1 (sequential) when unset. */
    public int maxConcurrentOrDefault() {
        return maxConcurrent == null || maxConcurrent < 1 ? 1 : maxConcurrent;
    }
}
