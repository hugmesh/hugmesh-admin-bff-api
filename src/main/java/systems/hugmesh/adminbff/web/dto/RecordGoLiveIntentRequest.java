package systems.hugmesh.adminbff.web.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.jspecify.annotations.Nullable;

/**
 * Body for {@code POST /bff/admin/go-live/intents} (SUPERADMIN + step-up) — records ONE
 * go-live (or roll-back-internal) INTENT in the {@code go_live_intent} ledger (schema 270).
 * The {@code @NotBlank}/{@code @Size} guards make a malformed request a clean 400 (mapped by
 * {@link systems.hugmesh.adminbff.web.ValidationExceptionHandler}) BEFORE any write; the
 * vocabulary checks (targetState / exposureModel / provider-catalog agreement) are enforced
 * in {@link systems.hugmesh.adminbff.golive.GoLiveService}.
 *
 * <p><b>NO SECRETS.</b> There is deliberately NO field for a tunnel/DNS/DDNS token — the
 * wizard routes secret material to the keys-USB/Vault paths on the generator side, never
 * through the admin BFF.
 *
 * <ul>
 *   <li>{@code clusterDomain} — the brand's base domain the intent targets. REQUIRED.</li>
 *   <li>{@code targetState} — {@code public} (go live) | {@code internal} (roll back);
 *       the host RELEASE_STATE vocabulary. REQUIRED.</li>
 *   <li>{@code exposureModel} — {@code tunnel} | {@code public_dns} | {@code funnel};
 *       REQUIRED to go public, ABSENT on a roll-back intent.</li>
 *   <li>{@code provider} — a {@code GoLiveProviderCatalog} KEY (e.g.
 *       {@code cloudflare-tunnel}); must serve the chosen exposureModel. REQUIRED to go
 *       public, ABSENT on a roll-back intent.</li>
 *   <li>{@code note} — optional non-secret operator note for the wizard history.</li>
 * </ul>
 */
public record RecordGoLiveIntentRequest(
        @NotBlank(message = "clusterDomain is required")
        @Size(max = 253, message = "clusterDomain is too long")
        String clusterDomain,

        @NotBlank(message = "targetState is required ('public' or 'internal')")
        @Size(max = 16, message = "targetState is too long")
        String targetState,

        @Size(max = 32, message = "exposureModel is too long")
        @Nullable
        String exposureModel,

        @Size(max = 64, message = "provider is too long")
        @Nullable
        String provider,

        @Size(max = 512, message = "note is too long")
        @Nullable
        String note) {
}
