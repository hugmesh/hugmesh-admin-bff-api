package systems.hugmesh.adminbff.profile;

import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import systems.hugmesh.authcore.casdoor.CasdoorAdminClient;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Forwards a freshly-registered principal's {@code displayName} (UTF-8) +
 * {@code screenReaderName} (ASCII aria-label) to the hugmesh-user-bff profile
 * service so the a11y spoken name is recorded at registration time (the
 * {@code screen_reader_name} column already exists on the user-bff
 * {@code user_profile} table). The login-ui already collects + sends both names; the
 * admin-bff is the registration entry point, so it is the natural place to push them
 * across.
 *
 * <h3>GATED STUB-SEAM (mirrors {@code FederationUsernameClient} /
 * {@code HomeserverAdminClient} / {@code PhpbbAdminClient})</h3>
 * <ul>
 *   <li>the reactive {@link WebClient} is ALWAYS built + injected non-null so the
 *       {@link systems.hugmesh.adminbff.AuthController} has a real collaborator;</li>
 *   <li>gated by {@code profile.forward.enabled} (default false) so a user-bff-less
 *       dev/test/CI run boots clean — when DISABLED the forwarder short-circuits to
 *       a no-op WITHOUT a call;</li>
 *   <li>BEST-EFFORT + fail-OPEN: a profile forward is an enrichment, NOT a gate, so a
 *       transport/parse error is logged and swallowed — it MUST NEVER fail
 *       registration (the account + session are already durable). The user-bff is the
 *       source of truth for the deep displayName/screenReaderName validation on
 *       receipt; an invalid name is rejected THERE, not here.</li>
 * </ul>
 *
 * <p>The user-bff profile endpoint is owner-scoped to the JWT subject; this internal
 * registration forward carries a config-driven internal service credential (an
 * {@code X-Internal-Token} header) + the registered owner id, so the user-bff can
 * attribute the write to the right owner. The exact internal contract is wired in the
 * deployment once the user-bff exposes the internal upsert; until then the seam stays
 * gated off (config-only flip, no code change).
 */
public class ProfileForwarder {

    private static final Logger log = LoggerFactory.getLogger(ProfileForwarder.class);

    private final WebClient http;
    private final boolean enabled;
    private final String path;
    private final String internalTokenHeader;
    private final String internalToken;
    /**
     * OPTIONAL Casdoor admin write client — {@code null} when {@code casdoor.admin.enabled=false}
     * (Casdoor-less / unit run). When present, a present {@code displayName} is ALSO written to
     * the registering subject's Casdoor user object (the human-visible name) via the
     * sibling-preserving GET-then-MERGE + {@code &columns=display_name} primitive. This is the
     * Casdoor leg of registration display-name forwarding; it is independent of the user-bff
     * forward gate ({@code profile.forward.enabled}) so the Casdoor name lands even when the
     * user-bff profile-upsert seam is still dark. Best-effort: never fails registration.
     */
    @Nullable
    private final CasdoorAdminClient casdoor;

    public ProfileForwarder(WebClient http, boolean enabled, String path,
                            String internalTokenHeader, String internalToken,
                            @Nullable CasdoorAdminClient casdoor) {
        this.http = http;
        this.enabled = enabled;
        this.path = path;
        this.internalTokenHeader = internalTokenHeader;
        this.internalToken = internalToken;
        this.casdoor = casdoor;
    }

    public boolean enabled() {
        return enabled;
    }

    /**
     * Forward the names for {@code ownerId} (the registered account id = the
     * user-bff profile owner). No-op when the gate is off or both names are
     * absent. Fail-OPEN on any error: registration is never failed by a profile
     * forward. Returns a {@code Mono<Void>} that always completes empty.
     */
    public Mono<Void> forward(String ownerId, String displayName, String screenReaderName) {
        boolean noNames = (displayName == null || displayName.isBlank())
                && (screenReaderName == null || screenReaderName.isBlank());
        if (noNames || ownerId == null || ownerId.isBlank()) {
            return Mono.empty();
        }
        // Casdoor displayName leg: independent of the user-bff forward gate so the
        // human-visible Casdoor name lands even when the user-bff profile-upsert seam is
        // still dark. Best-effort + fail-OPEN inside the client (never fails registration).
        Mono<Void> casdoorLeg = forwardCasdoorDisplayName(ownerId, displayName);
        if (!enabled) {
            // user-bff forward seam is dark — only the Casdoor leg runs.
            return casdoorLeg;
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("ownerId", ownerId);
        if (displayName != null && !displayName.isBlank()) body.put("displayName", displayName);
        if (screenReaderName != null && !screenReaderName.isBlank()) {
            body.put("screenReaderName", screenReaderName);
        }
        return http.post()
                .uri(path)
                .headers(h -> {
                    if (internalToken != null && !internalToken.isBlank()) {
                        h.set(internalTokenHeader, internalToken);
                    }
                })
                .bodyValue(body)
                .retrieve()
                .toBodilessEntity()
                .doOnSuccess(r -> log.info("[profile-forward] recorded a11y names for {}", ownerId))
                .onErrorResume(e -> {
                    // FAIL-OPEN: enrichment only — never fail registration.
                    log.warn("[profile-forward] best-effort forward for {} failed (registration kept): {}",
                            ownerId, e.toString());
                    return Mono.empty();
                })
                .then()
                // Run the Casdoor displayName leg after the user-bff forward (both best-effort).
                .then(casdoorLeg);
    }

    /**
     * Write the registration {@code displayName} to the registering subject's Casdoor user
     * object. {@code ownerId} is the {@code provider:handle} account id (see
     * {@code AccountStore.idFor}); we split it back to {@code provider} + {@code handle} so the
     * Casdoor username is derived the SAME way the invite-time {@code ensureUser} derived it.
     * No-op when no Casdoor client is wired or {@code displayName} is blank. The owner is ALWAYS
     * the registering subject — there is no caller-supplied target, so a display name can never
     * be written for another user. Best-effort + fail-OPEN inside the client.
     */
    private Mono<Void> forwardCasdoorDisplayName(String ownerId, String displayName) {
        if (casdoor == null || displayName == null || displayName.isBlank()) {
            return Mono.empty();
        }
        int colon = ownerId.indexOf(':');
        if (colon < 0) return Mono.empty();
        String provider = ownerId.substring(0, colon);
        String handle = ownerId.substring(colon + 1);
        if (provider.isBlank() || handle.isBlank()) return Mono.empty();
        return casdoor.updateDisplayName(provider, handle, displayName)
                .doOnSuccess(v -> log.info("[profile-forward] recorded Casdoor displayName for {}", ownerId))
                .onErrorResume(e -> {
                    log.warn("[profile-forward] best-effort Casdoor displayName for {} failed "
                            + "(registration kept): {}", ownerId, e.toString());
                    return Mono.empty();
                });
    }
}
