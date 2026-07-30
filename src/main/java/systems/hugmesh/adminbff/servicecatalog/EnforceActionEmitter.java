package systems.hugmesh.adminbff.servicecatalog;

import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/**
 * The enforce-action seam for the App-Store expiry loop. When a {@code service_deployment}
 * CASes {@code active -> ended} at its {@code ending_at} clock,
 * {@link ServiceDeploymentExpiryAction} hands the row's {@code enforce_actions} list here.
 *
 * <p><b>Ships DARK by default.</b> The real effect (ArgoCD Application delete + Casdoor role
 * revoke + route-access revoke) is delegated to {@link AddServiceEffector#teardown}, whose
 * ArgoCD leg is itself gated by {@code app.appstore.effector.enabled}. When the effector is
 * DISABLED (the default) the teardown runs against the {@code NoopArgoCdClient} — so it logs
 * the intent and makes NO real ArgoCD mutation, byte-equivalent to the original
 * log-only behaviour. When the effector is ENABLED the SAME seam performs the real teardown
 * for the {@code teardown}/{@code revoke-*} actions. The controller + data layer never change.
 *
 * <p>The injected {@link AddServiceEffector} is {@link Nullable} only for the legacy unit-test
 * seam (the no-arg constructor) that asserts pure log-only emission; the production wiring
 * always supplies it.
 */
@Component
public class EnforceActionEmitter {

    private static final Logger log = LoggerFactory.getLogger(EnforceActionEmitter.class);

    /** Enforce-action tokens that drive the real {@link AddServiceEffector#teardown} when the
     *  effector is enabled. {@code alert} (and any unknown token) stays a logged emission. */
    static final java.util.Set<String> TEARDOWN_ACTIONS =
            java.util.Set.of("teardown", "revoke-roles", "revoke-certs", "revoke");

    @Nullable
    private final AddServiceEffector effector;

    // The package-private no-arg test seam makes this a multi-constructor bean, so Spring
    // no longer auto-selects the injection constructor — mark it explicitly (the
    // constructor the container already uses in prod). Behaviorally inert.
    @Autowired
    public EnforceActionEmitter(@Nullable AddServiceEffector effector) {
        this.effector = effector;
    }

    /** Legacy test seam — a log-only emitter with no effector wired. */
    EnforceActionEmitter() {
        this(null);
    }

    /**
     * Emit the enforce actions for an ended deployment. Returns the COUNT of actions emitted.
     * A teardown/revoke action drives {@link AddServiceEffector#teardown} (real ONLY when the
     * effector is enabled; a logged no-op otherwise); other actions (e.g. {@code alert}) are
     * logged. An empty/blank list emits nothing. The teardown is run AT MOST ONCE per emit
     * even when several teardown/revoke tokens are present (they describe one teardown).
     */
    public Mono<Integer> emit(ServiceDeployment deployment) {
        String[] actions = parse(deployment.enforceActions());
        boolean teardownRequested = false;
        for (String action : actions) {
            if (TEARDOWN_ACTIONS.contains(action.toLowerCase())) {
                teardownRequested = true;
            } else {
                log.info("[deployment-expiry] emit enforce action '{}' for deployment id={} "
                                + "service={} domain={} (no teardown effect)",
                        action, deployment.id(), deployment.serviceKey(), deployment.domain());
            }
        }
        Mono<Void> teardown = (teardownRequested && effector != null)
                ? effector.teardown(deployment).doOnSubscribe(s -> log.info(
                        "[deployment-expiry] teardown for id={} service={} domain={} (effectorEnabled={})",
                        deployment.id(), deployment.serviceKey(), deployment.domain(),
                        effector.effectorEnabled()))
                : Mono.empty();
        return teardown.thenReturn(actions.length);
    }

    /** Split the opaque enforce_actions list (comma/whitespace separated; tolerates a JSON
     *  array literal like {@code ["teardown","alert"]}) into trimmed, non-blank tokens. */
    static String[] parse(String enforceActions) {
        if (enforceActions == null || enforceActions.isBlank()) {
            return new String[0];
        }
        String cleaned = enforceActions
                .replace("[", " ").replace("]", " ")
                .replace("\"", " ").replace("'", " ");
        String[] raw = cleaned.split("[,\\s]+");
        return java.util.Arrays.stream(raw)
                .map(String::trim)
                .filter(s -> !s.isBlank())
                .toArray(String[]::new);
    }
}
