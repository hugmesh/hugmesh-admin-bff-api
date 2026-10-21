package net.hugmesh.adminbff.optionalservices;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The SUPERADMIN control surface's service half: the optional-service CATALOGUE (read) and the
 * runtime TOGGLE (write) behind {@code /bff/superadmin/optional-services}. Clones the
 * {@code backingservices.BackingServiceService} posture — reads stay live while the effector is
 * dark so the console renders honestly, and the mutating verb refuses EARLY with a typed
 * exception the controller maps to a status.
 *
 * <h3>The whole point: no silent no-ops</h3>
 * Every path that cannot actuate says so, by name, at the HTTP boundary:
 * <ul>
 *   <li>a slug the platform has never heard of -> {@link UnknownSlugException} (404);</li>
 *   <li>a slug the platform KNOWS but the reconciler cannot action
 *       ({@code workloadConsole}, {@code headwind} and {@code attestation-server} today, all
 *       {@code NO_APPLICATIONSET_ELEMENT}; {@code meshbridge} was refused here as
 *       {@code NOT_IN_CRD_ENUM} until #106 made it managed) -> {@link NotToggleableException}
 *       (422) carrying the registry's NAMED {@link OptionalServiceRegistry.NotToggleable}
 *       reason. The write is never attempted;</li>
 *   <li>the reconciler wired to no cluster ({@code app.optional-services.reconcile.enabled=false},
 *       the shipped default) -> {@link OptionalServiceWriteException.Kind#NOT_WIRED} (503,
 *       {@code dark:true}). Nothing is written and nothing claims to have been;</li>
 *   <li>a slug whose greying key is missing from {@code apps/16}'s {@code ignoreDifferences}
 *       toggles for real on the ApplicationSet side but has its ConfigMap mirror selfHealed
 *       back — reported as a {@code warnings} entry on BOTH the catalogue row and the toggle
 *       response, never swallowed. No managed slug has that gap today: {@code character-forge}
 *       was flagged until #106, but generator apps/16 carries its pointer, and
 *       {@code OptionalServiceRegistryParityTest} pins the (now empty) set against the vendored
 *       apps/16. The path stays for the next slug that gains a 13a element before its
 *       pointer.</li>
 * </ul>
 * This is the direct answer to the defect that motivated the surface: {@code character-forge}
 * was accepted by the API server, reported {@code enabled: true} by {@code kubectl}, and
 * actuated NOTHING, with no trace anywhere.
 *
 * <p>The fabric8 calls are blocking, so they run on {@code boundedElastic} — the same reactive
 * boundary {@link OptionalServiceReconciler} uses.
 */
@Service
public class OptionalServiceAdminService {

    private static final Logger log = LoggerFactory.getLogger(OptionalServiceAdminService.class);

    private final OptionalServiceRegistry registry;
    private final OptionalServiceClient client;

    public OptionalServiceAdminService(OptionalServiceRegistry registry, OptionalServiceClient client) {
        this.registry = registry;
        this.client = client;
    }

    /** True when a real cluster client is wired (i.e. a toggle here can actually land). */
    public boolean isReconcilerWired() {
        return client.isReal();
    }

    // ── catalogue (read; live even while the reconciler is dark) ─────────────────────

    /**
     * Every slug the PLATFORM knows — managed AND not-toggleable — joined with the live CR
     * state. A slug the registry cannot reconcile is reported as {@code toggleable:false} with
     * its named reason; it is NEVER listed as though it worked.
     */
    public Mono<Map<String, Object>> catalogue() {
        return Mono.fromCallable(this::catalogueBlocking).subscribeOn(Schedulers.boundedElastic());
    }

    private Map<String, Object> catalogueBlocking() {
        Map<String, OptionalServiceCr> crs = new LinkedHashMap<>();
        for (OptionalServiceCr cr : client.listDesired()) {
            crs.put(cr.slug(), cr);
        }

        List<Map<String, Object>> services = new ArrayList<>();
        for (String slug : registry.knownSlugs()) {
            services.add(row(slug, crs.get(slug)));
        }

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("reconcilerEnabled", client.isReal());
        out.put("services", services);
        out.put("note", note());
        return out;
    }

    /** One catalogue row: the registry facts + the CR's desired state + honest warnings. */
    private Map<String, Object> row(String slug, OptionalServiceCr cr) {
        OptionalServiceRegistry.NotToggleable blocked = registry.notToggleableReason(slug);
        OptionalServiceRegistry.Entry entry = registry.entry(slug);

        Map<String, Object> r = new LinkedHashMap<>();
        r.put("slug", slug);
        r.put("displayName", entry != null ? entry.displayName() : slug);
        r.put("namespace", entry != null ? entry.namespace() : null);
        r.put("mountAt", entry != null ? entry.mountAt() : null);
        r.put("applicationName", blocked == null ? registry.applicationName(slug) : null);
        r.put("toggleable", blocked == null);
        r.put("notToggleableReason", blocked == null ? null : blocked.name());
        r.put("notToggleableDetail", blocked == null ? null : blocked.detail());
        // A managed slug with no CR is treated by the reconciler as NOT installed; say both,
        // so "false" is never confused with "nobody has ever expressed a desired state".
        r.put("enabled", cr != null && cr.enabled());
        r.put("crPresent", cr != null);
        r.put("reason", cr == null ? null : cr.reason());
        r.put("requestedBy", cr == null ? null : cr.requestedBy());
        r.put("warnings", warnings(slug));
        return r;
    }

    /**
     * The caveats that would otherwise be invisible. Today exactly one: a managed slug whose
     * {@code /data/<slug>} pointer is missing from {@code apps/16}'s {@code ignoreDifferences},
     * so ArgoCD {@code selfHeal} reverts the greying mirror while the Application half of the
     * toggle sticks.
     */
    private List<String> warnings(String slug) {
        OptionalServiceRegistry.Entry entry = registry.entry(slug);
        if (entry == null || entry.configMapSelfHealProtected()) {
            return List.of();
        }
        return List.of("PARTIAL: apps/16-reserved-prefixes-policy.yaml has no /data/" + slug
                + " ignoreDifferences pointer, so ArgoCD selfHeal REVERTS the installed-services "
                + "greying boolean for this slug. The ApplicationSet element (and therefore the "
                + "optional-" + slug + " Application) still toggles correctly; the console greying "
                + "will snap back to the git baseline until that pointer is added.");
    }

    // ── toggle (write; refuses rather than no-ops) ──────────────────────────────────

    /**
     * Set one slug's runtime {@code spec.enabled}. Fail-closed and LOUD at every step; see the
     * class javadoc for the refusal ladder.
     *
     * @throws UnknownSlugException   the platform does not know this slug at all
     * @throws NotToggleableException the platform knows it but the reconciler cannot action it
     * @throws OptionalServiceWriteException the write itself did not land (dark / rejected / failed)
     */
    public Mono<Map<String, Object>> setEnabled(String slug, boolean enabled, String reason, String actor) {
        return Mono.fromCallable(() -> setEnabledBlocking(slug, enabled, reason, actor))
                .subscribeOn(Schedulers.boundedElastic());
    }

    private Map<String, Object> setEnabledBlocking(String slug, boolean enabled, String reason, String actor) {
        if (!registry.isPlatformKnown(slug)) {
            throw new UnknownSlugException(slug, registry.knownSlugs());
        }
        OptionalServiceRegistry.NotToggleable blocked = registry.notToggleableReason(slug);
        if (blocked != null) {
            log.info("[optional-services-admin] REFUSED {} -> enabled={} by={}: {}",
                    slug, enabled, actor, blocked.name());
            throw new NotToggleableException(slug, blocked);
        }

        OptionalServiceCr written = client.setEnabled(slug, enabled, reason, actor);

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("slug", written.slug());
        out.put("enabled", written.enabled());
        out.put("reason", written.reason());
        out.put("requestedBy", written.requestedBy());
        out.put("applicationName", registry.applicationName(written.slug()));
        out.put("observedGeneration", written.generation());
        out.put("warnings", warnings(written.slug()));
        out.put("note", note());
        log.info("[optional-services-admin] {} -> enabled={} by={} (reason={})",
                slug, enabled, actor, reason == null ? "-" : reason);
        return out;
    }

    /** The one-line contract statement every surface repeats (the console's honesty banner). */
    private String note() {
        return client.isReal()
                ? "desired state only — the Lease-gated OptionalServiceReconciler converges the "
                        + "CR onto the apps/13a ApplicationSet element and the installed-services "
                        + "greying boolean on its next tick; ArgoCD then creates or prunes "
                        + "optional-<slug>"
                : "READ-ONLY: the optional-services reconciler is not wired to a cluster "
                        + "(app.optional-services.reconcile.enabled=false, the shipped default), so "
                        + "no toggle made here can land — PUT answers 503. Enabled state below is "
                        + "whatever the CR client reports, which is nothing while dark.";
    }

    // ── typed refusals (mapped to statuses by the controller) ───────────────────────

    /** The platform has never heard of this slug — 404. */
    public static class UnknownSlugException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        public UnknownSlugException(String slug, List<String> known) {
            super("unknown optional-service slug '" + slug + "'; known slugs: "
                    + String.join(", ", known));
        }
    }

    /**
     * The platform KNOWS the slug but the reconciler cannot action it — 422. Carries the named
     * reason so a client can branch on it rather than parse prose.
     */
    public static class NotToggleableException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        private final OptionalServiceRegistry.NotToggleable reason;

        public NotToggleableException(String slug, OptionalServiceRegistry.NotToggleable reason) {
            super("optional-service '" + slug + "' is NOT runtime-toggleable (" + reason.name()
                    + "): " + reason.detail() + ". Nothing was written.");
            this.reason = reason;
        }

        public OptionalServiceRegistry.NotToggleable reason() {
            return reason;
        }
    }
}
