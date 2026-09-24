package net.hugmesh.adminbff.optionalservices;

import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The built-in, closed registry of the OPTIONAL cluster-service slugs this controller knows —
 * the Java mirror of the generator's {@code specs/cluster/manifests/optional-services-operator/
 * crd-optionalservice.yaml} slug enum + {@code seed-optionalservices.yaml} + the
 * {@code apps/13a-optional-services.yaml} element list + the {@code installed-services}
 * ConfigMap booleans + {@code apps/16}'s {@code ignoreDifferences} pointers.
 *
 * <p>The registry has TWO halves, and the split is the point:
 * <ul>
 *   <li>{@link #slugs()} — the MANAGED slugs the {@link OptionalServiceReconciler} can
 *       actually actuate (they are in the CRD {@code spec.slug} enum, so a CR can exist for
 *       them, AND they have a 13a ApplicationSet element, so flipping one writes a real
 *       target). These are the ONLY slugs the reconciler builds its desired map over.</li>
 *   <li>{@link #notToggleable()} — slugs the PLATFORM knows (they appear in the 13a element
 *       list and/or as an {@code installed-services} ConfigMap boolean) that the reconciler
 *       CANNOT actuate, each carrying a NAMED {@link NotToggleable} reason.</li>
 * </ul>
 *
 * <h3>Why the second half exists (the character-forge lesson)</h3>
 * Before 2026-08-26 this class held ONLY the managed half, and every other slug simply fell
 * off the end of the world: {@code character-forge} was in the CRD enum, had a seed CR, had a
 * 13a element and had a ConfigMap key — but was MISSING here. The API server accepted
 * {@code spec.slug: character-forge}, {@code kubectl} reported {@code enabled: true}, and the
 * reconciler logged "unknown slug — ignoring", wrote NEITHER target and skipped the CR's
 * {@code /status} entirely, so nothing anywhere recorded that the toggle had done nothing.
 * A registry that lists only what works cannot report what does not; the admin surface
 * ({@link OptionalServiceAdminService}) needs BOTH halves to REFUSE a write instead of
 * silently dropping it. {@code OptionalServiceRegistryParityTest} DERIVES both halves (and
 * every field below) from the vendored generator manifests, so a slug added upstream fails
 * the build until it is classified here.
 *
 * <h3>...and why the parity test alone did not stop it recurring (meshbridge, #106)</h3>
 * The parity test is only as current as its VENDORED fixtures. {@code meshbridge} was parked
 * in the not-toggleable half as {@link NotToggleable#NOT_IN_CRD_ENUM} while the generator's
 * CRD enum and seed CRs already carried it (hugmesh-admin-bff-api#106 dates both to
 * 2026-08-26), so the reconciler ignored its seeded CR exactly as it had ignored
 * character-forge — and the parity test stayed green, because the vendored CRD copy it read
 * still lacked the enum value. The same stale copy hid that apps/16 had gained a
 * {@code /data/character-forge} pointer, so character-forge raised a selfHeal warning for a
 * revert that no longer happens. What caught both was the generator-side gate
 * ({@code hugmesh-generator tests/scripts/test-optional-service-slug-closure.sh}), which
 * parses THIS file and compares it to the live manifests. Fixed 2026-09-24 together with a
 * fixture refresh; {@code OptionalServiceManifestDriftTest} is what flags a stale fixture on a
 * machine that has a generator checkout (it SKIPS in this repo's own CI).
 *
 * <h3>Deliberately absent</h3>
 * {@code egress-vpn} / {@code tor} are NODE services (OpenRC + node reconcile agents), not
 * cluster Applications: they have no 13a element and no {@code installed-services} boolean, so
 * they are outside this mechanism entirely (see {@code EgressVpnController}) rather than
 * "platform-known but not toggleable".
 *
 * <p>path/namespace/mountAt are INTRINSIC to a slug and resolved here (not settable on the CR)
 * so an admin cannot repoint a slug at an arbitrary manifest path. The reconciler flips the 13a
 * element / ConfigMap key BY SLUG (read-modify-write), so the write path does not depend on
 * these values; they back {@link #applicationName} + status/audit + the admin catalogue.
 */
@Component
public class OptionalServiceRegistry {

    /**
     * One immutable MANAGED registry entry (mirrors an installed-services {@code services.json}
     * row plus the one ArgoCD fact the admin surface has to be honest about).
     *
     * @param slug        the optional-service slug (1:1 with the 13a element + ConfigMap key)
     * @param namespace   the namespace the slug's Application deploys into
     * @param mountAt     the host-shell mount path, or {@code null} for a backend-only service
     * @param displayName the human label (mirrors the {@code services.json} row)
     * @param configMapSelfHealProtected whether {@code apps/16} carries a
     *        {@code /data/<slug>} {@code ignoreDifferences} pointer for this slug. When
     *        {@code false} the reconciler's greying-mirror write IS made but ArgoCD's
     *        {@code selfHeal} REVERTS it on the next pass, so the toggle HALF-actuates
     *        (Application created/pruned correctly — the 13a {@code elements} list is
     *        wholesale-ignored by the app-of-apps roots — while the greying boolean snaps
     *        back to git). Surfaced as a WARNING on the catalogue and on the toggle
     *        response; never silently swallowed.
     */
    public record Entry(String slug, String namespace, String mountAt, String displayName,
                        boolean configMapSelfHealProtected) {}

    /** Why a platform-known slug is NOT runtime-toggleable by this controller. */
    public enum NotToggleable {

        /**
         * The slug has a 13a ApplicationSet element (and/or a ConfigMap boolean) but is ABSENT
         * from the CRD {@code spec.slug} enum, so the API server REJECTS an OptionalService CR
         * for it outright — there is no desired-state object to reconcile. It fails loud at the
         * API server; this entry makes the admin surface fail loud too, in advance.
         *
         * <p>No slug carries this reason today: {@code meshbridge} did until 2026-09-24, and by
         * then the claim had been false for weeks (the generator's enum had gained it; see the
         * class javadoc). The constant stays because it is the correct classification for the
         * NEXT slug that gains a 13a element before its enum value, and both
         * {@code OptionalServiceRegistryParityTest} and the generator's slug-closure gate check
         * it against the CRD enum rather than trusting it.
         */
        NOT_IN_CRD_ENUM("no OptionalService CR can exist for this slug — it is absent from the "
                + "CRD spec.slug enum, so the API server rejects the write"),

        /**
         * The slug has an {@code installed-services} ConfigMap boolean but NO 13a
         * ApplicationSet element, so toggling it would HALF-actuate: the greying boolean would
         * move while no Application is ever created or pruned. Left build-determined.
         */
        NO_APPLICATIONSET_ELEMENT("no apps/13a ApplicationSet element — toggling would only move "
                + "the greying boolean and never create or prune an Application");

        private final String detail;

        NotToggleable(String detail) {
            this.detail = detail;
        }

        /** The human half of the refusal message (the enum NAME is the machine half). */
        public String detail() {
            return detail;
        }
    }

    // Order mirrors apps/13a-optional-services.yaml + the installed-services ConfigMap.
    private static final List<Entry> ENTRIES = List.of(
            new Entry("akkoma",           "hugmesh-backend",   "/social/mastodon",
                    "Akkoma (Mastodon)", true),
            new Entry("tuwunel",          "hugmesh-backend",   "/social/matrix",
                    "tuwunel (Matrix)", true),
            new Entry("phpbb",            "hugmesh-forum",     "/social/forum",
                    "phpBB (Forum)", true),
            new Entry("games",            "hugmesh-games",     "/games",
                    "HugMesh Games", true),
            new Entry("owncast",          "hugmesh-owncast",   "/owncast",
                    "Owncast (live streaming)", true),
            new Entry("tube",             "hugmesh-tube",      "/tube",
                    "LocalTube (YouTube archive)", true),
            new Entry("character-studio", "hugmesh-frontend",  "/character-studio",
                    "Character Studio (VN)", true),
            // character-forge — ADDED 2026-08-26. It already had a CRD enum value, a seed CR, a
            // 13a element and a ConfigMap key but was MISSING here, which made it a SILENTLY
            // INERT toggle (see the class javadoc). configMapSelfHealProtected flipped to true
            // 2026-09-24 (#106): generator apps/16 carries /data/character-forge, so the
            // selfHeal warning this entry used to raise described a revert that no longer
            // happens.
            new Entry("character-forge",  "hugmesh-backend",   "/character-forge",
                    "Character Forge (3D)", true),
            new Entry("anubis",           "hugmesh-frontend",  null,
                    "Anubis (anti-scraper PoW gate)", true),
            new Entry("coturn",           "hugmesh-backend",   null,
                    "coturn (TURN/STUN server)", true),
            // meshbridge — MANAGED since 2026-09-24 (#106). It was parked in NOT_TOGGLEABLE as
            // NOT_IN_CRD_ENUM after the generator had already put it in the CRD enum and the
            // seed CRs, which gave it the character-forge shape: the API server ACCEPTED the
            // seeded CR and the reconciler ignored it. Every field is read off the generator's
            // manifests: 13a element (namespace hugmesh-backend, placed after coturn), the
            // installed-services services.json row (displayName, mountAt null — it is a
            // backend bridge with no host-shell route) and the apps/16 /data/meshbridge
            // pointer (so selfHeal-protected). NOT verified here: whether an actuated
            // meshbridge Application comes up healthy — that needs a running cluster with the
            // reconciler enabled. Its services.json row also says dependsOn tuwunel; this
            // registry has no field for that and does not enforce it.
            new Entry("meshbridge",       "hugmesh-backend",   null,
                    "Mesh radio bridge (Meshtastic ↔ Matrix)", true),
            new Entry("edge-ai",          "hugmesh-inference", "/admin/edge-ai",
                    "Edge AI (inference)", true),
            new Entry("edge-ai-analysis", "hugmesh-inference", "/admin/edge-ai-analysis",
                    "Edge AI — analysis API", true),
            new Entry("edge-ai-tts",      "hugmesh-inference", "/admin/edge-ai-tts",
                    "Edge AI — voice synthesis (TTS)", true)
    );

    /**
     * Platform-known slugs the reconciler CANNOT actuate, with the named reason. Derived +
     * asserted by {@code OptionalServiceRegistryParityTest} from the vendored manifests:
     * a slug with no 13a element is {@link NotToggleable#NO_APPLICATIONSET_ELEMENT}; a slug
     * that HAS one but is absent from the CRD enum is {@link NotToggleable#NOT_IN_CRD_ENUM}.
     */
    private static final Map<String, NotToggleable> NOT_TOGGLEABLE = new LinkedHashMap<>();

    static {
        // ConfigMap boolean, no 13a element — its RBAC is the hardcoded
        // apps/14-workload-console-rbac.yaml, not ApplicationSet-owned.
        NOT_TOGGLEABLE.put("workloadConsole", NotToggleable.NO_APPLICATIONSET_ELEMENT);
        // (meshbridge used to be listed here as NOT_IN_CRD_ENUM. It is a MANAGED entry above
        // since #106 — the generator's CRD enum and seed CRs carry it.)
        // ConfigMap-only greying booleans (hugmesh-pki workloads, no 13a element).
        NOT_TOGGLEABLE.put("headwind", NotToggleable.NO_APPLICATIONSET_ELEMENT);
        NOT_TOGGLEABLE.put("attestation-server", NotToggleable.NO_APPLICATIONSET_ELEMENT);
    }

    private final Map<String, Entry> bySlug;
    private final List<String> slugs;
    private final Map<String, NotToggleable> notToggleable;
    private final List<String> knownSlugs;

    public OptionalServiceRegistry() {
        Map<String, Entry> m = new LinkedHashMap<>();
        for (Entry e : ENTRIES) {
            m.put(e.slug(), e);
        }
        this.bySlug = Map.copyOf(m);
        this.slugs = ENTRIES.stream().map(Entry::slug).toList();
        this.notToggleable = Map.copyOf(NOT_TOGGLEABLE);
        List<String> all = new ArrayList<>(this.slugs);
        all.addAll(NOT_TOGGLEABLE.keySet());
        this.knownSlugs = List.copyOf(all);
    }

    /** The closed MANAGED slug set, in ApplicationSet/ConfigMap order — what the reconciler actuates. */
    public List<String> slugs() {
        return slugs;
    }

    /**
     * Every slug the PLATFORM knows: the managed set followed by the not-toggleable set. The
     * admin catalogue lists these; {@link #notToggleableReason(String)} says which is which.
     */
    public List<String> knownSlugs() {
        return knownSlugs;
    }

    /** True iff this slug is a controller-managed optional cluster service (the reconciler can actuate it). */
    public boolean isKnown(String slug) {
        return bySlug.containsKey(slug);
    }

    /** True iff the platform knows this slug at all (managed OR explicitly not-toggleable). */
    public boolean isPlatformKnown(String slug) {
        return bySlug.containsKey(slug) || notToggleable.containsKey(slug);
    }

    public Entry entry(String slug) {
        return bySlug.get(slug);
    }

    /** The named reason this slug is not toggleable, or {@code null} when it IS toggleable / unknown. */
    public NotToggleable notToggleableReason(String slug) {
        return notToggleable.get(slug);
    }

    /** The platform-known-but-unactionable slugs and their named reasons. */
    public Map<String, NotToggleable> notToggleable() {
        return notToggleable;
    }

    /** The Application the 13a ApplicationSet generates for this slug ({@code optional-<slug>}). */
    public String applicationName(String slug) {
        return "optional-" + slug;
    }
}
