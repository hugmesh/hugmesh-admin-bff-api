package systems.hugmesh.adminbff.servicecatalog.scaffold;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import systems.hugmesh.adminbff.servicecatalog.PerServiceIdentity;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Builds the {@code {{TOKEN}} -> value} render context {@link TokenRenderer} substitutes into a
 * scaffold skeleton. The token VALUES follow the generator's own derivations
 * ({@code scripts/render-repo-tree.sh}) so a scaffolded tree renders byte-compatibly with a real
 * generator render — the impl-note shorthands ({@code NPM_SCOPE=@+domainSlug}) are NOT used where
 * they diverge from the generator (that value would double the {@code @} the skeleton already
 * prepends, e.g. {@code @{{NPM_SCOPE}}/...}, yielding an invalid npm scope). Derivations:
 *
 * <ul>
 *   <li>{@code APP_SLUG} = {@code slug(serviceKey)} — the code identity (+ the Java-package
 *       segment for spring-bff, gated to {@code ^[a-z0-9]+$} upstream in {@link ScaffoldService}).</li>
 *   <li>{@code BRAND} = {@code slug(domain)}; {@code CLUSTER_DOMAIN} = {@code domain}.</li>
 *   <li>{@code BRAND_TITLE} / {@code TITLE_WORD} = {@code displayName} (default {@code serviceKey}).</li>
 *   <li>{@code NPM_SCOPE} = {@code ORG_SLUG} = {@code slug(org)} — the BARE npm scope (the skeleton
 *       writes {@code @{{NPM_SCOPE}}/...}); {@code ORG} from {@code app.appstore.scaffold.org}.</li>
 *   <li>{@code HOST_NAME} = {@code slug(domain) + "-host"} (the generator's {@code ${BRAND}-host}).</li>
 *   <li>{@code REPO_NAME} = {@code "hugmesh-" + slug(serviceKey)} (the repo short name).</li>
 *   <li>{@code GENERATOR_ORG_GROUP} = the configured override, else {@code NPM_SCOPE +
 *       "/hugmesh-generator"} (the CI-include {@code group/project} path — a bare group would
 *       be an invalid {@code project:} include).</li>
 *   <li>{@code HARBOR_PROJECT} / {@code MESH_TAG} / {@code NS_PREFIX} / {@code HEADSCALE_URL} /
 *       {@code PROFILE} = config defaults (not used by today's four skeletons — carried so a
 *       re-vendored skeleton that introduces one renders without a code change; an UNKNOWN
 *       {@code {{UPPER_SNAKE}}} still hard-fails the render — see {@link TokenRenderer}).</li>
 * </ul>
 */
@Component
public class ScaffoldRenderContext {

    // ── Identity token keys ──────────────────────────────────────────────────────
    static final String APP_SLUG = "APP_SLUG";
    static final String TITLE_WORD = "TITLE_WORD";
    static final String BRAND_TITLE = "BRAND_TITLE";
    static final String CLUSTER_DOMAIN = "CLUSTER_DOMAIN";
    static final String BRAND = "BRAND";
    static final String ORG = "ORG";
    static final String ORG_SLUG = "ORG_SLUG";
    static final String NPM_SCOPE = "NPM_SCOPE";
    static final String HOST_NAME = "HOST_NAME";
    static final String REPO_NAME = "REPO_NAME";
    static final String GENERATOR_ORG_GROUP = "GENERATOR_ORG_GROUP";
    // ── Config-driven infra token keys (future skeletons) ────────────────────────
    static final String HARBOR_PROJECT = "HARBOR_PROJECT";
    static final String MESH_TAG = "MESH_TAG";
    static final String NS_PREFIX = "NS_PREFIX";
    static final String HEADSCALE_URL = "HEADSCALE_URL";
    static final String PROFILE = "PROFILE";

    private final String org;
    private final String generatorOrgGroupOverride;
    private final String harborProject;
    private final String meshTag;
    private final String nsPrefix;
    private final String headscaleUrl;
    private final String profile;

    public ScaffoldRenderContext(
            @Value("${app.appstore.scaffold.org:hugmesh}") String org,
            @Value("${app.appstore.scaffold.generator-org-group:}") String generatorOrgGroupOverride,
            @Value("${app.appstore.scaffold.harbor-project:hugmesh}") String harborProject,
            @Value("${app.appstore.scaffold.mesh-tag:mesh_default}") String meshTag,
            @Value("${app.appstore.scaffold.ns-prefix:hugmesh}") String nsPrefix,
            @Value("${app.appstore.scaffold.headscale-url:http://headscale.headscale.svc.cluster.local:8080}")
                    String headscaleUrl,
            @Value("${app.appstore.scaffold.profile:prod}") String profile) {
        this.org = org;
        this.generatorOrgGroupOverride = generatorOrgGroupOverride;
        this.harborProject = harborProject;
        this.meshTag = meshTag;
        this.nsPrefix = nsPrefix;
        this.headscaleUrl = headscaleUrl;
        this.profile = profile;
    }

    /** The k8s/DNS-safe slug of {@code serviceKey} — the rendered {@code APP_SLUG}. Reuses
     *  {@link PerServiceIdentity#slug} so a scaffold's code identity matches the effector's. */
    public static String appSlug(String serviceKey) {
        return PerServiceIdentity.slug(serviceKey);
    }

    /**
     * The full render context for {@code (domain, serviceKey, displayName)}. Insertion-ordered so
     * the render is byte-stable.
     */
    public Map<String, String> build(String domain, String serviceKey, String displayName) {
        String domainSlug = PerServiceIdentity.slug(domain);
        String serviceSlug = appSlug(serviceKey);
        String title = displayName == null || displayName.isBlank() ? serviceKey : displayName;
        String npmScope = PerServiceIdentity.slug(org);
        String generatorOrgGroup = generatorOrgGroupOverride == null || generatorOrgGroupOverride.isBlank()
                ? npmScope + "/hugmesh-generator"
                : generatorOrgGroupOverride;

        Map<String, String> ctx = new LinkedHashMap<>();
        ctx.put(APP_SLUG, serviceSlug);
        ctx.put(TITLE_WORD, title);
        ctx.put(BRAND_TITLE, title);
        ctx.put(CLUSTER_DOMAIN, domain == null ? "" : domain.toLowerCase(Locale.ROOT));
        ctx.put(BRAND, domainSlug);
        ctx.put(ORG, org);
        ctx.put(ORG_SLUG, npmScope);
        ctx.put(NPM_SCOPE, npmScope);
        ctx.put(HOST_NAME, domainSlug + "-host");
        ctx.put(REPO_NAME, "hugmesh-" + serviceSlug);
        ctx.put(GENERATOR_ORG_GROUP, generatorOrgGroup);
        ctx.put(HARBOR_PROJECT, harborProject);
        ctx.put(MESH_TAG, meshTag);
        ctx.put(NS_PREFIX, nsPrefix);
        ctx.put(HEADSCALE_URL, headscaleUrl);
        ctx.put(PROFILE, profile);
        return ctx;
    }
}
