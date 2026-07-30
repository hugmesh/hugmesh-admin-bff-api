package systems.hugmesh.adminbff.servicecatalog.federation;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import systems.hugmesh.adminbff.servicecatalog.FederateOutcome;
import systems.hugmesh.adminbff.servicecatalog.ServiceDeployment;
import systems.hugmesh.adminbff.servicecatalog.repourl.RepoUrlValidator;
import systems.hugmesh.adminbff.web.dto.FederateServiceRequest;
import systems.hugmesh.commons.web.ApiException;
import tools.jackson.databind.json.JsonMapper;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The FEDERATE leg of the Service-Store wizard + the federation status read. Registers a
 * deployment's UI as a federation module (via {@link FederationModuleClient}) and reports whether
 * the federate leg is live.
 *
 * <p>Business rules (the controller holds none):
 * <ul>
 *   <li>{@code remoteEntryUrl} is structurally validated exactly like a service-catalog
 *       {@code repoUrl} ({@link RepoUrlValidator}: scheme ∈ {https,git,ssh}, non-empty host, no
 *       control chars, ≤512) — a bad URL is a clean 400 before any federation-api call.</li>
 *   <li>{@code kind} defaults to {@code remote-shell}, {@code visibility} to {@code internal}
 *       (a freshly-federated remote is live-but-internal until promoted); {@code metadata} carries
 *       {@code mountAt} + (when present) {@code requiresRole} as the JSON-STRING column convention.</li>
 *   <li>a federated module is {@code enabled=true} (registering it makes it manifest-visible to
 *       admin/superadmin renders; {@code visibility=internal} keeps it off unprivileged manifests).</li>
 * </ul>
 * {@link FederateOutcome#federationReal()} = {@link FederationModuleClient#isReal()};
 * {@link FederateOutcome#gitopsDescriptorPending()} is always true (the GitOps descriptor
 * automation does not exist yet).
 */
@Service
public class ServiceCatalogFederationService {

    private static final Logger log = LoggerFactory.getLogger(ServiceCatalogFederationService.class);

    private static final String DEFAULT_KIND = "remote-shell";
    private static final String DEFAULT_VISIBILITY = "internal";

    private static final JsonMapper JSON = JsonMapper.builder().build();

    private final FederationModuleClient client;

    public ServiceCatalogFederationService(FederationModuleClient client) {
        this.client = client;
    }

    /**
     * Register {@code deployment}'s UI as a federation module from {@code body}. Validates
     * {@code remoteEntryUrl}, assembles the module {@code metadata}, calls the (real or noop)
     * registry client, and maps the result to a {@link FederateOutcome} carrying the honest mode
     * flags.
     */
    public Mono<FederateOutcome> federate(ServiceDeployment deployment, FederateServiceRequest body) {
        RepoUrlValidator.Result urlCheck = RepoUrlValidator.validate(body.remoteEntryUrl());
        if (!urlCheck.valid()) {
            return Mono.error(ApiException.badRequest("remoteEntryUrl invalid: " + urlCheck.reason()));
        }
        String kind = blankTo(body.kind(), DEFAULT_KIND);
        String visibility = blankTo(body.visibility(), DEFAULT_VISIBILITY);
        String metadata = metadataJson(body.mountAt(), body.requiresRole());
        return client.registerModule(body.slug(), deployment.serviceKey(), kind, body.remoteEntryUrl(),
                        body.exposedModule(), null, visibility, true, metadata)
                .doOnNext(slug -> log.info("[federate] registered {} for deployment {} (real={})",
                        slug, deployment.id(), client.isReal()))
                .thenReturn(new FederateOutcome(deployment, client.isReal(), true));
    }

    /**
     * The federation-status envelope: {@code {enabled, warnings}}. {@code enabled} is whether the
     * real federation-api client is wired; when it is not, a warning explains the ships-dark
     * behaviour so the wizard renders honestly.
     */
    public Map<String, Object> status() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("enabled", client.isReal());
        out.put("warnings", client.isReal()
                ? List.of()
                : List.of("federation registration ships dark (app.appstore.federation.enabled=false) — "
                        + "a federate call is logged, not written to federation-api"));
        return out;
    }

    /** The module {@code metadata} JSON STRING (the existing column convention): {@code mountAt}
     *  always, {@code requiresRole} only when present. Built with a real serializer (never string
     *  concat) so a value with a quote/backslash cannot break the JSON. */
    private static String metadataJson(String mountAt, String requiresRole) {
        Map<String, String> meta = new LinkedHashMap<>();
        meta.put("mountAt", mountAt);
        if (requiresRole != null && !requiresRole.isBlank()) {
            meta.put("requiresRole", requiresRole);
        }
        return JSON.writeValueAsString(meta);
    }

    private static String blankTo(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value;
    }
}
