package systems.hugmesh.adminbff.appearance;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.commons.security.PrincipalDomain;

import java.util.Map;

/**
 * READ-ONLY surface for the admin-configured platform-wide default appearance the
 * hugmesh-mastodon-ui {@code PreferencesService} inherits when a user has not
 * customised their own look. Any AUTHENTICATED caller may read their OWN brand's
 * default (never another brand's) — the write side is admin-write-gated at
 * {@link MastodonAppearanceDefaultAdminController}.
 *
 * <ul>
 *   <li>{@code GET /bff/mastodon/appearance-default} — the caller's brand's currently
 *       configured default (a possibly-PARTIAL {@code AppearancePreferences}-shaped
 *       object; an empty object means no admin default has been configured for this
 *       brand yet — the client's built-in default applies).</li>
 * </ul>
 */
@Tag(name = "Mastodon appearance default", description = "Read-only: the admin-configured "
        + "platform-wide default appearance for the hugmesh-mastodon-ui remote "
        + "(domain-scoped).")
@RestController
public class MastodonAppearanceDefaultSurfaceController {

    private final MastodonAppearanceDefaultService service;
    private final DomainRegistry domainRegistry;

    public MastodonAppearanceDefaultSurfaceController(MastodonAppearanceDefaultService service,
                                                       DomainRegistry domainRegistry) {
        this.service = service;
        this.domainRegistry = domainRegistry;
    }

    @Operation(summary = "My brand's configured mastodon-ui appearance default.",
            operationId = "mastodonAppearanceDefaultGet")
    @GetMapping("/bff/mastodon/appearance-default")
    public Mono<Map<String, Object>> get(Authentication auth) {
        return service.get(PrincipalDomain.of(auth, domainRegistry).domain());
    }
}
