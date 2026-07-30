package systems.hugmesh.adminbff.appearance;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.constraints.NotEmpty;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.commons.security.PrincipalDomain;

import java.util.Map;

/**
 * ADMIN-only write surface for the platform-wide default appearance the
 * hugmesh-mastodon-ui {@code PreferencesService} inherits for a non-customised user.
 * Admin gating is DEFENCE IN DEPTH identical to {@link
 * systems.hugmesh.adminbff.announcement.AnnouncementAdminController}: the gateway
 * denies {@code /bff/admin/**} to non-admins, the resource-server filter re-applies
 * {@code hasRole('ADMIN')} on the path, AND {@code @PreAuthorize("hasRole('ADMIN')")}
 * re-checks here.
 *
 * <ul>
 *   <li>{@code PUT /bff/admin/mastodon/appearance-default} — upsert one or more
 *       {@code AppearancePreferences} fields (see {@code PreferencesService}'s
 *       {@code DEFAULTS_SYNC_HOOK}: {@code PUT .../appearance-default { prefs }}) as the
 *       CALLER'S brand's new default, returning the resolved view. Every field key/value
 *       is validated against the known vocabulary (mirrors the per-user
 *       {@code mastodon.appearance.*} keys in hugmesh-user-bff-api) so a bad value
 *       never reaches the durable row — an invalid or empty {@code prefs} is a clean 400,
 *       NEVER a silently-accepted no-op.</li>
 * </ul>
 *
 * <p>DOMAIN SCOPING: the default is written to the ACTING ADMIN's own brand (resolved
 * from the validated JWT issuer via {@link PrincipalDomain}) — an admin can never set
 * another brand's default. The read side is {@link MastodonAppearanceDefaultSurfaceController}.
 */
@Tag(name = "Mastodon appearance default admin", description = "ADMIN-write-gated: set the "
        + "platform-wide default appearance for the hugmesh-mastodon-ui remote "
        + "(domain-scoped to the acting admin's own brand).")
@RestController
@RequestMapping("/bff/admin/mastodon/appearance-default")
@Validated
public class MastodonAppearanceDefaultAdminController {

    private final MastodonAppearanceDefaultService service;
    private final DomainRegistry domainRegistry;

    public MastodonAppearanceDefaultAdminController(MastodonAppearanceDefaultService service,
                                                     DomainRegistry domainRegistry) {
        this.service = service;
        this.domainRegistry = domainRegistry;
    }

    /** PUT body: one or more AppearancePreferences fields to set as the brand default. */
    public record AppearanceDefaultUpdate(@NotEmpty Map<String, Object> prefs) {}

    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Set my brand's mastodon-ui appearance default.",
            operationId = "mastodonAppearanceDefaultPut")
    @PutMapping
    public Mono<Map<String, Object>> put(@RequestBody @jakarta.validation.Valid AppearanceDefaultUpdate body,
                                         Authentication auth) {
        PrincipalDomain scope = PrincipalDomain.of(auth, domainRegistry);
        String actor = auth == null ? "admin" : auth.getName();
        return service.put(body.prefs(), scope.domain(), actor);
    }
}
