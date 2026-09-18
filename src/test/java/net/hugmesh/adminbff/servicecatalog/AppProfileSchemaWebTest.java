package net.hugmesh.adminbff.servicecatalog;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.config.SecurityConfig;
import net.hugmesh.adminbff.web.ApiExceptionHandler;
import net.hugmesh.adminbff.web.ValidationExceptionHandler;
import net.hugmesh.commons.security.DomainRegistry;

import java.time.Instant;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * The app-profile schema refusal ON THE WIRE (issue #55) — the REAL {@link AppProfileService}
 * behind the real controller and the real advice, with only the repository mocked, so this
 * answers the question the unit tests cannot: what does a superadmin's browser actually receive?
 *
 * <p>It must be the shared bean-validation body — {@code {"error":"validation failed",
 * "fields":{path:message}}} — because the console already folds a {@code fields} map into its
 * form error field by field ({@code ServiceCatalogService.describeValidationFields}). A
 * one-line {@code {"error": …}} would render as a single opaque sentence instead.
 *
 * <p>{@link AppProfileControllerTest} covers the SUPERADMIN-only role matrix with the service
 * mocked; this class deliberately does not repeat it.
 */
@WebFluxTest(controllers = AppProfileController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class,
        ApiExceptionHandler.class, AppProfileService.class})
class AppProfileSchemaWebTest {

    @Autowired ApplicationContext context;
    @MockitoBean AppProfileRepository repo;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    WebTestClient web;

    @BeforeEach
    void setUp() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    private WebTestClient asSuperadmin() {
        return web.mutateWith(mockJwt().jwt(j -> j.subject("superadmin-subject-9"))
                .authorities(new SimpleGrantedAuthority("ROLE_USER"),
                        new SimpleGrantedAuthority("ROLE_SUPERADMIN")));
    }

    /** A create body carrying {@code profileJson} as a JSON STRING, the way the console sends it. */
    private static String createBody(String name, String profileJson) {
        return "{\"name\":\"" + name + "\",\"profileJson\":"
                + new com.fasterxml.jackson.databind.node.TextNode(profileJson) + "}";
    }

    @Test
    void post_withAnInvalidProfile_is400_withEveryPathInTheFieldsMap_andNothingIsWritten() {
        asSuperadmin().post().uri("/bff/superadmin/app-profiles")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(createBody("small-postgres",
                        "{\"resources\":{\"cpu\":\"lots\"},\"roles\":[\"admin\"],\"bogus\":1}"))
                .exchange()
                .expectStatus().isBadRequest()
                .expectBody()
                .jsonPath("$.error").isEqualTo("validation failed")
                .jsonPath("$.fields.bogus")
                .isEqualTo("unknown field (allowed here: resources, roles, certs, exposure)")
                .jsonPath("$.fields['roles[0]']")
                .isEqualTo("must match ^ROLE_[A-Z][A-Z0-9_]*$ (e.g. \"ROLE_ADMIN\", \"ROLE_MESH\")")
                .jsonPath("$.fields['resources.cpu']").exists();

        verify(repo, never()).insert(anyString(), any(), anyString());
        verify(repo, never()).findByName(anyString());
    }

    @Test
    void put_withAnInvalidProfile_is400_inTheSameShape() {
        asSuperadmin().put().uri("/bff/superadmin/app-profiles/small-postgres")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(createBody("ignored-on-update", "{\"certs\":{\"ttl\":\"30d\"}}"))
                .exchange()
                .expectStatus().isBadRequest()
                .expectBody()
                .jsonPath("$.error").isEqualTo("validation failed")
                .jsonPath("$.fields['certs.ttl']")
                .isEqualTo("must match ^([0-9]+(h|m|s))+$ (e.g. \"720h\", \"168h\", \"1h30m\")");

        verify(repo, never()).updateJson(anyString(), any());
    }

    @Test
    void post_withAValidProfile_isCreated_andStoresTheTextVerbatim() {
        String profile = "{\"resources\":{\"cpu\":\"500m\",\"memory\":\"512Mi\"}}";
        when(repo.findByName("small-postgres")).thenReturn(Mono.empty());
        when(repo.insert("small-postgres", profile, "superadmin-subject-9"))
                .thenReturn(Mono.just(new AppProfile("ap-1", "small-postgres", profile,
                        "superadmin-subject-9", Instant.now(), Instant.now())));

        asSuperadmin().post().uri("/bff/superadmin/app-profiles")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(createBody("small-postgres", profile))
                .exchange()
                .expectStatus().isCreated()
                .expectBody().jsonPath("$.profileJson").isEqualTo(profile);

        verify(repo).insert("small-postgres", profile, "superadmin-subject-9");
    }
}
