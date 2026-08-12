package net.hugmesh.adminbff.cloudbackup;
import org.junit.jupiter.api.BeforeEach;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.config.SecurityConfig;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.PrincipalDomain;
import net.hugmesh.adminbff.web.ApiExceptionHandler;
import net.hugmesh.adminbff.web.ValidationExceptionHandler;

import java.time.Instant;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * The TOTAL-CLOUD backup SUPERADMIN-only boundary on
 * {@code /bff/superadmin/cloud-backups/total}. {@code @WebFluxTest} + the real
 * {@link SecurityConfig} so BOTH the coarse {@code /bff/superadmin/**} path gate (hasRole
 * SUPERADMIN) AND the per-method {@code @PreAuthorize("hasRole('SUPERADMIN')")} run.
 *
 * <ul>
 *   <li>SUPERADMIN — ALLOW; the create is invoked with {@code BackupCloudScope.TOTAL} +
 *       the superadmin's JWT subject (owner == subject).</li>
 *   <li>ADMIN / MOD / USER — 403 + never reach the service (mutation-resistant DENY).</li>
 *   <li>unauthenticated — 401.</li>
 * </ul>
 */
@WebFluxTest(controllers = BackupSuperadminController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class, ApiExceptionHandler.class})
class BackupSuperadminControllerTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean BackupService service;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    private static final String SUBJECT = "superadmin-subject-3";

    private WebTestClient asSuperadmin() {
        return web.mutateWith(mockJwt().jwt(j -> j.subject(SUBJECT))
                .authorities(new SimpleGrantedAuthority("ROLE_USER"),
                        new SimpleGrantedAuthority("ROLE_SUPERADMIN")));
    }

    private WebTestClient asAdmin() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    private WebTestClient asMod() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_MOD")));
    }

    private WebTestClient asUser() {
        return web.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_USER")));
    }

    private static BackupSet totalSet() {
        return new BackupSet("total-1", "total-cloud", 1L, BackupCloudScope.TOTAL, "default",
                SUBJECT, List.of("postgres", "etcd"), BackupDestinationKind.OBJECT_STORE, "s3://b",
                null, null, BackupSet.STATUS_PENDING, Instant.now(), null, null);
    }

    private static final String TOTAL_BODY =
            "{\"services\":[\"postgres\",\"etcd\"],\"destinationKind\":\"object_store\","
            + "\"destinationRef\":\"s3://b\"}";

    @Test
    void createTotal_asSuperadmin_isAllowed_withTotalScopeAndSubject() {
        when(service.create(any(), eq(BackupCloudScope.TOTAL), any(), any(), anyString(), any(),
                eq(SUBJECT), any(PrincipalDomain.class))).thenReturn(Mono.just(totalSet()));
        asSuperadmin().post().uri("/bff/superadmin/cloud-backups/total")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(TOTAL_BODY)
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.scope").isEqualTo("TOTAL");
        verify(service).create(any(), eq(BackupCloudScope.TOTAL), any(), any(), anyString(), any(),
                eq(SUBJECT), any(PrincipalDomain.class));
    }

    @Test
    void createTotal_asAdmin_isForbidden_andNeverWrites() {
        asAdmin().post().uri("/bff/superadmin/cloud-backups/total")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(TOTAL_BODY)
                .exchange().expectStatus().isForbidden();
        verify(service, never()).create(any(), any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    void createTotal_asMod_isForbidden_andNeverWrites() {
        asMod().post().uri("/bff/superadmin/cloud-backups/total")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(TOTAL_BODY)
                .exchange().expectStatus().isForbidden();
        verify(service, never()).create(any(), any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    void createTotal_asUser_isForbidden_andNeverWrites() {
        asUser().post().uri("/bff/superadmin/cloud-backups/total")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(TOTAL_BODY)
                .exchange().expectStatus().isForbidden();
        verify(service, never()).create(any(), any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    void createTotal_unauthenticated_is401() {
        web.post().uri("/bff/superadmin/cloud-backups/total")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(TOTAL_BODY)
                .exchange().expectStatus().isUnauthorized();
        verify(service, never()).create(any(), any(), any(), any(), any(), any(), any(), any());
    }
}
