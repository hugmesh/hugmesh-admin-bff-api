package net.hugmesh.adminbff.gamesservices;
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
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.config.SecurityConfig;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.PrincipalDomain;
import net.hugmesh.adminbff.web.ApiExceptionHandler;
import net.hugmesh.adminbff.web.ValidationExceptionHandler;
import net.hugmesh.adminbff.web.dto.CreateGameInstanceRequest;

import java.time.Instant;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * The games-services INSTANCE controller role matrix — the AND-derived-role split:
 * <ul>
 *   <li>create — GAMES_SERVICES_ADMIN ONLY; a RUNNER or a plain GAMES_SERVICES member is
 *       403 + never reaches the service.</li>
 *   <li>run/stop (suspend/resume/terminate) — GAMES_SERVICES_ADMIN OR GAMES_SERVICES_RUNNER.</li>
 *   <li>list/get — any GAMES_SERVICES member.</li>
 *   <li>no games-services role at all (plain ADMIN) — 403 on everything (the AND model:
 *       ADMIN alone never reaches the games-services surface).</li>
 * </ul>
 * Mirrors {@code DomainRegistryControllerTest}: {@code @WebFluxTest} + real {@link SecurityConfig}.
 */
@WebFluxTest(controllers = GameInstanceController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class, ApiExceptionHandler.class})
class GameInstanceControllerTest {

    @Autowired ApplicationContext context;

    WebTestClient web;

    @BeforeEach
    void setUpWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean GameInstanceService service;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    private WebTestClient withRoles(String... roles) {
        SimpleGrantedAuthority[] auth = new SimpleGrantedAuthority[roles.length + 1];
        auth[0] = new SimpleGrantedAuthority("ROLE_USER");
        for (int i = 0; i < roles.length; i++) auth[i + 1] = new SimpleGrantedAuthority("ROLE_" + roles[i]);
        return web.mutateWith(mockJwt().jwt(j -> j.subject("alice")).authorities(auth));
    }

    private static GameInstance sample(String state) {
        return new GameInstance("inst-1", "brandx", "minetest", "world1", state, "pending",
                "alice", Instant.now(), null, null, null, null, Instant.now());
    }

    private static final String CREATE_BODY = "{\"slug\":\"minetest\",\"name\":\"world1\"}";

    // ── CREATE — GAMES_SERVICES_ADMIN only ───────────────────────────────────────

    @Test
    void create_asGamesServicesAdmin_isAllowed() {
        when(service.create(any(CreateGameInstanceRequest.class), eq("alice"), any(PrincipalDomain.class)))
                .thenReturn(Mono.just(sample("pending")));
        withRoles("GAMES_SERVICES", "GAMES_SERVICES_ADMIN").post()
                .uri("/bff/games-services/instances")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(CREATE_BODY)
                .exchange().expectStatus().isCreated()
                .expectBody().jsonPath("$.slug").isEqualTo("minetest")
                .jsonPath("$.ownerSubject").isEqualTo("alice");
        verify(service).create(any(), eq("alice"), any());
    }

    @Test
    void create_asRunner_isForbidden_andNeverWrites() {
        withRoles("GAMES_SERVICES", "GAMES_SERVICES_RUNNER").post()
                .uri("/bff/games-services/instances")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(CREATE_BODY)
                .exchange().expectStatus().isForbidden();
        verify(service, never()).create(any(), anyString(), any());
    }

    @Test
    void create_asPlainGamesServices_isForbidden() {
        withRoles("GAMES_SERVICES").post()
                .uri("/bff/games-services/instances")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(CREATE_BODY)
                .exchange().expectStatus().isForbidden();
        verify(service, never()).create(any(), anyString(), any());
    }

    @Test
    void create_asPlainAdmin_withoutGamesServices_isForbidden_theANDModel() {
        // ADMIN alone never reaches the games-services surface (coarse gate denies).
        withRoles("ADMIN").post()
                .uri("/bff/games-services/instances")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(CREATE_BODY)
                .exchange().expectStatus().isForbidden();
        verify(service, never()).create(any(), anyString(), any());
    }

    // ── RUN/STOP — admin OR runner ───────────────────────────────────────────────

    @Test
    void terminate_asRunner_isAllowed() {
        when(service.terminate(eq("inst-1"), any(PrincipalDomain.class)))
                .thenReturn(Mono.just(sample("terminated")));
        withRoles("GAMES_SERVICES", "GAMES_SERVICES_RUNNER").post()
                .uri("/bff/games-services/instances/inst-1/terminate")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.state").isEqualTo("terminated");
        verify(service).terminate(eq("inst-1"), any());
    }

    @Test
    void suspend_asAdmin_isAllowed() {
        when(service.suspend(eq("inst-1"), any(PrincipalDomain.class)))
                .thenReturn(Mono.just(sample("suspended")));
        withRoles("GAMES_SERVICES", "GAMES_SERVICES_ADMIN").post()
                .uri("/bff/games-services/instances/inst-1/suspend")
                .exchange().expectStatus().isOk();
        verify(service).suspend(eq("inst-1"), any());
    }

    @Test
    void terminate_asPlainGamesServices_isForbidden() {
        withRoles("GAMES_SERVICES").post()
                .uri("/bff/games-services/instances/inst-1/terminate")
                .exchange().expectStatus().isForbidden();
        verify(service, never()).terminate(anyString(), any());
    }

    // ── READ — any games-services member ─────────────────────────────────────────

    @Test
    void list_asGamesServices_isAllowed() {
        when(service.list(any(PrincipalDomain.class))).thenReturn(Flux.just(sample("active")));
        withRoles("GAMES_SERVICES").get().uri("/bff/games-services/instances")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$[0].name").isEqualTo("world1");
        verify(service).list(any());
    }

    @Test
    void list_withoutAnyGamesServicesRole_isForbidden() {
        withRoles("MOD").get().uri("/bff/games-services/instances")
                .exchange().expectStatus().isForbidden();
        verify(service, never()).list(any());
    }

    // ── creation-gate 403 propagates from the service ────────────────────────────

    @Test
    void create_quotaExceeded_403_fromServiceGate() {
        when(service.create(any(), anyString(), any()))
                .thenReturn(Mono.error(net.hugmesh.commons.web.ApiException.forbidden(
                        "instance quota reached for 'minetest' in this domain (1/1)")));
        withRoles("GAMES_SERVICES", "GAMES_SERVICES_ADMIN").post()
                .uri("/bff/games-services/instances")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(CREATE_BODY)
                .exchange().expectStatus().isForbidden()
                .expectBody().jsonPath("$.error").value(
                        org.hamcrest.Matchers.containsString("quota reached"));
    }
}
