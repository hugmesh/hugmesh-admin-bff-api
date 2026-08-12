package net.hugmesh.adminbff.charactermoderation;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for the two ROLE_SERVICE WebClient clients that bracket the reconciler — the
 * federation resolved-findings READ ({@link FederationResolvedFindingsClient}, #71) and the
 * user-bff character moderation SINK ({@link UserBffCharacterModerationClient}, #87). Each
 * drives the REAL Boot-4 reactive codec via an {@link ExchangeFunction} stub (no live
 * service), capturing the outgoing {@link ClientRequest} to assert the exact contract shape
 * (path, query params, bearer, body), plus the gate-off short-circuits.
 */
class CharacterModerationClientsTest {

    private static final java.util.function.Supplier<Mono<String>> TOKEN = () -> Mono.just("svc-jwt");

    // ── federation read: surface + strict sinceId + clamped limit + bearer ──
    @Test
    void federationRead_buildsStrictCursorQuery_withServiceBearer() {
        AtomicReference<ClientRequest> captured = new AtomicReference<>();
        ExchangeFunction stub = req -> {
            captured.set(req);
            return Mono.just(ClientResponse.create(HttpStatus.OK)
                    .header("Content-Type", MediaType.APPLICATION_JSON_VALUE)
                    .body("[{\"id\":11,\"surface\":\"character-part\",\"subjectRef\":900,"
                            + "\"status\":\"actioned\",\"reviewer\":\"mod-x\",\"domain\":\"d\",\"ts\":\"t\"}]")
                    .build());
        };
        WebClient wc = WebClient.builder().baseUrl("http://fed").exchangeFunction(stub).build();
        FederationResolvedFindingsClient client = new FederationResolvedFindingsClient(wc, true, TOKEN);

        StepVerifier.create(client.fetchResolved("character-part", 5L, 200))
                .assertNext(page -> {
                    assertThat(page).hasSize(1);
                    ResolvedFindingDto f = page.get(0);
                    assertThat(f.id()).isEqualTo(11L);
                    assertThat(f.subjectRef()).isEqualTo(900L);
                    assertThat(f.status()).isEqualTo("actioned");
                    assertThat(f.isPushable()).isTrue();
                })
                .verifyComplete();

        ClientRequest req = captured.get();
        assertThat(req.url().getPath()).isEqualTo("/api/federation/findings/resolved");
        assertThat(req.url().getQuery()).contains("surface=character-part")
                .contains("sinceId=5").contains("limit=200");
        assertThat(req.headers().getFirst("Authorization")).isEqualTo("Bearer svc-jwt");
    }

    @Test
    void federationRead_clampsLimitToContractCeiling_andNullSinceIsZero() {
        AtomicReference<ClientRequest> captured = new AtomicReference<>();
        ExchangeFunction stub = req -> {
            captured.set(req);
            return Mono.just(ClientResponse.create(HttpStatus.OK)
                    .header("Content-Type", MediaType.APPLICATION_JSON_VALUE)
                    .body("[]").build());
        };
        WebClient wc = WebClient.builder().baseUrl("http://fed").exchangeFunction(stub).build();
        FederationResolvedFindingsClient client = new FederationResolvedFindingsClient(wc, true, TOKEN);

        StepVerifier.create(client.fetchResolved("character-sticker", null, 9999))
                .assertNext(page -> assertThat(page).isEmpty())
                .verifyComplete();

        assertThat(captured.get().url().getQuery())
                .contains("sinceId=0")
                .contains("limit=" + FederationResolvedFindingsClient.MAX_LIMIT);
    }

    @Test
    void federationRead_gateOff_returnsEmpty_withNoCall() {
        AtomicReference<Boolean> called = new AtomicReference<>(false);
        ExchangeFunction stub = req -> {
            called.set(true);
            return Mono.just(ClientResponse.create(HttpStatus.OK).body("[]").build());
        };
        WebClient wc = WebClient.builder().exchangeFunction(stub).build();
        FederationResolvedFindingsClient client = new FederationResolvedFindingsClient(wc, false, TOKEN);

        StepVerifier.create(client.fetchResolved("character-part", 3L, 100))
                .assertNext(page -> assertThat(page).isEmpty())
                .verifyComplete();
        assertThat(called.get()).isFalse();
    }

    @Test
    void federationRead_transportError_propagates_soTheReconcilerHaltsTheSurface() {
        ExchangeFunction stub = req -> Mono.error(new RuntimeException("connection refused"));
        WebClient wc = WebClient.builder().exchangeFunction(stub).build();
        FederationResolvedFindingsClient client = new FederationResolvedFindingsClient(wc, true, TOKEN);

        // A failed poll must ERROR (not look like an empty page) so the reconciler does NOT advance.
        StepVerifier.create(client.fetchResolved("character-part", 0L, 100))
                .expectError()
                .verify();
    }

    // ── user-bff sink: parts path + body + bearer → APPLIED on 2xx ──────────
    @Test
    void sink_postsToPartsPath_withStatusBody_andBearer_returnsApplied() {
        AtomicReference<ClientRequest> captured = new AtomicReference<>();
        ExchangeFunction stub = req -> {
            captured.set(req);
            return Mono.just(ClientResponse.create(HttpStatus.OK).build());
        };
        WebClient wc = WebClient.builder().baseUrl("http://userbff").exchangeFunction(stub).build();
        UserBffCharacterModerationClient client = new UserBffCharacterModerationClient(wc, true, TOKEN);

        StepVerifier.create(client.applyModeration(
                        UserBffCharacterModerationClient.KIND_PARTS, 777L, "REJECTED", 10L, "mod-z"))
                .assertNext(o -> assertThat(o).isEqualTo(UserBffCharacterModerationClient.Outcome.APPLIED))
                .verifyComplete();

        ClientRequest req = captured.get();
        assertThat(req.url().getPath()).isEqualTo("/bff/user/internal/character/parts/777/moderation");
        assertThat(req.headers().getFirst("Authorization")).isEqualTo("Bearer svc-jwt");
    }

    @Test
    void sink_stickersPath_idempotentNoOp2xx_isApplied() {
        AtomicReference<ClientRequest> captured = new AtomicReference<>();
        ExchangeFunction stub = req -> {
            captured.set(req);
            // sink idempotently no-ops an already-flipped row but still returns 2xx.
            return Mono.just(ClientResponse.create(HttpStatus.NO_CONTENT).build());
        };
        WebClient wc = WebClient.builder().baseUrl("http://userbff").exchangeFunction(stub).build();
        UserBffCharacterModerationClient client = new UserBffCharacterModerationClient(wc, true, TOKEN);

        StepVerifier.create(client.applyModeration(
                        UserBffCharacterModerationClient.KIND_STICKERS, 5L, "ACTIVE", 42L, "mod-z"))
                .assertNext(o -> assertThat(o).isEqualTo(UserBffCharacterModerationClient.Outcome.APPLIED))
                .verifyComplete();
        assertThat(captured.get().url().getPath())
                .isEqualTo("/bff/user/internal/character/stickers/5/moderation");
    }

    @Test
    void sink_404alreadyFlipped_isApplied_soTheCursorAdvancesNotWedges() {
        // The REAL #87 sink flips ONLY a PENDING row; an already-flipped / unknown id is
        // surfaced as a 404 (its resolve{Part,Sticker} does switchIfEmpty→notFound), NOT a
        // 2xx. On a retry (crash/leadership-handoff between the flips and the cursor write)
        // the re-pushed rows are now terminal → 404. That MUST read as APPLIED so the cursor
        // advances; mapping it to FAILED would HALT the surface forever at that id.
        ExchangeFunction stub = req -> Mono.just(ClientResponse.create(HttpStatus.NOT_FOUND)
                .header("Content-Type", MediaType.APPLICATION_JSON_VALUE)
                .body("{\"error\":\"no PENDING sticker for id\"}").build());
        WebClient wc = WebClient.builder().baseUrl("http://userbff").exchangeFunction(stub).build();
        UserBffCharacterModerationClient client = new UserBffCharacterModerationClient(wc, true, TOKEN);

        StepVerifier.create(client.applyModeration(
                        UserBffCharacterModerationClient.KIND_STICKERS, 5L, "ACTIVE", 42L, "mod-z"))
                .assertNext(o -> assertThat(o).isEqualTo(UserBffCharacterModerationClient.Outcome.APPLIED))
                .verifyComplete();
    }

    @Test
    void sink_non404_4xx_isFailed_soOnlyIdempotent404Advances() {
        // Discriminate: 404 == idempotent already-flipped (APPLIED), but a genuine 4xx like
        // 400 (bad status payload) / 401 / 403 (auth) is NOT idempotent → FAILED → halt.
        ExchangeFunction stub = req -> Mono.just(
                ClientResponse.create(HttpStatus.BAD_REQUEST).build());
        WebClient wc = WebClient.builder().baseUrl("http://userbff").exchangeFunction(stub).build();
        UserBffCharacterModerationClient client = new UserBffCharacterModerationClient(wc, true, TOKEN);

        StepVerifier.create(client.applyModeration(
                        UserBffCharacterModerationClient.KIND_PARTS, 1L, "REJECTED", 1L, "m"))
                .assertNext(o -> assertThat(o).isEqualTo(UserBffCharacterModerationClient.Outcome.FAILED))
                .verifyComplete();
    }

    @Test
    void sink_non2xx_isFailed_soTheCursorDoesNotAdvance() {
        ExchangeFunction stub = req -> Mono.just(
                ClientResponse.create(HttpStatus.INTERNAL_SERVER_ERROR).build());
        WebClient wc = WebClient.builder().baseUrl("http://userbff").exchangeFunction(stub).build();
        UserBffCharacterModerationClient client = new UserBffCharacterModerationClient(wc, true, TOKEN);

        StepVerifier.create(client.applyModeration(
                        UserBffCharacterModerationClient.KIND_PARTS, 1L, "REJECTED", 1L, "m"))
                .assertNext(o -> assertThat(o).isEqualTo(UserBffCharacterModerationClient.Outcome.FAILED))
                .verifyComplete();
    }

    @Test
    void sink_gateOff_returnsFailed_withNoCall_soNoUnpushedRowIsSkipped() {
        AtomicReference<Boolean> called = new AtomicReference<>(false);
        ExchangeFunction stub = req -> {
            called.set(true);
            return Mono.just(ClientResponse.create(HttpStatus.OK).build());
        };
        WebClient wc = WebClient.builder().exchangeFunction(stub).build();
        UserBffCharacterModerationClient client = new UserBffCharacterModerationClient(wc, false, TOKEN);

        StepVerifier.create(client.applyModeration(
                        UserBffCharacterModerationClient.KIND_PARTS, 1L, "REJECTED", 1L, "m"))
                .assertNext(o -> assertThat(o).isEqualTo(UserBffCharacterModerationClient.Outcome.FAILED))
                .verifyComplete();
        assertThat(called.get()).isFalse();
    }

    // ── status mapping helper ───────────────────────────────────────────────
    @Test
    void mapStatus_actionedRejected_dismissedActive_unknownThrows() {
        assertThat(FindingActivationReconciler.mapStatus("actioned")).isEqualTo("REJECTED");
        assertThat(FindingActivationReconciler.mapStatus("dismissed")).isEqualTo("ACTIVE");
        org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
                () -> FindingActivationReconciler.mapStatus("weird"));
    }
}
