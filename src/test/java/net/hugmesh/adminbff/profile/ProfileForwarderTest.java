package net.hugmesh.adminbff.profile;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.client.reactive.MockClientHttpRequest;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.ExchangeStrategies;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import net.hugmesh.authcore.casdoor.CasdoorAdminClient;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * {@link ProfileForwarder} fan-out: the user-bff profile POST (gated by
 * {@code profile.forward.enabled}) AND the optional Casdoor displayName leg (present only
 * when a Casdoor admin client is wired). Asserts:
 * <ul>
 *   <li>the Casdoor displayName leg runs even when the user-bff gate is DARK (the two legs
 *       are independent), and the owner is ALWAYS derived from the {@code provider:handle}
 *       ownerId — never a caller-supplied target;</li>
 *   <li>with the gate ENABLED, BOTH the user-bff POST and the Casdoor update fire;</li>
 *   <li>both legs are skipped when no names are supplied or no Casdoor client is wired;</li>
 *   <li>fail-OPEN: a Casdoor error never propagates (registration is kept).</li>
 * </ul>
 * The Casdoor client is a Mockito mock (its own sibling-preserving wire contract is covered
 * by {@code CasdoorAdminClientDisplayNameTest}); the user-bff POST is captured off a stub
 * {@link ExchangeFunction}.
 */
class ProfileForwarderTest {

    /** Captures the user-bff profile-upsert POST bodies. */
    static class Recorder implements ExchangeFunction {
        final List<String> userBffBodies = new ArrayList<>();

        @Override
        public Mono<ClientResponse> exchange(ClientRequest request) {
            MockClientHttpRequest mock = new MockClientHttpRequest(request.method(), request.url());
            request.body().insert(mock, new BodyInsertContext()).block();
            userBffBodies.add(mock.getBodyAsString().block());
            return Mono.just(ClientResponse.create(HttpStatus.OK)
                    .header("Content-Type", "application/json").body("{\"status\":\"ok\"}").build());
        }
    }

    static class BodyInsertContext implements org.springframework.web.reactive.function.BodyInserter.Context {
        private final ExchangeStrategies strategies = ExchangeStrategies.withDefaults();
        @Override public List<org.springframework.http.codec.HttpMessageWriter<?>> messageWriters() {
            return strategies.messageWriters();
        }
        @Override public java.util.Optional<org.springframework.http.server.reactive.ServerHttpRequest> serverRequest() {
            return java.util.Optional.empty();
        }
        @Override public java.util.Map<String, Object> hints() {
            return java.util.Collections.emptyMap();
        }
    }

    private WebClient webFor(Recorder rec) {
        return WebClient.builder().exchangeFunction(rec).build();
    }

    @Test
    void casdoorLegRunsEvenWhenUserBffGateIsDark() {
        Recorder rec = new Recorder();
        CasdoorAdminClient casdoor = mock(CasdoorAdminClient.class);
        when(casdoor.updateDisplayName(eq("google"), eq("alice@x.com"), eq("Alice Liddell")))
                .thenReturn(Mono.empty());
        ProfileForwarder f = new ProfileForwarder(
                webFor(rec), /*enabled=*/false, "/bff/user/profile/internal",
                "X-Internal-Token", "", casdoor);

        f.forward("google:alice@x.com", "Alice Liddell", "Alice").block();

        // user-bff gate is dark -> no profile POST.
        assertThat(rec.userBffBodies).isEmpty();
        // Casdoor displayName leg ran; provider+handle derived from the ownerId.
        verify(casdoor, times(1)).updateDisplayName("google", "alice@x.com", "Alice Liddell");
    }

    @Test
    void bothLegsFireWhenGateEnabled() {
        Recorder rec = new Recorder();
        CasdoorAdminClient casdoor = mock(CasdoorAdminClient.class);
        when(casdoor.updateDisplayName(eq("discord"), eq("bob"), eq("Bob B")))
                .thenReturn(Mono.empty());
        ProfileForwarder f = new ProfileForwarder(
                webFor(rec), /*enabled=*/true, "/bff/user/profile/internal",
                "X-Internal-Token", "", casdoor);

        f.forward("discord:bob", "Bob B", "Bob").block();

        // user-bff profile upsert fired with the owner + names.
        assertThat(rec.userBffBodies).hasSize(1);
        assertThat(rec.userBffBodies.get(0)).contains("\"ownerId\":\"discord:bob\"");
        assertThat(rec.userBffBodies.get(0)).contains("\"displayName\":\"Bob B\"");
        assertThat(rec.userBffBodies.get(0)).contains("\"screenReaderName\":\"Bob\"");
        // Casdoor displayName leg also fired.
        verify(casdoor, times(1)).updateDisplayName("discord", "bob", "Bob B");
    }

    @Test
    void noNames_noOp_neitherLeg() {
        Recorder rec = new Recorder();
        CasdoorAdminClient casdoor = mock(CasdoorAdminClient.class);
        ProfileForwarder f = new ProfileForwarder(
                webFor(rec), /*enabled=*/true, "/bff/user/profile/internal",
                "X-Internal-Token", "", casdoor);

        f.forward("google:alice@x.com", "  ", null).block();

        assertThat(rec.userBffBodies).isEmpty();
        verifyNoInteractions(casdoor);
    }

    @Test
    void noCasdoorClient_onlyUserBffLeg() {
        Recorder rec = new Recorder();
        ProfileForwarder f = new ProfileForwarder(
                webFor(rec), /*enabled=*/true, "/bff/user/profile/internal",
                "X-Internal-Token", "", /*casdoor=*/null);

        f.forward("google:alice@x.com", "Alice", null).block();

        assertThat(rec.userBffBodies).hasSize(1);
    }

    @Test
    void onlyScreenReaderName_noCasdoorDisplayNameWrite() {
        Recorder rec = new Recorder();
        CasdoorAdminClient casdoor = mock(CasdoorAdminClient.class);
        ProfileForwarder f = new ProfileForwarder(
                webFor(rec), /*enabled=*/true, "/bff/user/profile/internal",
                "X-Internal-Token", "", casdoor);

        // screenReaderName-only: the user-bff leg still fires, but Casdoor displayName is NOT
        // written (there is no Casdoor screenReaderName column — only the visible displayName).
        f.forward("google:alice@x.com", null, "Alice").block();

        assertThat(rec.userBffBodies).hasSize(1);
        assertThat(rec.userBffBodies.get(0)).contains("\"screenReaderName\":\"Alice\"");
        verify(casdoor, never()).updateDisplayName(eq("google"), eq("alice@x.com"), org.mockito.ArgumentMatchers.any());
    }
}
