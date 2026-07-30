package systems.hugmesh.adminbff.federation;

import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * Thin wrapper around admin-bff-api's OWN custody-swap endpoint ({@code POST
 * /bff/internal/session/exchange}) — swaps a raw {@code bff_} token for the custody-held
 * Casdoor access JWT. See {@code InternalAccountController#exchange} for the full
 * fail-closed contract this client is a CALLER of (503 custody disabled, 404 unknown
 * session, 401 no custody, 403 suspended/banned); this class does not reinterpret those
 * statuses — {@link SessionExchangeService} does that.
 *
 * <p>A genuine SELF-loopback: admin-bff-api calls its OWN {@code /bff/internal/**}
 * surface over HTTP, exactly as a remote caller (the gateway, mod-bff-api) would — see
 * {@link SessionExchangeConfig} for why this deliberately does NOT take an in-process
 * shortcut despite holding every bean {@code InternalAccountController#exchange} needs in
 * the same JVM, and for the loopback WebClient's mTLS/credential wiring (reusing this
 * service's OWN {@code server.ssl.*}/{@code app.internal.token} — the SAME credential
 * {@code InternalTokenWebFilter} already validates inbound requests against).
 *
 * <p>No fail-closed-stub null check here (mirrors mod-bff-api's {@code
 * AdminBffSessionIntrospectClient}): this client is only ever constructed with a real,
 * non-null {@link WebClient} — see {@link SessionExchangeConfig}. The "is a client even
 * wired" question is answered by the CONSUMER via {@code
 * ObjectProvider<SessionExchangeService>}.
 */
final class SessionExchangeClient implements SessionExchangeTransport {

    private static final String EXCHANGE_PATH = "/bff/internal/session/exchange";

    private final WebClient http;

    SessionExchangeClient(WebClient http) {
        this.http = http;
    }

    /**
     * Exchange a raw {@code bff_} token for the custody JWT. Completes empty on a
     * blank/absent {@code bearer} field in an otherwise-2xx response; any HTTP error
     * status or transport failure (timeout, connection-refused) propagates as an error —
     * the caller ({@link SessionExchangeService}) categorises and degrades.
     */
    @Override
    public Mono<String> exchange(String rawToken) {
        return http.post()
                .uri(EXCHANGE_PATH)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("token", rawToken))
                .retrieve()
                .bodyToMono(ExchangeResponse.class)
                .flatMap(resp -> {
                    String bearer = resp == null ? null : resp.bearer();
                    return (bearer == null || bearer.isBlank()) ? Mono.empty() : Mono.just(bearer);
                });
    }

    /** Response body shape — CONTRACT: reconciled with admin-bff's {@code
     *  InternalAccountController#exchange}, which returns {@code Map.of("bearer", jwt)}.
     *  Package-private (not private) so the JSON decoder's reflection can construct it. */
    record ExchangeResponse(String bearer) {}
}
