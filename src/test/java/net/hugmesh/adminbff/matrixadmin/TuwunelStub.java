package net.hugmesh.adminbff.matrixadmin;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.client.reactive.MockClientHttpRequest;
import org.springframework.web.reactive.function.BodyInserter;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.ExchangeStrategies;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.http.server.reactive.ServerHttpRequest;
import reactor.core.publisher.Mono;

import java.util.Optional;

/**
 * A stub tuwunel for the admin-room transport: records every request (method, decoded path,
 * Authorization header, body text) and answers the directory lookup and the send with
 * configurable status/body. No socket is opened.
 */
final class TuwunelStub implements ExchangeFunction {

    record Seen(HttpMethod method, String path, String authorization, String body) { }

    final List<Seen> seen = new CopyOnWriteArrayList<>();
    volatile HttpStatus directoryStatus = HttpStatus.OK;
    volatile String directoryBody = "{\"room_id\":\"!adminroom:hugmesh.net\",\"servers\":[\"hugmesh.net\"]}";
    volatile HttpStatus sendStatus = HttpStatus.OK;
    volatile String sendBody = "{\"event_id\":\"$evt-1\"}";
    /** When true every exchange never answers (drives the timeout path). */
    volatile boolean hang;

    @Override
    public Mono<ClientResponse> exchange(ClientRequest request) {
        MockClientHttpRequest captured = new MockClientHttpRequest(request.method(), request.url());
        BodyInserter.Context ctx = new BodyInserter.Context() {
            @Override
            public List<org.springframework.http.codec.HttpMessageWriter<?>> messageWriters() {
                return ExchangeStrategies.withDefaults().messageWriters();
            }

            @Override
            public Optional<ServerHttpRequest> serverRequest() {
                return Optional.empty();
            }

            @Override
            public Map<String, Object> hints() {
                return Map.of();
            }
        };
        return request.body().insert(captured, ctx)
                .then(Mono.defer(() -> captured.getBodyAsString().defaultIfEmpty("")))
                .defaultIfEmpty("")
                .flatMap(body -> {
                    seen.add(new Seen(request.method(), request.url().getPath(),
                            request.headers().getFirst("Authorization"), body));
                    if (hang) {
                        return Mono.never();
                    }
                    boolean directory = request.method() == HttpMethod.GET;
                    HttpStatus status = directory ? directoryStatus : sendStatus;
                    String json = directory ? directoryBody : sendBody;
                    return Mono.just(ClientResponse.create(status)
                            .header("Content-Type", "application/json")
                            .body(json).build());
                });
    }

    WebClient webClient() {
        return WebClient.builder().baseUrl("http://tuwunel.invalid:8008").exchangeFunction(this).build();
    }

    List<Seen> sends() {
        return seen.stream().filter(s -> s.method() == HttpMethod.PUT).toList();
    }

    List<Seen> lookups() {
        return seen.stream().filter(s -> s.method() == HttpMethod.GET).toList();
    }
}
