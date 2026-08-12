package net.hugmesh.adminbff.config;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import org.springframework.beans.factory.ObjectProvider;
import net.hugmesh.adminbff.suspension.SuspensionService;
import net.hugmesh.authcore.account.AccountStatus;

import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * The admin-bff-local bff_ suspension gate: a suspended/banned native-login session is
 * 403'd on admin-bff's own surface (parity with the mod-bff/user-bff sibling filters),
 * while active bff_ sessions, JWT principals, and unauthenticated requests pass through.
 * Also pins the exactly-once chain invariant.
 */
class BffSessionSuspensionGateWebFilterTest {

    @SuppressWarnings("unchecked")
    private static ObjectProvider<SuspensionService> provider(SuspensionService svc) {
        ObjectProvider<SuspensionService> op = mock(ObjectProvider.class);
        when(op.getIfAvailable()).thenReturn(svc);
        return op;
    }

    private static UsernamePasswordAuthenticationToken bffAuth(String accountId) {
        return new UsernamePasswordAuthenticationToken(accountId, null,
                List.of(new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    private MockServerWebExchange exchange() {
        return MockServerWebExchange.from(MockServerHttpRequest.get("/bff/admin/allowlist").build());
    }

    /** A chain that records whether it was invoked (and how many times). */
    private static WebFilterChain countingChain(AtomicBoolean called) {
        return ex -> {
            called.set(true);
            return Mono.empty();
        };
    }

    private void run(BffSessionSuspensionGateWebFilter filter, MockServerWebExchange ex,
                     WebFilterChain chain, Authentication auth) {
        Mono<Void> mono = filter.filter(ex, chain);
        if (auth != null) {
            mono = mono.contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth));
        }
        StepVerifier.create(mono).verifyComplete();
    }

    @Test
    void suspendedBffSession_403_chainNeverInvoked() {
        SuspensionService suspensions = mock(SuspensionService.class);
        when(suspensions.statusFor("alice"))
                .thenReturn(Mono.just(new AccountStatus(AccountStatus.SUSPENDED, Instant.now().plusSeconds(3600), "abuse")));
        var filter = new BffSessionSuspensionGateWebFilter(provider(suspensions));
        var ex = exchange();
        var chainCalled = new AtomicBoolean(false);

        run(filter, ex, countingChain(chainCalled), bffAuth("casdoor:alice"));

        assertThat(ex.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(ex.getResponse().getHeaders().getFirst("X-Bff-Denied")).isEqualTo("account-suspended");
        assertThat(chainCalled).as("downstream must not run for a suspended session").isFalse();
    }

    @Test
    void bannedBffSession_403() {
        SuspensionService suspensions = mock(SuspensionService.class);
        when(suspensions.statusFor("bob"))
                .thenReturn(Mono.just(new AccountStatus(AccountStatus.BANNED, null, "banned")));
        var filter = new BffSessionSuspensionGateWebFilter(provider(suspensions));
        var ex = exchange();
        var chainCalled = new AtomicBoolean(false);

        run(filter, ex, countingChain(chainCalled), bffAuth("casdoor:bob"));

        assertThat(ex.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(chainCalled).isFalse();
    }

    @Test
    void activeBffSession_passesThroughExactlyOnce() {
        SuspensionService suspensions = mock(SuspensionService.class);
        when(suspensions.statusFor("alice")).thenReturn(Mono.just(AccountStatus.active()));
        var filter = new BffSessionSuspensionGateWebFilter(provider(suspensions));
        var ex = exchange();
        var count = new java.util.concurrent.atomic.AtomicInteger();
        WebFilterChain chain = e -> { count.incrementAndGet(); return Mono.empty(); };

        run(filter, ex, chain, bffAuth("casdoor:alice"));

        assertThat(ex.getResponse().getStatusCode()).isNull(); // not rejected
        assertThat(count.get()).as("chain invoked exactly once").isEqualTo(1);
    }

    @Test
    void jwtPrincipal_notGated_passesThrough_suspensionNeverConsulted() {
        SuspensionService suspensions = mock(SuspensionService.class);
        var filter = new BffSessionSuspensionGateWebFilter(provider(suspensions));
        var ex = exchange();
        var chainCalled = new AtomicBoolean(false);
        Jwt jwt = Jwt.withTokenValue("t").header("alg", "none").subject("carol").claim("x", "y").build();
        var jwtAuth = new org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken(jwt);

        run(filter, ex, countingChain(chainCalled), jwtAuth);

        assertThat(ex.getResponse().getStatusCode()).isNull();
        assertThat(chainCalled).isTrue();
        org.mockito.Mockito.verifyNoInteractions(suspensions); // JWT suspension is not this filter's job
    }

    @Test
    void unauthenticated_passesThrough() {
        SuspensionService suspensions = mock(SuspensionService.class);
        var filter = new BffSessionSuspensionGateWebFilter(provider(suspensions));
        var ex = exchange();
        var chainCalled = new AtomicBoolean(false);

        run(filter, ex, countingChain(chainCalled), null); // no security context

        assertThat(ex.getResponse().getStatusCode()).isNull();
        assertThat(chainCalled).isTrue();
        org.mockito.Mockito.verifyNoInteractions(suspensions);
    }
}
