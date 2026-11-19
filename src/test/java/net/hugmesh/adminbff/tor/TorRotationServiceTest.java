package net.hugmesh.adminbff.tor;

import net.hugmesh.adminbff.capability.DomainCapability;
import net.hugmesh.adminbff.capability.DomainCapabilityRepository;
import net.hugmesh.commons.security.PrincipalDomain;
import net.hugmesh.commons.web.ApiException;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * hugmesh-generator#652: the request for a new Tor address, and its refusals in order.
 * Nothing is written by a refusal.
 */
class TorRotationServiceTest {

    private final TorRotationRowRepository repo = mock(TorRotationRowRepository.class);
    private final DomainCapabilityRepository caps = mock(DomainCapabilityRepository.class);
    private final TorRotationService svc = new TorRotationService(repo, caps);

    private static DomainCapability row(String domain, boolean granted, boolean enabled) {
        return new DomainCapability("id-" + domain, domain, DomainCapability.TOR_ONION, granted, enabled,
                "root", Instant.now(), 1L);
    }

    private void live(DomainCapability... rows) {
        when(caps.listAll()).thenReturn(Flux.fromArray(rows));
    }

    private static HttpStatus status(Throwable t) {
        return ((ApiException) t).status();
    }

    @Test
    void aDomainAdmin_asksForTheirOwnDomain_andTheCountIsReadBack() {
        live(row(DomainCapability.GLOBAL_DOMAIN, true, false), row("shop", true, true));
        when(repo.increment("shop", "rita")).thenReturn(Mono.just(1L));
        when(repo.findById("shop")).thenReturn(Mono.just(new TorRotationRow("shop", 3L, "rita", Instant.now())));
        StepVerifier.create(svc.request("shop", "shop", PrincipalDomain.forDomain("shop"), "rita"))
                .assertNext(r -> {
                    assertThat(r.domain()).isEqualTo("shop");
                    assertThat(r.requestCount()).isEqualTo(3L);
                    assertThat(r.status()).isEqualTo("requested");
                })
                .verifyComplete();
    }

    @Test
    void aSuperadmin_mayAskForAnyDomain() {
        live(row(DomainCapability.GLOBAL_DOMAIN, true, false), row("shop", true, true));
        when(repo.increment(anyString(), anyString())).thenReturn(Mono.just(1L));
        when(repo.findById("shop")).thenReturn(Mono.just(new TorRotationRow("shop", 1L, "root", Instant.now())));
        StepVerifier.create(svc.request("shop", "shop", PrincipalDomain.superadminFor("default"), "root"))
                .expectNextCount(1).verifyComplete();
    }

    @Test
    void anotherDomainsAdmin_isRefused403_beforeAnythingIsRead() {
        StepVerifier.create(svc.request("shop", "shop", PrincipalDomain.forDomain("brandb"), "bob"))
                .expectErrorSatisfies(t -> assertThat(status(t).value()).isEqualTo(403))
                .verify();
        verify(caps, never()).listAll();
        verify(repo, never()).increment(any(), any());
    }

    @Test
    void theMeshsOwnAddress_andANonSlug_areRefused422_evenForASuperadmin() {
        for (String d : List.of("default", "Shop", "../x", "")) {
            StepVerifier.create(svc.request(d, d, PrincipalDomain.superadminFor("default"), "root"))
                    .expectErrorSatisfies(t -> assertThat(status(t).value()).isEqualTo(422))
                    .verify();
        }
        verify(repo, never()).increment(any(), any());
    }

    @Test
    void aWrongConfirmation_isRefused422() {
        StepVerifier.create(svc.request("shop", "shopp", PrincipalDomain.forDomain("shop"), "rita"))
                .expectErrorSatisfies(t -> assertThat(status(t).value()).isEqualTo(422))
                .verify();
        verify(repo, never()).increment(any(), any());
    }

    @Test
    void aDomainWithoutItsOwnTorAddress_isRefused409() {
        // the platform switch off; the row inactive; the row missing
        List<DomainCapability[]> cases = List.of(
                new DomainCapability[] {row(DomainCapability.GLOBAL_DOMAIN, false, false), row("shop", true, true)},
                new DomainCapability[] {row(DomainCapability.GLOBAL_DOMAIN, true, false), row("shop", true, false)},
                new DomainCapability[] {row(DomainCapability.GLOBAL_DOMAIN, true, false)});
        for (DomainCapability[] rows : cases) {
            live(rows);
            StepVerifier.create(svc.request("shop", "shop", PrincipalDomain.forDomain("shop"), "rita"))
                    .expectErrorSatisfies(t -> assertThat(status(t).value()).isEqualTo(409))
                    .verify();
        }
        verify(repo, never()).increment(any(), any());
    }
}
