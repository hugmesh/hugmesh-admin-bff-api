package net.hugmesh.adminbff.servicecatalog.scaffold;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import net.hugmesh.commons.web.ApiException;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The scaffold service's create-validation + archive rules (Mockito unit — no Spring/Docker):
 * archetype-catalog membership, the spring-bff Java-package-safe-slug gate, the archive
 * 404 / domain-guard, and the requested-&gt;archived materialisation CAS.
 */
class ScaffoldServiceTest {

    private final ServiceScaffoldRepository repo = mock(ServiceScaffoldRepository.class);
    private final ScaffoldArchiveRenderer renderer = mock(ScaffoldArchiveRenderer.class);
    private final ScaffoldRenderContext context = new ScaffoldRenderContext(
            "hugmesh", "", "hugmesh", "mesh_default", "hugmesh", "http://headscale", "prod");
    private final ScaffoldService service = new ScaffoldService(repo, renderer, context);

    private static ServiceScaffold row(String archetype) {
        return new ServiceScaffold("scaf-1", "acme.test", "owncast", archetype, "Owncast",
                "/owncast", "ROLE_OWNCAST", ServiceScaffold.STATE_REQUESTED, "root",
                Instant.now(), Instant.now());
    }

    private static void expect400(Mono<?> mono, String messageFragment) {
        StepVerifier.create(mono)
                .expectErrorSatisfies(e -> {
                    assertThat(e).isInstanceOf(ApiException.class);
                    assertThat(((ApiException) e).status()).isEqualTo(HttpStatus.BAD_REQUEST);
                    assertThat(e.getMessage()).contains(messageFragment);
                })
                .verify();
    }

    @Test
    void create_unknownArchetype_400_noWrite() {
        // "nope" passes the DTO ^[a-z0-9-]{1,64}$ pattern but is not a catalog member.
        expect400(service.create("acme.test", "owncast", "nope", null, null, null, "root"),
                "unknown archetype");
        verify(repo, never()).insertRequested(any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    void create_springBff_hyphenatedSlug_400_noWrite() {
        // slug("own-cast") = "own-cast" — not ^[a-z0-9]+$, so it cannot be a Java package segment.
        expect400(service.create("acme.test", "own-cast", "spring-bff", null, null, null, "root"),
                "not a valid Java package segment");
        verify(repo, never()).insertRequested(any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    void create_springBff_cleanSlug_persistsRequested() {
        when(repo.insertRequested(eq("acme.test"), eq("owncast"), eq("spring-bff"), eq("Owncast"),
                eq("/owncast"), eq("ROLE_OWNCAST"), eq("root")))
                .thenReturn(Mono.just(row("spring-bff")));
        StepVerifier.create(service.create("acme.test", "owncast", "spring-bff", "Owncast",
                        "/owncast", "ROLE_OWNCAST", "root"))
                .assertNext(s -> {
                    assertThat(s.archetype()).isEqualTo("spring-bff");
                    assertThat(s.state()).isEqualTo(ServiceScaffold.STATE_REQUESTED);
                })
                .verifyComplete();
        verify(repo).insertRequested("acme.test", "owncast", "spring-bff", "Owncast", "/owncast",
                "ROLE_OWNCAST", "root");
    }

    @Test
    void create_angularMfe_hyphenatedSlugAllowed_persists() {
        // angular archetypes do NOT feed a Java package, so a hyphenated slug is fine.
        when(repo.insertRequested(eq("acme.test"), eq("my-remote"), eq("angular-mfe"), any(), any(),
                any(), eq("root"))).thenReturn(Mono.just(row("angular-mfe")));
        StepVerifier.create(service.create("acme.test", "my-remote", "angular-mfe", null, null, null, "root"))
                .expectNextCount(1)
                .verifyComplete();
        verify(repo).insertRequested("acme.test", "my-remote", "angular-mfe", null, null, null, "root");
    }

    @Test
    void archive_unknownId_404() {
        when(repo.findById(eq("nope"))).thenReturn(Mono.empty());
        StepVerifier.create(service.archive("acme.test", "nope"))
                .expectErrorSatisfies(e -> {
                    assertThat(e).isInstanceOf(ApiException.class);
                    assertThat(((ApiException) e).status()).isEqualTo(HttpStatus.NOT_FOUND);
                })
                .verify();
        verify(renderer, never()).render(any(), any(), anyBoolean(), any());
    }

    @Test
    void archive_domainMismatch_400_noRenderNoArchive() {
        when(repo.findById(eq("scaf-1"))).thenReturn(Mono.just(row("spring-bff")));
        expect400(service.archive("other.test", "scaf-1"), "is not in domain");
        verify(renderer, never()).render(any(), any(), anyBoolean(), any());
        verify(repo, never()).markArchived(any());
    }

    @Test
    void archive_happyPath_rendersAndCasesArchived() {
        byte[] zip = {1, 2, 3};
        when(repo.findById(eq("scaf-1"))).thenReturn(Mono.just(row("spring-bff")));
        when(renderer.render(eq("spring-bff"), eq("owncast"), eq(true), any())).thenReturn(zip);
        when(repo.markArchived(eq("scaf-1"))).thenReturn(Mono.just(1L));
        StepVerifier.create(service.archive("acme.test", "scaf-1"))
                .assertNext(bytes -> assertThat(bytes).containsExactly(1, 2, 3))
                .verifyComplete();
        verify(renderer).render(eq("spring-bff"), eq("owncast"), eq(true), any());
        verify(repo).markArchived("scaf-1");
    }
}
