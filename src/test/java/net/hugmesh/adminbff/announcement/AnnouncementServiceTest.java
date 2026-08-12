package net.hugmesh.adminbff.announcement;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.security.PrincipalDomain;
import net.hugmesh.commons.web.ApiException;
import net.hugmesh.adminbff.web.dto.AnnouncementRequest;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Service-layer behaviour: sanitisation on create, cross-field validation (→400),
 * and the akkoma propagation stub-seam — publishing a target_akkoma announcement
 * invokes the (stubbed/recording) client and persists akkoma_ref; unpublish removes
 * it. The repository is mocked; its SQL is covered in AnnouncementRepositoryTest.
 * Domain-isolation (cross-brand DENY) is covered in AnnouncementDomainScopeTest.
 */
class AnnouncementServiceTest {

    private AnnouncementRepository repo;
    private AnnouncementMastodonClient akkoma;
    private AnnouncementService service;

    /** Superadmin scope (unscoped) — service tests focus on business logic, not isolation. */
    private static final PrincipalDomain SUPER = superadminScope();

    private static PrincipalDomain superadminScope() {
        org.springframework.security.oauth2.jwt.Jwt jwt =
                org.springframework.security.oauth2.jwt.Jwt.withTokenValue("t")
                        .header("alg", "none")
                        .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                        .subject("u").issuer("https://idp.example")
                        .claim("roles", List.of("superadmin")).build();
        var auth = new org.springframework.security.oauth2.server.resource.authentication
                .JwtAuthenticationToken(jwt,
                List.of(new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_SUPERADMIN")));
        return PrincipalDomain.of(auth, new net.hugmesh.commons.security.DomainRegistry("", ""));
    }

    @BeforeEach
    void setUp() {
        repo = mock(AnnouncementRepository.class);
        akkoma = mock(AnnouncementMastodonClient.class);
        service = new AnnouncementService(repo, new AnnouncementSanitizer(), akkoma);
        // setAkkomaRef default: succeed.
        when(repo.setAkkomaRef(any(), any())).thenReturn(Mono.empty());
    }

    private static AnnouncementRequest req(String state, boolean home, boolean akkoma) {
        return new AnnouncementRequest("Title", "<p>body</p><script>alert(1)</script>",
                "html", state, home, false, akkoma, false, 0, null, null, "UTC", true);
    }

    private static Announcement row(String id, String state, boolean akkoma, String akkomaRef) {
        return new Announcement(id, "Title", "<p>body</p>", "html", state,
                true, false, akkoma, false, 0, null, null, "UTC", true, "admin@x", akkomaRef,
                Instant.now(), Instant.now(), "default");
    }

    @Test
    void create_sanitizesBodyHtmlBeforePersist() {
        when(repo.insert(any())).thenAnswer(inv -> {
            Announcement a = inv.getArgument(0);
            // The body handed to the repo must already be sanitised.
            assertThat(a.bodyHtml()).doesNotContain("<script").contains("<p>body</p>");
            return Mono.just(row("id1", a.state(), a.targetAkkoma(), null));
        });

        Announcement created = service.create(req("draft", true, false), "admin@x", SUPER).block();
        assertThat(created.id()).isEqualTo("id1");
        // draft + not-akkoma → no akkoma propagation.
        verify(akkoma, never()).createLocalAnnouncement(any());
    }

    @Test
    void create_publishedAkkomaTarget_invokesClientAndRecordsRef() {
        when(repo.insert(any())).thenAnswer(inv ->
                Mono.just(row("id2", "published", true, null)));
        when(akkoma.createLocalAnnouncement(any())).thenReturn(Mono.just(AkkomaOutcome.created("akk-99")));

        Announcement created = service.create(req("published", true, true), "admin@x", SUPER).block();

        verify(akkoma, times(1)).createLocalAnnouncement(any());
        // The returned akkoma id is persisted as akkoma_ref.
        verify(repo).setAkkomaRef("id2", "akk-99");
        assertThat(created.akkomaRef()).isEqualTo("akk-99");
    }

    @Test
    void create_publishedAkkomaTarget_stubbed_keepsRowNoRef() {
        when(repo.insert(any())).thenAnswer(inv -> Mono.just(row("id3", "published", true, null)));
        when(akkoma.createLocalAnnouncement(any())).thenReturn(Mono.just(AkkomaOutcome.stubbed()));

        Announcement created = service.create(req("published", true, true), "admin@x", SUPER).block();

        verify(akkoma, times(1)).createLocalAnnouncement(any());
        // Stubbed → no ref persisted, row still stands.
        verify(repo, never()).setAkkomaRef(eq("id3"), any());
        assertThat(created.akkomaRef()).isNull();
    }

    // Real UUIDs for the ids that flow through the service's id-parse guard.
    private static final String UUID4 = "44444444-4444-4444-4444-444444444444";
    private static final String UUID5 = "55555555-5555-5555-5555-555555555555";

    @Test
    void update_unpublishingAkkomaTarget_removesAkkomaPost() {
        // Existing: published + akkoma + has a ref.
        when(repo.find(eq(UUID4), any(PrincipalDomain.class))).thenReturn(Mono.just(row(UUID4, "published", true, "akk-77")));
        // The edit drops it to draft (still akkoma-targeted) → should remove.
        when(repo.update(eq(UUID4), any())).thenReturn(Mono.just(row(UUID4, "draft", true, "akk-77")));
        when(akkoma.removeAnnouncement("akk-77")).thenReturn(Mono.just(AkkomaOutcome.ok()));

        AnnouncementRequest edit = req("draft", true, true);
        Announcement updated = service.update(UUID4, edit, "admin@x", SUPER).block();

        verify(akkoma).removeAnnouncement("akk-77");
        verify(repo).setAkkomaRef(UUID4, null);
        assertThat(updated.akkomaRef()).isNull();
    }

    @Test
    void delete_removesAkkomaPostThenRow() {
        when(repo.find(eq(UUID5), any(PrincipalDomain.class))).thenReturn(Mono.just(row(UUID5, "published", true, "akk-55")));
        when(akkoma.removeAnnouncement("akk-55")).thenReturn(Mono.just(AkkomaOutcome.ok()));
        when(repo.delete(eq(UUID5), any(PrincipalDomain.class))).thenReturn(Mono.empty());

        service.delete(UUID5, SUPER).block();

        verify(akkoma).removeAnnouncement("akk-55");
        verify(repo).delete(eq(UUID5), any(PrincipalDomain.class));
    }

    @Test
    void create_noTargetFlag_isBadRequest() {
        AnnouncementRequest noTarget = new AnnouncementRequest("T", "<p>b</p>", "html", "draft",
                false, false, false, false, 0, null, null, "UTC", true);
        assertThatThrownBy(() -> service.create(noTarget, "admin@x", SUPER).block())
                .isInstanceOf(ApiException.class)
                .hasMessageContaining("at least one target");
        verify(repo, never()).insert(any());
    }

    @Test
    void create_endsBeforeStarts_isBadRequest() {
        Instant now = Instant.now();
        AnnouncementRequest badWindow = new AnnouncementRequest("T", "<p>b</p>", "html", "draft",
                true, false, false, false, 0,
                now.plus(2, ChronoUnit.HOURS), now.plus(1, ChronoUnit.HOURS), "UTC", true);
        assertThatThrownBy(() -> service.create(badWindow, "admin@x", SUPER).block())
                .isInstanceOf(ApiException.class)
                .hasMessageContaining("ends_at must be after starts_at");
        verify(repo, never()).insert(any());
    }

    @Test
    void get_unknownId_notFound() {
        String id = "11111111-2222-3333-4444-555555555555";
        when(repo.find(eq(id), any(PrincipalDomain.class))).thenReturn(Mono.empty());
        assertThatThrownBy(() -> service.get(id, SUPER).block())
                .isInstanceOf(ApiException.class)
                .hasMessageContaining("not found");
    }

    @Test
    void get_malformedId_notFound() {
        assertThatThrownBy(() -> service.get("not-a-uuid", SUPER).block())
                .isInstanceOf(ApiException.class)
                .hasMessageContaining("not found");
    }

    @Test
    void reconcile_removesStaleAkkomaPostsAndClearsRef() {
        Announcement stale = row("id6", "draft", true, "akk-stale");
        when(repo.expiredWithAkkomaRef(any())).thenReturn(Flux.just(stale));
        when(akkoma.removeAnnouncement("akk-stale")).thenReturn(Mono.just(AkkomaOutcome.ok()));

        service.reconcileAkkomaReactive().block();

        verify(akkoma).removeAnnouncement("akk-stale");
        verify(repo).setAkkomaRef("id6", null);
    }

    @Test
    void update_unpublish_degradedRemove_keepsAkkomaRef() {
        // Honest-disclosure pin: an UNCONFIRMED removal (e.g. the live-verified
        // force-HTTPS 308 the client now raises to degraded) must NOT clear akkoma_ref —
        // clearing it would permanently orphan the live Akkoma post. The ref stays so
        // the reconcile sweep can retry.
        when(repo.find(eq(UUID4), any(PrincipalDomain.class)))
                .thenReturn(Mono.just(row(UUID4, "published", true, "akk-77")));
        when(repo.update(eq(UUID4), any())).thenReturn(Mono.just(row(UUID4, "draft", true, "akk-77")));
        when(akkoma.removeAnnouncement("akk-77"))
                .thenReturn(Mono.just(AkkomaOutcome.degraded("http-308")));

        Announcement updated = service.update(UUID4, req("draft", true, true), "admin@x", SUPER).block();

        verify(akkoma).removeAnnouncement("akk-77");
        verify(repo, never()).setAkkomaRef(eq(UUID4), any());
        assertThat(updated.akkomaRef()).isEqualTo("akk-77");
    }

    @Test
    void reconcile_degradedRemove_keepsRefForRetry() {
        Announcement stale = row("id7", "draft", true, "akk-stuck");
        when(repo.expiredWithAkkomaRef(any())).thenReturn(Flux.just(stale));
        when(akkoma.removeAnnouncement("akk-stuck"))
                .thenReturn(Mono.just(AkkomaOutcome.degraded("http-308")));

        service.reconcileAkkomaReactive().block();

        // Unconfirmed removal: the ref survives so the NEXT sweep retries.
        verify(akkoma).removeAnnouncement("akk-stuck");
        verify(repo, never()).setAkkomaRef(eq("id7"), any());
    }
}
