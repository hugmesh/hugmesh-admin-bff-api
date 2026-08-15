package net.hugmesh.adminbff.directory;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Flux;
import reactor.test.StepVerifier;
import net.hugmesh.authcore.account.AccountStore;
import net.hugmesh.commons.security.PrincipalDomain;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The SECURITY-relevant half of the user typeahead: proves the domain predicate is applied
 * by the QUERY, not by a post-hoc filter, and that the cap/ranking contract the picker
 * relies on holds.
 *
 * <p>The distinction the first two tests draw is the one that matters — a scoped ADMIN must
 * reach the {@code AndDomain} finder (SQL {@code WHERE domain = :domain}) and must NEVER
 * reach the unscoped one. A test that only asserted "brand Y's user is absent from the
 * result" would still pass if the service read every brand and filtered afterwards, which
 * is exactly the enumeration hole this endpoint exists to close.
 */
class UserDirectoryServiceTest {

    AccountStore store;
    UserDirectoryService service;

    @BeforeEach
    void setUp() {
        store = mock(AccountStore.class);
        service = new UserDirectoryService(store);
    }

    /** Empty both providers unless a test overrides one — search reads BOTH streams. */
    private void emptyDirectory() {
        when(store.allowedEmails(eq("brandx"))).thenReturn(Flux.empty());
        when(store.allowedDiscord(eq("brandx"))).thenReturn(Flux.empty());
        when(store.allowedEmails()).thenReturn(Flux.empty());
        when(store.allowedDiscord()).thenReturn(Flux.empty());
    }

    // ════════════════════════ domain scoping ═══════════════════════════════════════

    @Test
    void scopedAdmin_readsOnlyTheDomainScopedFinder() {
        emptyDirectory();
        when(store.allowedEmails(eq("brandx")))
                .thenReturn(Flux.just("alice@brandx.example", "bob@brandx.example"));

        List<DirectoryUser> out = service
                .search(PrincipalDomain.forDomain("brandx"), "ali", 10).block();

        assertThat(out).extracting(DirectoryUser::username).containsExactly("alice");
        verify(store).allowedEmails(eq("brandx"));
        verify(store).allowedDiscord(eq("brandx"));
        // The unscoped (cross-brand) finders must never be touched by a scoped admin.
        verify(store, never()).allowedEmails();
        verify(store, never()).allowedDiscord();
    }

    @Test
    void superadmin_readsTheUnscopedFinder() {
        emptyDirectory();
        when(store.allowedEmails()).thenReturn(Flux.just("alice@brandy.example"));

        List<DirectoryUser> out = service
                .search(PrincipalDomain.superadminFor("brandx"), "ali", 10).block();

        assertThat(out).extracting(DirectoryUser::username).containsExactly("alice");
        verify(store).allowedEmails();
        verify(store).allowedDiscord();
        verify(store, never()).allowedEmails(eq("brandx"));
    }

    @Test
    void nullScope_failsClosedToNoDomain() {
        when(store.allowedEmails(eq(PrincipalDomain.NO_DOMAIN))).thenReturn(Flux.empty());
        when(store.allowedDiscord(eq(PrincipalDomain.NO_DOMAIN))).thenReturn(Flux.empty());

        StepVerifier.create(service.search(null, "ali", 10))
                .expectNext(List.of())
                .verifyComplete();

        // NO_DOMAIN is a sentinel no real brand can equal, so this reads nothing at all.
        verify(store).allowedEmails(eq(PrincipalDomain.NO_DOMAIN));
        verify(store, never()).allowedEmails();
    }

    // ════════════════════════ query contract ═══════════════════════════════════════

    @Test
    void blankQuery_returnsEmpty_withoutTouchingTheDirectory() {
        StepVerifier.create(service.search(PrincipalDomain.forDomain("brandx"), "   ", 10))
                .expectNext(List.of())
                .verifyComplete();

        // "Keep typing" is a server contract: a blank q must not dump the brand's directory.
        verify(store, never()).allowedEmails(eq("brandx"));
        verify(store, never()).allowedDiscord(eq("brandx"));
    }

    @Test
    void matchesHandleAsWellAsDerivedUsername() {
        emptyDirectory();
        when(store.allowedEmails(eq("brandx"))).thenReturn(Flux.just("zed@acme.example"));

        // "acme" appears only in the handle's domain part, never in the derived username.
        List<DirectoryUser> out = service
                .search(PrincipalDomain.forDomain("brandx"), "acme", 10).block();

        assertThat(out).singleElement()
                .satisfies(u -> {
                    assertThat(u.username()).isEqualTo("zed");
                    assertThat(u.handle()).isEqualTo("zed@acme.example");
                    assertThat(u.provider()).isEqualTo("google");
                    assertThat(u.domain()).isEqualTo("brandx");
                });
    }

    @Test
    void discordHandlesKeepTheirFullHandleAsTheUsername() {
        emptyDirectory();
        when(store.allowedDiscord(eq("brandx"))).thenReturn(Flux.just("alice#1234"));

        List<DirectoryUser> out = service
                .search(PrincipalDomain.forDomain("brandx"), "alice", 10).block();

        // CasdoorAdminClient.usernameOf only strips at '@' — a Discord handle passes through.
        assertThat(out).singleElement()
                .satisfies(u -> {
                    assertThat(u.username()).isEqualTo("alice#1234");
                    assertThat(u.provider()).isEqualTo("discord");
                });
    }

    @Test
    void prefixMatchesOutrankSubstringMatchesAcrossProviders() {
        emptyDirectory();
        // The substring hit comes from the email stream (read first); the prefix hit from
        // the discord stream. Per-provider ordering alone would put them the wrong way round.
        when(store.allowedEmails(eq("brandx"))).thenReturn(Flux.just("notal@brandx.example"));
        when(store.allowedDiscord(eq("brandx"))).thenReturn(Flux.just("alpha"));

        List<DirectoryUser> out = service
                .search(PrincipalDomain.forDomain("brandx"), "al", 10).block();

        assertThat(out).extracting(DirectoryUser::username).containsExactly("alpha", "notal");
    }

    @Test
    void limitIsClampedToTheServerCeiling_regardlessOfWhatTheCallerAsks() {
        emptyDirectory();
        // 40 matching handles, more than MAX_LIMIT.
        when(store.allowedEmails(eq("brandx"))).thenReturn(
                Flux.range(0, 40).map(i -> String.format("user%02d@brandx.example", i)));

        List<DirectoryUser> out = service
                .search(PrincipalDomain.forDomain("brandx"), "user", 1_000).block();

        assertThat(out).hasSize(UserDirectoryService.MAX_LIMIT);
    }

    @Test
    void limitBelowOneIsClampedUp() {
        emptyDirectory();
        when(store.allowedEmails(eq("brandx"))).thenReturn(Flux.just("alice@brandx.example"));

        List<DirectoryUser> out = service
                .search(PrincipalDomain.forDomain("brandx"), "alice", 0).block();

        assertThat(out).hasSize(1);
    }
}
