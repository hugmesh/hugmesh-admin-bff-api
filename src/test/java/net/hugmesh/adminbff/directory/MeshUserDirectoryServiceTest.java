package net.hugmesh.adminbff.directory;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Flux;
import reactor.test.StepVerifier;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.PrincipalDomain;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * The SECURITY half of the member directory: the domain predicate is applied by the QUERY (the caller's
 * issuers in the WHERE), an unresolvable scope fails closed without a query, only SUPERADMIN reaches the
 * unscoped finder, a short fragment reads nothing, the cap is the SQL limit, and no row can carry an e-mail.
 */
class MeshUserDirectoryServiceTest {

    static final String ISSUER_X = "https://id.brandx.example";
    static final String ISSUER_Y = "https://id.brandy.example";

    MeshUserDirectoryRepository repo;
    DomainRegistry domains;
    MeshUserDirectoryService service;

    @BeforeEach
    void setUp() {
        repo = mock(MeshUserDirectoryRepository.class);
        domains = mock(DomainRegistry.class);
        when(domains.trustedIssuers()).thenReturn(Set.of(ISSUER_X, ISSUER_Y));
        when(domains.domainOf(ISSUER_X)).thenReturn("brandx");
        when(domains.domainOf(ISSUER_Y)).thenReturn("brandy");
        when(domains.isMultiIssuer()).thenReturn(true);
        service = new MeshUserDirectoryService(repo, domains);
    }

    private static MeshUserRow row(String user, String localpart, String issuer) {
        return new MeshUserRow("id-" + user, user, localpart, issuer);
    }

    @Test
    void a_scoped_member_reaches_only_the_issuers_of_their_own_domain_and_never_the_unscoped_finder() {
        when(repo.searchInIssuers(anyCollection(), anyString(), anyString(), anyInt()))
                .thenReturn(Flux.just(row("alice", "alice", ISSUER_X)));

        StepVerifier.create(service.search(PrincipalDomain.forDomain("brandx"), "ali", 10))
                .assertNext(list -> assertThat(list).containsExactly(new MeshUser("alice", "alice", "brandx")))
                .verifyComplete();

        verify(repo).searchInIssuers(eq(Set.of(ISSUER_X)), eq("%ali%"), eq("ali%"), eq(10));
        verify(repo, never()).searchAll(anyString(), anyString(), anyInt());
        verify(repo, never()).searchInIssuersOrUnstamped(anyCollection(), anyString(), anyString(), anyInt());
    }

    @Test
    void only_a_superadmin_reaches_the_unscoped_finder() {
        when(repo.searchAll(anyString(), anyString(), anyInt()))
                .thenReturn(Flux.just(row("alice", "alice", ISSUER_X), row("alina", null, ISSUER_Y)));

        StepVerifier.create(service.search(PrincipalDomain.superadminFor("brandx"), "ali", 10))
                .assertNext(list -> assertThat(list).extracting(MeshUser::domain).containsExactly("brandx", "brandy"))
                .verifyComplete();

        verify(repo).searchAll("%ali%", "ali%", 10);
        verify(repo, never()).searchInIssuers(anyCollection(), anyString(), anyString(), anyInt());
    }

    @Test
    void a_scope_that_resolves_to_no_issuer_fails_closed_without_a_query() {
        StepVerifier.create(service.search(PrincipalDomain.forDomain("no-such-brand"), "ali", 10))
                .assertNext(list -> assertThat(list).isEmpty())
                .verifyComplete();
        StepVerifier.create(service.search(null, "ali", 10))
                .assertNext(list -> assertThat(list).isEmpty())
                .verifyComplete();
        verifyNoInteractions(repo);
    }

    @Test
    void a_fragment_shorter_than_the_minimum_reads_nothing() {
        for (String q : new String[] {null, "", " ", "a", " a "}) {
            StepVerifier.create(service.search(PrincipalDomain.forDomain("brandx"), q, 10))
                    .assertNext(list -> assertThat(list).isEmpty())
                    .verifyComplete();
        }
        verifyNoInteractions(repo);
    }

    @Test
    void the_cap_is_clamped_into_the_sql_limit_whatever_is_asked_for() {
        when(repo.searchInIssuers(anyCollection(), anyString(), anyString(), anyInt())).thenReturn(Flux.empty());

        StepVerifier.create(service.search(PrincipalDomain.forDomain("brandx"), "ali", 100000)).expectNextCount(1).verifyComplete();
        StepVerifier.create(service.search(PrincipalDomain.forDomain("brandx"), "ali", -5)).expectNextCount(1).verifyComplete();

        verify(repo).searchInIssuers(any(), anyString(), anyString(), eq(MeshUserDirectoryService.MAX_LIMIT));
        verify(repo).searchInIssuers(any(), anyString(), anyString(), eq(1));
    }

    @Test
    void like_metacharacters_in_the_typed_text_match_themselves() {
        when(repo.searchInIssuers(anyCollection(), anyString(), anyString(), anyInt())).thenReturn(Flux.empty());

        StepVerifier.create(service.search(PrincipalDomain.forDomain("brandx"), "100%_a\\", 10)).expectNextCount(1).verifyComplete();

        verify(repo).searchInIssuers(any(), eq("%100\\%\\_a\\\\%"), eq("100\\%\\_a\\\\%"), eq(10));
    }

    @Test
    void a_single_issuer_deployment_also_reads_rows_never_stamped_with_an_issuer() {
        when(domains.isMultiIssuer()).thenReturn(false);
        when(repo.searchInIssuersOrUnstamped(anyCollection(), anyString(), anyString(), anyInt()))
                .thenReturn(Flux.just(row("old", "old", null)));

        StepVerifier.create(service.search(PrincipalDomain.forDomain("brandx"), "ol", 10))
                .assertNext(list -> assertThat(list).containsExactly(new MeshUser("old", "old", null)))
                .verifyComplete();

        verify(repo, never()).searchInIssuers(anyCollection(), anyString(), anyString(), anyInt());
    }

    @Test
    void a_row_carries_no_email_or_invite_handle() {
        // The projection and the DTO simply have no such field: guard that this stays true.
        assertThat(MeshUser.class.getRecordComponents()).extracting(c -> c.getName())
                .containsExactly("username", "matrixLocalpart", "domain");
        assertThat(MeshUserRow.class.getRecordComponents()).extracting(c -> c.getName())
                .doesNotContain("handle", "email");
    }
}
