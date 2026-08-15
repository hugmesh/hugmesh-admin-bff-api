package net.hugmesh.adminbff.theme;

import net.hugmesh.commons.security.PrincipalDomain;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Who may theme which domain — the authorization rule, tested at the layer that ENFORCES
 * it rather than through the UI that happens to render the control.
 *
 * <p>These tests exist because the first cut of this service was wrong in a way that read
 * as correct. {@link PrincipalDomain#NO_DOMAIN} is not the empty string; it is the
 * sentinel {@code " no-domain"}, whose leading space is what makes it unmatchable by a
 * registry-sanitized domain name. The service trimmed it. {@code " no-domain".trim()} is
 * {@code "no-domain"} — an ordinary non-empty string, which
 *
 * <ol>
 *   <li>sailed straight past the {@code own.isEmpty()} fail-closed guard, and</li>
 *   <li>equalled the key the MESH DEFAULT row was itself written under, because the
 *       record's compact constructor trimmed the sentinel the same way.</li>
 * </ol>
 *
 * <p>Composed, those two gave a principal whose tenant could not be resolved — an
 * unknown issuer, exactly the case the sentinel exists to contain — write access to the
 * one row every domain inherits. The escalation the class doc says only a superadmin may
 * perform was reachable by having no valid tenant at all. The CROSS-TENANT and FAIL-CLOSED
 * blocks below pin each half so neither can come back on its own.
 */
class DomainThemeAuthorizationTest {

    /** In-memory stand-in: these tests are about the DECISION, not the storage. */
    static final class FakeRepo extends DomainThemeRepository {
        final Map<String, DomainTheme> rows = new LinkedHashMap<>();

        FakeRepo() {
            super(null);
        }

        @Override
        public Flux<DomainTheme> findAll() {
            return Flux.fromIterable(rows.values());
        }

        @Override
        public Mono<DomainTheme> findByDomain(String domain) {
            DomainTheme t = rows.get(DomainTheme.normalizeDomain(domain));
            return t == null ? Mono.empty() : Mono.just(t);
        }

        @Override
        public Mono<DomainTheme> upsert(DomainTheme t) {
            rows.put(t.domain(), t);
            return Mono.just(t);
        }

        @Override
        public Mono<Void> delete(String domain) {
            rows.remove(DomainTheme.normalizeDomain(domain));
            return Mono.empty();
        }
    }

    private final FakeRepo repo = new FakeRepo();
    private final DomainThemeService service = new DomainThemeService(repo);

    private static DomainTheme theme(String domain) {
        return new DomainTheme(domain, "nord", "dusk", "soft", "none", null, null, null);
    }

    /** A principal whose issuer the registry could not resolve. */
    private static PrincipalDomain unresolvable() {
        return PrincipalDomain.forDomain(null);
    }

    // ------------------------------------------------------------------
    // FAIL-CLOSED (DENY) — the unresolvable principal
    // ------------------------------------------------------------------

    @Nested
    class WhenTheTenantCannotBeResolved {

        @Test
        void managesNothingAtAll() {
            PrincipalDomain nobody = unresolvable();
            assertThat(service.canManage(nobody, "brandx")).isFalse();
            assertThat(service.canManage(nobody, "")).isFalse();
            assertThat(service.canManage(nobody, null)).isFalse();
        }

        @Test
        void cannotManageTheMeshDefaultByAnySpellingOfTheSentinel() {
            PrincipalDomain nobody = unresolvable();
            // Each of these is a way the sentinel can arrive as a TARGET. Every one of
            // them keys the mesh-default row, so every one of them must be refused.
            assertThat(service.canManage(nobody, PrincipalDomain.NO_DOMAIN)).isFalse();
            assertThat(service.canManage(nobody, "no-domain")).isFalse();
            assertThat(service.canManage(nobody, " no-domain ")).isFalse();
            assertThat(service.canManage(nobody, DomainTheme.MESH_DEFAULT)).isFalse();
        }

        @Test
        void cannotWRITEtheMeshDefaultRow() {
            // The regression in full: a set() through the sentinel used to land on the
            // row every domain inherits. It must 403 and leave the store untouched.
            StepVerifier.create(service.set(theme("no-domain"), unresolvable(), "attacker"))
                    .expectErrorSatisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode())
                            .isEqualTo(HttpStatus.FORBIDDEN))
                    .verify();
            assertThat(repo.rows).isEmpty();
        }

        @Test
        void cannotCLEARtheMeshDefaultRow() {
            repo.rows.put(DomainTheme.MESH_DEFAULT, theme(DomainTheme.MESH_DEFAULT));
            StepVerifier.create(service.clear(PrincipalDomain.NO_DOMAIN, unresolvable()))
                    .expectError(ResponseStatusException.class)
                    .verify();
            assertThat(repo.rows).containsKey(DomainTheme.MESH_DEFAULT);
        }
    }

    // ------------------------------------------------------------------
    // CROSS-TENANT (DENY) — a domain admin is confined to its own domain
    // ------------------------------------------------------------------

    @Nested
    class WhenTheCallerIsADomainAdmin {

        private final PrincipalDomain brandx = PrincipalDomain.forDomain("brandx");

        @Test
        void managesItsOwnDomain() {
            assertThat(service.canManage(brandx, "brandx")).isTrue();
            assertThat(service.canManage(brandx, "  brandx  ")).isTrue();
        }

        @Test
        void doesNotManageAnotherDomain() {
            assertThat(service.canManage(brandx, "brandy")).isFalse();
            StepVerifier.create(service.set(theme("brandy"), brandx, "x-admin"))
                    .expectError(ResponseStatusException.class)
                    .verify();
            assertThat(repo.rows).isEmpty();
        }

        @Test
        void doesNotManageTheMeshDefault() {
            // The role boundary that matters: the default is every domain's inheritance,
            // so setting it repaints domains this admin has no authority over.
            assertThat(service.canManage(brandx, DomainTheme.MESH_DEFAULT)).isFalse();
            assertThat(service.canManage(brandx, PrincipalDomain.NO_DOMAIN)).isFalse();
            assertThat(service.canManage(brandx, null)).isFalse();
        }

        @Test
        void writesItsOwnDomainSuccessfullyAndIsRecordedAsTheAuthor() {
            StepVerifier.create(service.set(theme("brandx"), brandx, "x-admin"))
                    .assertNext(t -> {
                        assertThat(t.domain()).isEqualTo("brandx");
                        assertThat(t.updatedBy()).isEqualTo("x-admin");
                    })
                    .verifyComplete();
        }

        @Test
        void cannotSmuggleAnotherDomainPastTheCheckByPadding() {
            // canManage normalises the target the same way the row is keyed, so a
            // differently-spelled target cannot reach a row the check did not approve.
            StepVerifier.create(service.set(theme(" brandy "), brandx, "x-admin"))
                    .expectError(ResponseStatusException.class)
                    .verify();
            assertThat(repo.rows).isEmpty();
        }
    }

    // ------------------------------------------------------------------
    // MULTIUSER-SITUATIONAL (ALLOW) — superadmin is unscoped
    // ------------------------------------------------------------------

    @Nested
    class WhenTheCallerIsSuperadmin {

        private final PrincipalDomain root = PrincipalDomain.superadminFor("brandx");

        @Test
        void managesAnyDomainIncludingTheMeshDefault() {
            assertThat(service.canManage(root, "brandx")).isTrue();
            assertThat(service.canManage(root, "brandy")).isTrue();
            assertThat(service.canManage(root, DomainTheme.MESH_DEFAULT)).isTrue();
            assertThat(service.canManage(root, PrincipalDomain.NO_DOMAIN)).isTrue();
        }

        @Test
        void writesTheMeshDefaultUnderTheCanonicalKey() {
            // Whichever spelling the caller used, the row lands on MESH_DEFAULT — this is
            // what makes it findable again by resolve().
            StepVerifier.create(service.set(theme(PrincipalDomain.NO_DOMAIN), root, "root"))
                    .assertNext(t -> assertThat(t.domain()).isEqualTo(DomainTheme.MESH_DEFAULT))
                    .verifyComplete();
            assertThat(repo.rows).containsOnlyKeys(DomainTheme.MESH_DEFAULT);
        }
    }

    // ------------------------------------------------------------------
    // A null scope is not a bypass
    // ------------------------------------------------------------------

    @Test
    void aNullScopeManagesNothing() {
        assertThat(service.canManage(null, "brandx")).isFalse();
        assertThat(service.canManage(null, DomainTheme.MESH_DEFAULT)).isFalse();
        assertThat(service.canManage(null, PrincipalDomain.NO_DOMAIN)).isFalse();
    }

    // ------------------------------------------------------------------
    // Normalisation — one key per meaning
    // ------------------------------------------------------------------

    @Test
    void everySpellingOfNoDomainKeysTheOneMeshDefaultRow() {
        assertThat(DomainTheme.normalizeDomain(null)).isEqualTo(DomainTheme.MESH_DEFAULT);
        assertThat(DomainTheme.normalizeDomain("")).isEqualTo(DomainTheme.MESH_DEFAULT);
        assertThat(DomainTheme.normalizeDomain("   ")).isEqualTo(DomainTheme.MESH_DEFAULT);
        assertThat(DomainTheme.normalizeDomain(PrincipalDomain.NO_DOMAIN))
                .isEqualTo(DomainTheme.MESH_DEFAULT);
        assertThat(DomainTheme.normalizeDomain("no-domain")).isEqualTo(DomainTheme.MESH_DEFAULT);
        // ...and a real domain is left alone.
        assertThat(DomainTheme.normalizeDomain(" brandx ")).isEqualTo("brandx");
    }

    @Test
    void theRecordItselfCannotHoldAnUncanonicalKey() {
        // Defence in depth: even a caller that bypasses the service cannot construct a
        // second row for the mesh default.
        assertThat(theme(PrincipalDomain.NO_DOMAIN).domain()).isEqualTo(DomainTheme.MESH_DEFAULT);
        assertThat(theme("no-domain").domain()).isEqualTo(DomainTheme.MESH_DEFAULT);
        assertThat(theme(null).domain()).isEqualTo(DomainTheme.MESH_DEFAULT);
    }
}
