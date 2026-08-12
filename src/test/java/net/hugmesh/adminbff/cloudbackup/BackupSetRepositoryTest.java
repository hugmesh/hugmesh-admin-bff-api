package net.hugmesh.adminbff.cloudbackup;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.test.context.ActiveProfiles;
import reactor.test.StepVerifier;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.PrincipalDomain;
import net.hugmesh.adminbff.support.TestDatabaseConfig;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The backup_set R2DBC repository over a Liquibase-applied H2 (PG-compat) — proves the 160/161
 * changelog applies (table + CHECKs + UNIQUE) and the catalog idiom round-trips. Per the
 * test-standard: USER-SITUATIONAL (insert/read), VERSIONING (the version chain), CROSS-DOMAIN
 * isolation (a brand-X scoped admin can't see brand-Y sets), and SUPERADMIN-unscoped.
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
@ActiveProfiles("test")
class BackupSetRepositoryTest {

    @Autowired DatabaseClient db;

    @BeforeEach
    void clean() {
        db.sql("DELETE FROM backup_artifact").fetch().rowsUpdated().block();
        db.sql("DELETE FROM backup_set").fetch().rowsUpdated().block();
    }

    private BackupSetRepository repo() {
        return new BackupSetRepository(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.adminbff.cloudbackup.BackupSetR2dbcRepository.class));
    }

    private static final DomainRegistry REGISTRY = new DomainRegistry("",
            "https://idp.brandx.example=brandx,https://idp.brandy.example=brandy");

    private static PrincipalDomain admin(String issuer) {
        Jwt jwt = Jwt.withTokenValue("t").header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                .subject("u").issuer(issuer).claim("roles", List.of("admin")).build();
        Authentication auth = new JwtAuthenticationToken(jwt,
                List.of(new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));
        return PrincipalDomain.of(auth, REGISTRY);
    }

    private static PrincipalDomain superadmin() {
        Jwt jwt = Jwt.withTokenValue("t").header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                .subject("u").issuer("https://idp.brandx.example").claim("roles", List.of("superadmin")).build();
        Authentication auth = new JwtAuthenticationToken(jwt,
                List.of(new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_SUPERADMIN")));
        return PrincipalDomain.of(auth, REGISTRY);
    }

    // ── USER-SITUATIONAL: insert round-trips, services decode ────────────────────────────

    @Nested
    class InsertAndRead {
        @Test
        void insert_roundTrips_andServicesDecode() {
            BackupSet s = repo().insert("k1", 1L, BackupCloudScope.DOMAIN, "brandx", "alice",
                    List.of("postgres", "matrix"), BackupDestinationKind.OBJECT_STORE, "s3://b",
                    "{\"repo\":\"r\"}").block();
            assertThat(s.id()).isNotBlank();
            assertThat(s.scope()).isEqualTo(BackupCloudScope.DOMAIN);
            assertThat(s.services()).containsExactly("postgres", "matrix");
            assertThat(s.status()).isEqualTo(BackupSet.STATUS_PENDING);
            BackupSet read = repo().findById(s.id()).block();
            assertThat(read.domain()).isEqualTo("brandx");
            assertThat(read.destinationKind()).isEqualTo(BackupDestinationKind.OBJECT_STORE);
            assertThat(read.encryptionMeta()).contains("repo");
        }

        @Test
        void markStatus_transitionsAndStampsSize() {
            BackupSet s = repo().insert("k1", 1L, BackupCloudScope.DOMAIN, "brandx", "alice",
                    List.of("postgres"), BackupDestinationKind.OBJECT_STORE, "s3://b", null).block();
            assertThat(repo().markStatus(s.id(), BackupSet.STATUS_COMPLETE, 4096L).block()).isEqualTo(1L);
            BackupSet read = repo().findById(s.id()).block();
            assertThat(read.status()).isEqualTo(BackupSet.STATUS_COMPLETE);
            assertThat(read.sizeBytes()).isEqualTo(4096L);
            assertThat(read.completedAt()).isNotNull();
        }
    }

    // ── VERSIONING: the version chain ────────────────────────────────────────────────────

    @Nested
    class Versioning {
        @Test
        void maxVersion_thenChain() {
            BackupSetRepository r = repo();
            assertThat(r.maxVersion("brandx", "k1").block()).isEqualTo(0L);
            r.insert("k1", 1L, BackupCloudScope.DOMAIN, "brandx", "alice",
                    List.of("postgres"), BackupDestinationKind.OBJECT_STORE, "s3://b", null).block();
            assertThat(r.maxVersion("brandx", "k1").block()).isEqualTo(1L);
            BackupSet v2 = r.insert("k1", 2L, BackupCloudScope.DOMAIN, "brandx", "alice",
                    List.of("postgres"), BackupDestinationKind.OBJECT_STORE, "s3://b", null).block();
            assertThat(r.maxVersion("brandx", "k1").block()).isEqualTo(2L);
            // the chain for v2's id lists both versions (newest first), scoped to brandx.
            List<BackupSet> chain = r.versions(v2.id(), admin("https://idp.brandx.example"))
                    .collectList().block();
            assertThat(chain).hasSize(2);
            assertThat(chain.get(0).version()).isEqualTo(2L);
            assertThat(chain.get(1).version()).isEqualTo(1L);
        }

        @Test
        void differentDomain_sameKey_independentChains() {
            BackupSetRepository r = repo();
            r.insert("k1", 1L, BackupCloudScope.DOMAIN, "brandx", "alice",
                    List.of("postgres"), BackupDestinationKind.OBJECT_STORE, "s3://b", null).block();
            // brandy reuses the SAME set_key but its chain starts fresh at version 1.
            assertThat(r.maxVersion("brandy", "k1").block()).isEqualTo(0L);
        }
    }

    // ── CROSS-DOMAIN isolation ────────────────────────────────────────────────────────────

    @Nested
    class CrossDomainIsolation {
        @Test
        void scopedAdmin_seesOnlyOwnBrand() {
            BackupSetRepository r = repo();
            r.insert("kx", 1L, BackupCloudScope.DOMAIN, "brandx", "alice",
                    List.of("postgres"), BackupDestinationKind.OBJECT_STORE, "s3://b", null).block();
            r.insert("ky", 1L, BackupCloudScope.DOMAIN, "brandy", "bob",
                    List.of("postgres"), BackupDestinationKind.OBJECT_STORE, "s3://b", null).block();
            List<BackupSet> x = r.list(admin("https://idp.brandx.example")).collectList().block();
            assertThat(x).hasSize(1);
            assertThat(x.get(0).domain()).isEqualTo("brandx");
            // superadmin sees both brands.
            assertThat(r.list(superadmin()).collectList().block()).hasSize(2);
        }

        @Test
        void scopedAdmin_findScoped_cannotSeeOtherBrand() {
            BackupSetRepository r = repo();
            BackupSet y = r.insert("ky", 1L, BackupCloudScope.DOMAIN, "brandy", "bob",
                    List.of("postgres"), BackupDestinationKind.OBJECT_STORE, "s3://b", null).block();
            // a brand-X admin cannot resolve a brand-Y set (fail-closed empty).
            StepVerifier.create(r.findScoped(y.id(), admin("https://idp.brandx.example")))
                    .verifyComplete();
            // brand-Y admin can.
            assertThat(r.findScoped(y.id(), admin("https://idp.brandy.example")).block()).isNotNull();
        }

        @Test
        void scopedAdmin_versions_outOfScopeIsEmpty() {
            BackupSetRepository r = repo();
            BackupSet y = r.insert("ky", 1L, BackupCloudScope.DOMAIN, "brandy", "bob",
                    List.of("postgres"), BackupDestinationKind.OBJECT_STORE, "s3://b", null).block();
            // a brand-X admin can't enumerate a brand-Y set's version chain.
            StepVerifier.create(r.versions(y.id(), admin("https://idp.brandx.example")))
                    .verifyComplete();
        }

        @Test
        void superadmin_filterForDomain() {
            BackupSetRepository r = repo();
            r.insert("kx", 1L, BackupCloudScope.DOMAIN, "brandx", "alice",
                    List.of("postgres"), BackupDestinationKind.OBJECT_STORE, "s3://b", null).block();
            r.insert("ky", 1L, BackupCloudScope.DOMAIN, "brandy", "bob",
                    List.of("postgres"), BackupDestinationKind.OBJECT_STORE, "s3://b", null).block();
            assertThat(r.listForDomain("brandy").collectList().block()).hasSize(1);
        }
    }
}
