package net.hugmesh.adminbff.meshtoken;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import net.hugmesh.adminbff.support.TestDatabaseConfig;

import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.TreeSet;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * {@code mesh_token_issued} over the Liquibase-applied test database: changeset 390 applies, the
 * table has EXACTLY the twelve non-secret columns (no token / key column can creep in), a new
 * row inserts and reads back, the ADMIN read is confined to its domains, and the role/shell CHECK
 * holds at the table too.
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
@ActiveProfiles("test")
class MeshTokenIssuedRowRepositoryTest {

    @Autowired DatabaseClient db;
    @Autowired MeshTokenIssuedRowRepository repo;

    @BeforeEach
    void clean() {
        db.sql("DELETE FROM mesh_token_issued").fetch().rowsUpdated().block();
    }

    static MeshTokenIssued row(String id, String domain, String role, boolean shell, Instant at) {
        return new MeshTokenIssued(id, "hugmesh-local", domain, role, shell, "https://hs." + domain,
                MeshTokenFixtures.FINGERPRINT, "17", "laptop-1", "sub-1", at, at.plusSeconds(3600));
    }

    @Test
    void theTableHasExactlyTheTwelveNonSecretColumns() {
        List<String> cols = db.sql("SELECT column_name FROM information_schema.columns "
                        + "WHERE lower(table_name) = 'mesh_token_issued'")
                .map(r -> r.get(0, String.class).toLowerCase(Locale.ROOT)).all().collectList().block();
        Set<String> got = new TreeSet<>(cols);
        assertThat(got).containsExactlyInAnyOrder("id", "mesh", "domain", "role", "shell", "login_server",
                "issuer_fingerprint", "preauth_key_id", "node_name", "issued_by", "issued_at", "expires_at");
    }

    @Test
    void insertsAndReadsBack_newestFirst_andTheAdminReadIsConfinedToItsDomains() {
        Instant t = Instant.parse("2026-11-04T12:00:00Z");
        repo.save(row("aaaaaaaaaaaaaaa1", "hugmesh.net", "admin", true, t).toNewRow()).block();
        repo.save(row("aaaaaaaaaaaaaaa2", "brandx.org", "user", false, t.plusSeconds(60)).toNewRow()).block();
        repo.save(row("aaaaaaaaaaaaaaa3", "hugmesh.net", "superadmin", false, t.plusSeconds(120)).toNewRow()).block();

        assertThat(repo.findTop200ByOrderByIssuedAtDesc().map(MeshTokenIssuedRow::id).collectList().block())
                .containsExactly("aaaaaaaaaaaaaaa3", "aaaaaaaaaaaaaaa2", "aaaaaaaaaaaaaaa1");
        List<MeshTokenIssued> own = repo.findTop200ByDomainInOrderByIssuedAtDesc(List.of("hugmesh.net"))
                .map(MeshTokenIssuedRow::toDomain).collectList().block();
        assertThat(own).extracting(MeshTokenIssued::id).containsExactly("aaaaaaaaaaaaaaa3", "aaaaaaaaaaaaaaa1");
        MeshTokenIssued first = own.get(1);
        assertThat(first.shell()).isTrue();
        assertThat(first.role()).isEqualTo("admin");
        assertThat(first.preauthKeyId()).isEqualTo("17");
        assertThat(first.issuedAt()).isEqualTo(t);
        assertThat(first.expiresAt()).isEqualTo(t.plusSeconds(3600));
    }

    @Test
    void theTableRefusesShellForUserOrMod_andUnknownRoles() {
        Instant t = Instant.parse("2026-11-04T12:00:00Z");
        assertThatThrownBy(() -> repo.save(row("bbbbbbbbbbbbbbb1", "hugmesh.net", "user", true, t).toNewRow()).block())
                .isNotNull();
        assertThatThrownBy(() -> repo.save(row("bbbbbbbbbbbbbbb2", "hugmesh.net", "owner", false, t).toNewRow()).block())
                .isNotNull();
    }
}
