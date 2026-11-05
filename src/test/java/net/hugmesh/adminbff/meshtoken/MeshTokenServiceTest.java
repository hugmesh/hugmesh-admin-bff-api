package net.hugmesh.adminbff.meshtoken;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.ArgumentCaptor;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.security.PrincipalDomain;

import java.lang.reflect.RecordComponent;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The issuing rules, end to end through the real payload, signer and key, with headscale and the
 * audit store stubbed: the role / shell / own-domain matrix, dark mode, fail-fast boot, and that
 * neither the audit row nor any log line ever carries the token or its pre-auth key.
 */
class MeshTokenServiceTest {

    static final Instant NOW = Instant.parse("2026-11-04T12:00:00Z");
    static final String AUTH_KEY = "d0d0cafe0123456789abcdef0123456789abcdefdeadbeef";

    /** hugmesh.net and other.example belong to brand "default"; brandx.org to "brandx". */
    static MeshTokenProperties props(boolean enabled) {
        MeshTokenProperties p = new MeshTokenProperties();
        p.setEnabled(enabled);
        p.setMesh("hugmesh-local");
        p.setLoginServers("hugmesh.net=https://hs.hugmesh.net:8488/, brandx.org=https://hs.brandx.org,"
                + "other.example=https://other.example");
        p.setDomainBrands("brandx.org=brandx");
        return p;
    }

    HeadscalePreAuthKeyClient headscale;
    MeshTokenIssuedRowRepository repo;
    ListAppender<ILoggingEvent> logs;

    @BeforeEach
    void setUp() {
        headscale = mock(HeadscalePreAuthKeyClient.class);
        repo = mock(MeshTokenIssuedRowRepository.class);
        when(headscale.create(any())).thenReturn(Mono.just(new HeadscalePreAuthKeyClient.PreAuthKey("17", AUTH_KEY)));
        when(repo.save(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));
        logs = new ListAppender<>();
        logs.start();
        ((Logger) LoggerFactory.getLogger("net.hugmesh.adminbff.meshtoken")).addAppender(logs);
    }

    @AfterEach
    void tearDown() {
        ((Logger) LoggerFactory.getLogger("net.hugmesh.adminbff.meshtoken")).detachAppender(logs);
    }

    MeshTokenService service() {
        return new MeshTokenService(props(true), headscale, repo, Clock.fixed(NOW, ZoneOffset.UTC),
                MeshTokenFixtures.key());
    }

    static PrincipalDomain admin(String brand) {
        return PrincipalDomain.forDomain(brand);
    }

    static PrincipalDomain superadmin() {
        return PrincipalDomain.superadminFor("default");
    }

    static MeshTokenService.IssueRequest req(String domain, String role, boolean shell) {
        return new MeshTokenService.IssueRequest(domain, role, shell, null, "laptop-1");
    }

    // ── the matrix ──────────────────────────────────────────────────────────────────

    @ParameterizedTest(name = "{0} issues role={1} shell={2} for {3} -> {4}")
    @CsvSource({
            // caller,     role,       shell, domain,        outcome
            "admin,       user,       false, hugmesh.net,   ok",
            "admin,       mod,        false, hugmesh.net,   ok",
            "admin,       admin,      false, hugmesh.net,   ok",
            "admin,       admin,      true,  hugmesh.net,   ok",
            "admin,       user,       true,  hugmesh.net,   invalid",
            "admin,       mod,        true,  hugmesh.net,   invalid",
            "admin,       superadmin, false, hugmesh.net,   denied",
            "admin,       superadmin, true,  hugmesh.net,   denied",
            "admin,       user,       false, brandx.org,    denied",
            "admin,       admin,      true,  brandx.org,    denied",
            "admin,       user,       false, unknown.org,   invalid",
            "admin,       owner,      false, hugmesh.net,   invalid",
            "brandx,      user,       false, brandx.org,    ok",
            "brandx,      user,       false, hugmesh.net,   denied",
            "superadmin,  superadmin, true,  hugmesh.net,   ok",
            "superadmin,  superadmin, false, brandx.org,    ok",
            "superadmin,  user,       true,  brandx.org,    invalid",
            "superadmin,  mod,        false, other.example, ok",
            "superadmin,  user,       false, unknown.org,   invalid",
            "nodomain,    user,       false, hugmesh.net,   denied",
    })
    void roleShellDomainMatrix(String caller, String role, boolean shell, String domain, String outcome) {
        PrincipalDomain scope = switch (caller) {
            case "admin" -> admin("default");
            case "brandx" -> admin("brandx");
            case "superadmin" -> superadmin();
            default -> PrincipalDomain.forDomain(null);
        };
        Mono<MeshTokenService.IssueResult> r = service().issue("sub-1", scope, req(domain, role, shell));
        switch (outcome) {
            case "ok" -> {
                MeshTokenService.IssueResult res = r.block();
                assertThat(res).isNotNull();
                MeshTokenPayload p = decode(res.token());
                assertThat(p.role()).isEqualTo(role);
                assertThat(p.shell()).isEqualTo(shell);
                assertThat(p.domain()).isEqualTo(domain);
            }
            case "denied" -> {
                assertThatThrownBy(r::block).isInstanceOf(MeshTokenService.MeshTokenDeniedException.class);
                verify(headscale, never()).create(any());
                verify(repo, never()).save(any());
            }
            default -> {
                assertThatThrownBy(r::block).isInstanceOf(MeshTokenService.MeshTokenInvalidException.class);
                verify(headscale, never()).create(any());
                verify(repo, never()).save(any());
            }
        }
    }

    @Test
    void lifetime_defaultsTo7Days_and_isCappedAt90() {
        MeshTokenService s = service();
        MeshTokenService.IssueResult r = s.issue("sub-1", superadmin(), req("hugmesh.net", "user", false)).block();
        assertThat(r.expires()).isEqualTo(NOW.getEpochSecond() + 7 * 86400);
        assertThat(s.issue("sub-1", superadmin(),
                new MeshTokenService.IssueRequest("hugmesh.net", "user", false, 90L * 86400, "")).block())
                .isNotNull();
        assertThatThrownBy(() -> s.issue("sub-1", superadmin(),
                new MeshTokenService.IssueRequest("hugmesh.net", "user", false, 90L * 86400 + 1, "")).block())
                .isInstanceOf(MeshTokenService.MeshTokenInvalidException.class);
        assertThatThrownBy(() -> s.issue("sub-1", superadmin(),
                new MeshTokenService.IssueRequest("hugmesh.net", "user", false, 0L, "")).block())
                .isInstanceOf(MeshTokenService.MeshTokenInvalidException.class);
        assertThatThrownBy(() -> s.issue("sub-1", superadmin(),
                new MeshTokenService.IssueRequest("hugmesh.net", "user", false, -5L, "")).block())
                .isInstanceOf(MeshTokenService.MeshTokenInvalidException.class);
    }

    @Test
    void nodeName_mustBeADnsLabel_soNoStringEverNeedsEscaping() {
        for (String bad : List.of("Laptop", "-x", "a b", "a\"b", "a\\b", "été", "x".repeat(64))) {
            assertThatThrownBy(() -> service().issue("sub-1", superadmin(),
                    new MeshTokenService.IssueRequest("hugmesh.net", "user", false, null, bad)).block())
                    .as(bad).isInstanceOf(MeshTokenService.MeshTokenInvalidException.class);
        }
    }

    @Test
    void issuedToken_carriesTheConfiguredLoginServer_withoutTrailingSlash_andExpiresKeyWithToken() {
        MeshTokenService.IssueResult r = service().issue("sub-1", admin("default"),
                req("hugmesh.net", "admin", true)).block();
        MeshTokenPayload p = decode(r.token());
        assertThat(p.loginServer()).isEqualTo("https://hs.hugmesh.net:8488");
        assertThat(p.mesh()).isEqualTo("hugmesh-local");
        assertThat(p.issuer()).isEqualTo(MeshTokenFixtures.publicLine());
        assertThat(p.issued()).isEqualTo(NOW.getEpochSecond());
        assertThat(p.id()).matches("^[0-9a-f]{16}$").isEqualTo(r.id());
        assertThat(p.nodeName()).isEqualTo("laptop-1");
        assertThat(p.authKey()).isEqualTo(AUTH_KEY);
        assertThat(r.fingerprint()).isEqualTo(MeshTokenFixtures.FINGERPRINT);
        assertThat(r.describe()).isEqualTo("admin in hugmesh.net (mesh hugmesh-local), shell access, "
                + "expires 2026-11-11 12:00 UTC");
        verify(headscale).create(Instant.ofEpochSecond(r.expires()));
    }

    @Test
    void auditRow_andLogs_neverCarryTheTokenOrThePreAuthKey() {
        MeshTokenService.IssueResult r = service().issue("sub-1", superadmin(),
                req("hugmesh.net", "superadmin", true)).block();
        ArgumentCaptor<MeshTokenIssuedRow> row = ArgumentCaptor.forClass(MeshTokenIssuedRow.class);
        verify(repo).save(row.capture());
        MeshTokenIssuedRow saved = row.getValue();
        assertThat(saved.isNew()).isTrue();
        assertThat(saved.id()).isEqualTo(r.id());
        assertThat(saved.preauthKeyId()).isEqualTo("17");
        assertThat(saved.issuerFingerprint()).isEqualTo(MeshTokenFixtures.FINGERPRINT);
        assertThat(saved.issuedBy()).isEqualTo("sub-1");
        assertThat(saved.expiresAt()).isEqualTo(Instant.ofEpochSecond(r.expires()));
        String[] payloadAndSig = r.token().split("\\.");
        for (RecordComponent c : MeshTokenIssuedRow.class.getRecordComponents()) {
            Object v;
            try {
                v = c.getAccessor().invoke(saved);
            } catch (ReflectiveOperationException e) {
                throw new AssertionError(e);
            }
            String s = String.valueOf(v);
            assertThat(s).as(c.getName()).doesNotContain(AUTH_KEY).doesNotContain(AUTH_KEY.substring(0, 12))
                    .doesNotContain(payloadAndSig[1]).doesNotContain(payloadAndSig[2]);
        }
        assertThat(saved.toString()).doesNotContain(AUTH_KEY);
        assertThat(r.toString()).doesNotContain(AUTH_KEY).doesNotContain(r.token());

        assertThat(logs.list).isNotEmpty();
        for (ILoggingEvent e : logs.list) {
            String line = e.getFormattedMessage();
            assertThat(line).doesNotContain(AUTH_KEY).doesNotContain(AUTH_KEY.substring(0, 12))
                    .doesNotContain(r.token()).doesNotContain(payloadAndSig[1]).doesNotContain(payloadAndSig[2])
                    .doesNotContain("SSH SIGNATURE").doesNotContain("PRIVATE KEY");
        }
    }

    @Test
    void auditFailure_meansNoTokenIsReturned() {
        org.mockito.Mockito.doReturn(Mono.error(new IllegalStateException("db down"))).when(repo).save(any());
        assertThatThrownBy(() -> service().issue("sub-1", superadmin(), req("hugmesh.net", "user", false)).block())
                .hasMessageContaining("db down");
    }

    @Test
    void headscaleFailure_isPropagated_andNothingIsAudited() {
        when(headscale.create(any())).thenReturn(Mono.error(
                new HeadscalePreAuthKeyClient.HeadscaleUnavailableException("headscale did not answer in time.")));
        assertThatThrownBy(() -> service().issue("sub-1", superadmin(), req("hugmesh.net", "user", false)).block())
                .isInstanceOf(HeadscalePreAuthKeyClient.HeadscaleUnavailableException.class);
        verify(repo, never()).save(any());
    }

    // ── issuer descriptor ───────────────────────────────────────────────────────────

    @Test
    @SuppressWarnings("unchecked")
    void issuerDescriptor_listsOnlyTheCallersDomains_andNeverThePrivateKey() {
        MeshTokenService s = service();
        var a = s.issuer(admin("default"));
        assertThat(a.get("enabled")).isEqualTo(true);
        assertThat(a.get("publicKey")).isEqualTo(MeshTokenFixtures.publicLine());
        assertThat(a.get("fingerprint")).isEqualTo(MeshTokenFixtures.FINGERPRINT);
        assertThat(a.get("mesh")).isEqualTo("hugmesh-local");
        assertThat(a.get("maxLifetimeSeconds")).isEqualTo(90L * 86400);
        assertThat(((List<java.util.Map<String, Object>>) a.get("domains")).stream().map(m -> m.get("domain")))
                .containsExactly("hugmesh.net", "other.example");
        assertThat((List<String>) a.get("roles")).containsExactly("user", "mod", "admin");
        var sa = s.issuer(superadmin());
        assertThat(((List<java.util.Map<String, Object>>) sa.get("domains")).stream().map(m -> m.get("loginServer")))
                .containsExactly("https://hs.hugmesh.net:8488", "https://hs.brandx.org", "https://other.example");
        assertThat((List<String>) sa.get("roles")).containsExactly("user", "mod", "admin", "superadmin");
        assertThat(String.valueOf(a) + sa).doesNotContain(MeshTokenFixtures.text("test-issuer.seed.hex").trim());
    }

    // ── dark mode + boot ──────────────────────────────────────────────────────────────

    @Test
    void dark_issueRefusesBeforeHeadscale_andNeverReadsTheKeyFile(@TempDir Path dir) {
        MeshTokenProperties p = props(false);
        p.setIssuerKeyPath(dir.resolve("does-not-exist").toString());
        MeshTokenService s = new MeshTokenService(p, headscale, repo);
        assertThat(s.isEnabled()).isFalse();
        assertThatThrownBy(() -> s.issue("sub-1", superadmin(), req("hugmesh.net", "user", false)).block())
                .isInstanceOf(MeshTokenService.MeshTokenDarkException.class)
                .hasMessageContaining("make stack-up HEADSCALE=1");
        verify(headscale, never()).create(any());
        verify(repo, never()).save(any());
        var d = s.issuer(superadmin());
        assertThat(d.get("enabled")).isEqualTo(false);
        assertThat(d.get("publicKey")).isNull();
        assertThat(d.get("fingerprint")).isNull();
        assertThat(d.get("note")).isEqualTo(MeshTokenService.DARK_NOTE);
    }

    @Test
    void dark_auditListStillWorks() {
        MeshTokenService s = new MeshTokenService(props(false), headscale, repo);
        when(repo.findTop200ByDomainInOrderByIssuedAtDesc(any())).thenReturn(Flux.empty());
        assertThat(s.list(admin("default")).collectList().block()).isEmpty();
        verify(repo).findTop200ByDomainInOrderByIssuedAtDesc(List.of("hugmesh.net", "other.example"));
    }

    @Test
    void list_adminWithNoDomains_seesNothing_withoutAQuery() {
        assertThat(service().list(admin("nobody")).collectList().block()).isEmpty();
        verify(repo, never()).findTop200ByDomainInOrderByIssuedAtDesc(any());
        verify(repo, never()).findTop200ByOrderByIssuedAtDesc();
    }

    @Test
    void enabled_withAMissingOrBadIssuerKey_failsTheBoot(@TempDir Path dir) throws Exception {
        MeshTokenProperties p = props(true);
        assertThatThrownBy(() -> new MeshTokenService(p, headscale, repo))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("issuer-key-path");
        p.setIssuerKeyPath(dir.resolve("absent").toString());
        assertThatThrownBy(() -> new MeshTokenService(p, headscale, repo))
                .isInstanceOf(MeshTokenIssuerKey.IssuerKeyException.class);
        Path good = dir.resolve("issuer");
        Files.writeString(good, MeshTokenFixtures.openSshPem(), StandardCharsets.US_ASCII);
        p.setIssuerKeyPath(good.toString());
        assertThat(new MeshTokenService(p, headscale, repo).issuer(superadmin()).get("fingerprint"))
                .isEqualTo(MeshTokenFixtures.FINGERPRINT);
    }

    @Test
    void enabled_withABadMeshOrDomainTable_failsTheBoot() {
        MeshTokenProperties p = props(true);
        p.setMesh("mesh_default");
        assertThatThrownBy(() -> new MeshTokenService(p, headscale, repo, Clock.systemUTC(), MeshTokenFixtures.key()))
                .hasMessageContaining("mesh");
        MeshTokenProperties q = props(true);
        q.setLoginServers("hugmesh.net=https://hs.evil.org");
        assertThatThrownBy(() -> new MeshTokenService(q, headscale, repo, Clock.systemUTC(), MeshTokenFixtures.key()))
                .hasMessageContaining("outside its access domain");
        MeshTokenProperties r = props(true);
        r.setLoginServers("hugmesh.net=https://hs.hugmesh.net/path");
        assertThatThrownBy(() -> new MeshTokenService(r, headscale, repo, Clock.systemUTC(), MeshTokenFixtures.key()))
                .hasMessageContaining("https://host[:port]");
        MeshTokenProperties t = props(true);
        t.setLoginServers("");
        assertThatThrownBy(() -> new MeshTokenService(t, headscale, repo, Clock.systemUTC(), MeshTokenFixtures.key()))
                .hasMessageContaining("names no access domain");
    }

    /** Decode a token's payload back into the record (test-side parse; no trust decided). */
    static MeshTokenPayload decode(String token) {
        String[] parts = token.split("\\.");
        assertThat(parts).hasSize(3);
        assertThat(parts[0]).isEqualTo(MeshTokenPayload.FORMAT);
        try {
            var n = new com.fasterxml.jackson.databind.ObjectMapper()
                    .readTree(Base64.getUrlDecoder().decode(parts[1]));
            assertThat(n.size()).isEqualTo(12);
            return new MeshTokenPayload(n.get("auth_key").asText(), n.get("domain").asText(),
                    n.get("expires").asLong(), n.get("id").asText(), n.get("issued").asLong(),
                    n.get("issuer").asText(), n.get("login_server").asText(), n.get("mesh").asText(),
                    n.get("node_name").asText(), n.get("role").asText(), n.get("shell").asBoolean());
        } catch (java.io.IOException e) {
            throw new AssertionError(e);
        }
    }
}
