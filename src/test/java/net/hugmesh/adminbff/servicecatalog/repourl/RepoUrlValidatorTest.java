package net.hugmesh.adminbff.servicecatalog.repourl;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * Unit tests for {@link RepoUrlValidator} — the structural SSRF / supply-chain guard for the
 * App-Store service-catalog {@code repoUrl}. The hostile corpus exercises every attack class
 * the audit finding called out (YAML/Job-spec injection via newline/CRLF, metadata-IP SSRF,
 * file/javascript schemes, host-less URLs, embedded control chars, over-length), plus the
 * happy-path accepts and the optional host-allowlist behaviour.
 */
class RepoUrlValidatorTest {

    // ── REJECTED: the hostile corpus ──────────────────────────────────────────

    @ParameterizedTest(name = "rejected: [{0}]")
    @ValueSource(strings = {
            // newline / CRLF injection — break out of the Kaniko Job arg scalar and inject
            // a sibling YAML key (a privileged securityContext / extra --destination arg).
            "https://h/r\n    securityContext: {privileged: true}",
            "https://h/r\r\n    - --destination=evil.example/pwn",
            // local-file read (LFI) — the classic file: SSRF.
            "file:///etc/passwd",
            "FILE:///etc/passwd",
            // cloud-metadata SSRF over plaintext http (link-local 169.254.169.254).
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            // other dangerous / exotic schemes.
            "javascript:alert(1)",
            "gopher://127.0.0.1:6379/_FLUSHALL",
            "dict://127.0.0.1:11211/stats",
            "ftp://attacker.example/x",
            // host-less URLs — a scheme but no authority.
            "git://",
            "https:///path-no-host",
            // embedded control characters (tab, NUL, vertical tab).
            "https://h/repo\tname",
            "https://h/repo\u0000name",
            "https://h/repo\u000bname",
            // a bare space (whitespace) anywhere.
            "https://h/re po",
            // not a schemed URL at all (relative/opaque).
            "github.com/org/repo.git",
            "/etc/passwd",
            "../../secret",
    })
    void rejectsHostileRepoUrls(String hostile) {
        RepoUrlValidator.Result r = RepoUrlValidator.validate(hostile);
        assertThat(r.valid())
                .as("must REJECT hostile repoUrl: [%s]", hostile)
                .isFalse();
        assertThat(r.reason()).isNotBlank();
    }

    @Test
    void rejectsNullAndBlank() {
        assertThat(RepoUrlValidator.validate(null).valid()).isFalse();
        assertThat(RepoUrlValidator.validate("").valid()).isFalse();
        assertThat(RepoUrlValidator.validate("   ").valid()).isFalse();
    }

    @Test
    void rejectsOverLength() {
        // 513 chars: scheme + host + a long path that pushes past MAX_LENGTH (512).
        String longPath = "a".repeat(RepoUrlValidator.MAX_LENGTH);
        String tooLong = "https://h/" + longPath;
        assertThat(tooLong.length()).isGreaterThan(RepoUrlValidator.MAX_LENGTH);
        RepoUrlValidator.Result r = RepoUrlValidator.validate(tooLong);
        assertThat(r.valid()).isFalse();
        assertThat(r.reason()).containsIgnoringCase("too long");
    }

    @Test
    void fileSchemeReasonMentionsScheme() {
        assertThat(RepoUrlValidator.validate("file:///etc/passwd").reason())
                .containsIgnoringCase("scheme");
    }

    @Test
    void newlineReasonMentionsControlOrWhitespace() {
        // The newline is caught at the whitespace/control-char pass before URI parsing.
        assertThat(RepoUrlValidator.validate("https://h/r\n  x: y").reason())
                .containsIgnoringCase("control");
    }

    // ── ACCEPTED: well-formed repos on allowed schemes ────────────────────────

    @ParameterizedTest(name = "accepted: [{0}]")
    @ValueSource(strings = {
            "https://github.com/org/repo.git",
            "https://forgejo.test/acme/myservice",
            "https://gitlab.example.com/group/subgroup/project.git",
            "git://host/path",
            "git://git.example.com/org/repo.git",
            "ssh://git@host/r",
            "ssh://git@github.com/org/repo.git",
            // query/fragment chars within the allowed charset are fine structurally.
            "https://host/repo.git#main",
    })
    void acceptsValidRepoUrls(String valid) {
        RepoUrlValidator.Result r = RepoUrlValidator.validate(valid);
        assertThat(r.valid())
                .as("must ACCEPT valid repoUrl: [%s] (reason=%s)", valid, r.reason())
                .isTrue();
        assertThat(r.reason()).isNull();
    }

    // ── Optional host allowlist ────────────────────────────────────────────────

    @Test
    void hostAllowlist_unset_acceptsAnyValidHost() {
        assertThat(RepoUrlValidator.validate(
                "https://anything.example/x", Set.of()).valid()).isTrue();
    }

    @Test
    void hostAllowlist_set_acceptsMember_caseInsensitive() {
        Set<String> allow = Set.of("forgejo.test", "github.com");
        assertThat(RepoUrlValidator.validate(
                "https://forgejo.test/acme/x", allow).valid()).isTrue();
        // host comparison is case-insensitive.
        assertThat(RepoUrlValidator.validate(
                "https://GitHub.com/org/repo.git", allow).valid()).isTrue();
    }

    @Test
    void hostAllowlist_set_rejectsNonMember() {
        Set<String> allow = Set.of("forgejo.test");
        RepoUrlValidator.Result r = RepoUrlValidator.validate(
                "https://github.com/org/repo.git", allow);
        assertThat(r.valid()).isFalse();
        assertThat(r.reason()).containsIgnoringCase("allowlist");
    }

    @Test
    void hostAllowlist_set_stillRejectsBadSchemeEvenIfHostWouldMatch() {
        // A file: URL has no usable host and a bad scheme — rejected regardless of allowlist.
        Set<String> allow = Set.of("forgejo.test");
        assertThat(RepoUrlValidator.validate("file://forgejo.test/etc/passwd", allow).valid())
                .isFalse();
    }

    // ── parseHostAllowlist ─────────────────────────────────────────────────────

    @Test
    void parseHostAllowlist_trimsLowercasesAndDropsBlanks() {
        Set<String> set = RepoUrlValidator.parseHostAllowlist("  Forgejo.Test , ,github.com ,");
        assertThat(set).containsExactly("forgejo.test", "github.com");
    }

    @Test
    void parseHostAllowlist_nullOrBlank_isEmpty() {
        assertThat(RepoUrlValidator.parseHostAllowlist(null)).isEmpty();
        assertThat(RepoUrlValidator.parseHostAllowlist("")).isEmpty();
        assertThat(RepoUrlValidator.parseHostAllowlist("   ")).isEmpty();
    }

    // ── requireValid (the fail-closed sink entry point) ────────────────────────

    @Test
    void requireValid_throwsOnHostile() {
        assertThatThrownBy(() -> RepoUrlValidator.requireValid("file:///etc/passwd"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("invalid repoUrl");
    }

    @Test
    void requireValid_passesOnValid() {
        assertThatCode(() -> RepoUrlValidator.requireValid("https://github.com/org/repo.git"))
                .doesNotThrowAnyException();
    }
}
