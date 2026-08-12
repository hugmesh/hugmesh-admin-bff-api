package net.hugmesh.adminbff.servicecatalog.repourl;

import jakarta.validation.ConstraintValidatorContext;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link RepoUrlConstraintValidator} — the {@link RepoUrl} bean-validation
 * adapter. Drives {@code isValid} directly with a mocked {@link ConstraintValidatorContext}
 * (no Spring context needed) so the offline {@code mvn -o test} run is self-contained. Proves:
 * the validator delegates the accept/reject decision to {@link RepoUrlValidator}, honours the
 * injected {@code app.appstore.repo-host-allowlist} CSV, and substitutes the precise structural
 * reason into the violation message.
 */
class RepoUrlConstraintValidatorTest {

    /** A constraint context whose violation-builder chain is stubbed so message substitution
     *  can be asserted. */
    private static ConstraintValidatorContext mockContext() {
        ConstraintValidatorContext ctx = mock(ConstraintValidatorContext.class);
        var builder = mock(ConstraintValidatorContext.ConstraintViolationBuilder.class);
        when(ctx.buildConstraintViolationWithTemplate(any())).thenReturn(builder);
        return ctx;
    }

    @Test
    void valid_https_isValid_noAllowlist() {
        var v = new RepoUrlConstraintValidator("");
        assertThat(v.isValid("https://github.com/org/repo.git", mockContext())).isTrue();
    }

    @Test
    void invalid_fileScheme_isRejected_andMessageMentionsScheme() {
        var v = new RepoUrlConstraintValidator("");
        ConstraintValidatorContext ctx = mockContext();

        assertThat(v.isValid("file:///etc/passwd", ctx)).isFalse();

        // The default message is disabled and replaced with the precise reason.
        verify(ctx).disableDefaultConstraintViolation();
        verify(ctx).buildConstraintViolationWithTemplate(
                org.mockito.ArgumentMatchers.contains("scheme"));
    }

    @Test
    void invalid_metadataSsrf_isRejected() {
        var v = new RepoUrlConstraintValidator("");
        assertThat(v.isValid("http://169.254.169.254/latest/meta-data/", mockContext())).isFalse();
    }

    @Test
    void invalid_newlineInjection_isRejected() {
        var v = new RepoUrlConstraintValidator("");
        assertThat(v.isValid("https://h/r\n    securityContext: {privileged: true}", mockContext()))
                .isFalse();
    }

    @Test
    void invalid_nullAndBlank_isRejected() {
        var v = new RepoUrlConstraintValidator("");
        assertThat(v.isValid(null, mockContext())).isFalse();
        assertThat(v.isValid("", mockContext())).isFalse();
    }

    @Test
    void hostAllowlist_configured_acceptsMember_rejectsNonMember() {
        var v = new RepoUrlConstraintValidator("forgejo.test, github.com");
        assertThat(v.isValid("https://forgejo.test/acme/x", mockContext())).isTrue();
        assertThat(v.isValid("https://evil.example/x", mockContext())).isFalse();
    }

    @Test
    void message_isElTemplateSafe_metacharsNeutralised() {
        // The reason for a bad scheme echoes the allowed-scheme set "[https, git, ssh]"; ensure
        // no EL/template metachar ($ or {}) reaches the template (would otherwise be interpolated).
        var v = new RepoUrlConstraintValidator("");
        ConstraintValidatorContext ctx = mockContext();
        v.isValid("gopher://127.0.0.1:6379/_", ctx);
        verify(ctx).buildConstraintViolationWithTemplate(
                org.mockito.ArgumentMatchers.argThat(msg ->
                        msg != null && !msg.contains("${") && !msg.contains("{")));
    }
}
