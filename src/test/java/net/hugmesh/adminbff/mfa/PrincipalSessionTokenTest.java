package net.hugmesh.adminbff.mfa;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/** Which session's MFA stamp counts for the current principal. */
class PrincipalSessionTokenTest {

    @Test
    void anExplicitBffBearer_winsOverADifferentCookie() {
        assertThat(PrincipalSessionToken.of("bff_B", "Bearer bff_A")).isEqualTo("bff_A");
    }

    @Test
    void theHeaderIsParsedLikeThePrincipalFilterParsesIt() {
        assertThat(PrincipalSessionToken.of("bff_B", "bearer bff_A")).isEqualTo("bff_A");
        assertThat(PrincipalSessionToken.of("bff_B", "BEARER bff_A")).isEqualTo("bff_A");
        assertThat(PrincipalSessionToken.of("bff_B", "  Bearer   bff_A  ")).isEqualTo("bff_A");
    }

    @Test
    void theCookieCountsOnlyWhenTheHeaderNamesNoSession() {
        assertThat(PrincipalSessionToken.of("bff_B", null)).isEqualTo("bff_B");
        assertThat(PrincipalSessionToken.of("bff_B", "Bearer eyJhbGciOi.jwt.sig")).isEqualTo("bff_B");
        assertThat(PrincipalSessionToken.of("not-a-session", null)).isNull();
        assertThat(PrincipalSessionToken.of(null, "Basic Zm9vOmJhcg==")).isNull();
    }

    @Test
    void fromAuthorization_neverReadsACookie() {
        assertThat(PrincipalSessionToken.fromAuthorization((String) null)).isNull();
        assertThat(PrincipalSessionToken.fromAuthorization("Bearer bff_A")).isEqualTo("bff_A");
        assertThat(PrincipalSessionToken.fromAuthorization("Bearer jwt")).isNull();
        assertThat(PrincipalSessionToken.fromAuthorization("Bearerbff_A")).isNull();
    }

    /**
     * No production MFA lookup may go back to the cookie-first helper with a cookie argument.
     * The one allowed caller outside {@link PrincipalSessionToken} is logout
     * ({@code AuthController.sessionOut}), which deletes a session and reads no MFA stamp.
     */
    @Test
    void noProductionCodeReadsTheCookieFirst_exceptLogout() throws IOException {
        Pattern call = Pattern.compile("bffTokenFrom\\(\\s*([^,]+?)\\s*,");
        List<String> offenders = new ArrayList<>();
        Path root = Path.of("src/main/java");
        try (Stream<Path> files = Files.walk(root)) {
            for (Path f : files.filter(p -> p.toString().endsWith(".java")).toList()) {
                String name = f.getFileName().toString();
                if (name.equals("PrincipalSessionToken.java")) {
                    continue;
                }
                String src = Files.readString(f);
                Matcher m = call.matcher(src);
                while (m.find()) {
                    String first = m.group(1);
                    if (first.equals("null") || first.equals("String")) {
                        continue;
                    }
                    if (name.equals("AuthController.java") && first.equals("cookie")) {
                        continue;
                    }
                    offenders.add(root.relativize(f) + ": bffTokenFrom(" + first + ", ...)");
                }
            }
        }
        assertThat(offenders).isEmpty();
    }
}
