package net.hugmesh.adminbff.workload;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/** The server-side secret redaction applied to every log line before it leaves the BFF. */
class LogRedactorTest {

    @Test
    void redactsKeyValueSecrets() {
        assertThat(LogRedactor.redact("password=hunter2")).doesNotContain("hunter2");
        assertThat(LogRedactor.redact("api_key: abc123def")).doesNotContain("abc123def");
        assertThat(LogRedactor.redact("client_secret=topsecretvalue")).doesNotContain("topsecretvalue");
    }

    @Test
    void redactsJwtAndBearer() {
        String jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmno";
        assertThat(LogRedactor.redact("token " + jwt)).doesNotContain("eyJzdWIi");
        assertThat(LogRedactor.redact("Authorization: Bearer aGVsbG93b3JsZHRva2Vu"))
                .doesNotContain("aGVsbG93b3JsZHRva2Vu");
    }

    @Test
    void preservesOrdinaryText() {
        assertThat(LogRedactor.redact("starting server on port 8080"))
                .isEqualTo("starting server on port 8080");
    }

    @Test
    void nullSafe() {
        assertThat(LogRedactor.redact(null)).isNull();
        assertThat(LogRedactor.redact("")).isEmpty();
    }
}
