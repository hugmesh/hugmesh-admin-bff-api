package systems.hugmesh.adminbff.testreports;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit coverage for the read-time secret scrubber: the high-signal secret shapes
 * that leak into test logs / JUnit output are redacted, and benign text survives.
 */
class ReportScrubberTest {

    @Test
    void redactsJwt() {
        String jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.abcDEF123_secret-sig";
        String out = ReportScrubber.scrub("token=" + jwt + " trailing");
        assertThat(out).doesNotContain(jwt).contains("***REDACTED***").contains("trailing");
    }

    @Test
    void redactsBearerToken() {
        String out = ReportScrubber.scrub("Authorization: Bearer abc123def456ghi789");
        assertThat(out).doesNotContain("abc123def456ghi789").contains("***REDACTED***");
    }

    @Test
    void redactsKeyValueSecrets() {
        assertThat(ReportScrubber.scrub("password=hunter2longenough")).contains("***REDACTED***")
                .doesNotContain("hunter2longenough");
        assertThat(ReportScrubber.scrub("\"client_secret\": \"sk_live_abcdef\"")).contains("***REDACTED***")
                .doesNotContain("sk_live_abcdef");
        assertThat(ReportScrubber.scrub("api_key=AKIA1234567890")).contains("***REDACTED***")
                .doesNotContain("AKIA1234567890");
    }

    @Test
    void redactsConnectionStringPassword() {
        String out = ReportScrubber.scrub("r2dbc:postgresql://adminbff:SuperSecret@db:5432/x");
        assertThat(out).doesNotContain("SuperSecret").contains("adminbff:***REDACTED***@db");
    }

    @Test
    void redactsSwarmPassword() {
        assertThat(ReportScrubber.scrub("E2E_SWARM_PASSWORD=deterministic-swarm-pw"))
                .doesNotContain("deterministic-swarm-pw").contains("***REDACTED***");
    }

    @Test
    void leavesBenignTextUntouched() {
        String benign = "19-local-only-mastodon › locked toot absent on peer (1200ms) PASS";
        assertThat(ReportScrubber.scrub(benign)).isEqualTo(benign);
    }

    @Test
    void isTextClassifiesArtifacts() {
        assertThat(ReportScrubber.isText("junit.xml")).isTrue();
        assertThat(ReportScrubber.isText("summary.json")).isTrue();
        assertThat(ReportScrubber.isText("logs/19-local-only.log")).isTrue();
        assertThat(ReportScrubber.isText("trace/screenshot.png")).isFalse();
        assertThat(ReportScrubber.isText(null)).isFalse();
    }

    @Test
    void nullAndEmptySafe() {
        assertThat(ReportScrubber.scrub(null)).isNull();
        assertThat(ReportScrubber.scrub("")).isEmpty();
    }
}
