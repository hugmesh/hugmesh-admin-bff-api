package net.hugmesh.adminbff.announcement;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The server-side body_html sanitiser MUST strip the XSS-relevant constructs (the
 * announcement body is rendered to users including anonymous login visitors) while
 * keeping safe rich-text markup. Exercises the jsoup Safelist allowlist directly.
 */
class AnnouncementSanitizerTest {

    private final AnnouncementSanitizer sanitizer = new AnnouncementSanitizer();

    @Test
    void stripsScriptTag() {
        String out = sanitizer.sanitize("<p>hello</p><script>alert('xss')</script>");
        assertThat(out).doesNotContain("<script").doesNotContain("alert");
        assertThat(out).contains("<p>hello</p>");
    }

    @Test
    void stripsOnErrorHandlerButKeepsImg() {
        // jsoup's relaxed allowlist requires a real protocol on img[src], so a safe
        // https image survives while the onerror handler is stripped.
        String out = sanitizer.sanitize(
                "<img src=\"https://cdn.example/a.png\" onerror=\"alert(1)\">");
        assertThat(out).doesNotContain("onerror").doesNotContain("alert");
        assertThat(out).contains("<img");
        assertThat(out).contains("src=\"https://cdn.example/a.png\"");
    }

    @Test
    void dropsProtocolRelativeImgSrcButRemovesOnError() {
        // A protocol-less src ("x") is dropped by the allowlist; the critical part is
        // the onerror XSS vector is gone either way.
        String out = sanitizer.sanitize("<img src=\"x\" onerror=\"alert(1)\">");
        assertThat(out).doesNotContain("onerror").doesNotContain("alert");
    }

    @Test
    void stripsJavascriptUrl() {
        String out = sanitizer.sanitize("<a href=\"javascript:alert(1)\">click</a>");
        assertThat(out).doesNotContain("javascript:");
        // The link text survives even though the unsafe href is dropped.
        assertThat(out).contains("click");
    }

    @Test
    void stripsIframeAndForm() {
        String out = sanitizer.sanitize(
                "<iframe src=\"https://evil.example\"></iframe><form action=\"/steal\"><input></form>");
        assertThat(out).doesNotContain("<iframe").doesNotContain("<form").doesNotContain("<input");
    }

    @Test
    void keepsSafeRichText() {
        String out = sanitizer.sanitize(
                "<h2>Title</h2><p><strong>bold</strong> and <em>italic</em></p>"
                + "<ul><li>one</li></ul><a href=\"https://hugmesh.systems\">link</a>");
        assertThat(out).contains("<h2>", "<strong>", "<em>", "<ul>", "<li>");
        assertThat(out).contains("href=\"https://hugmesh.systems\"");
    }

    @Test
    void nullOrBlankBecomesEmpty() {
        assertThat(sanitizer.sanitize(null)).isEmpty();
        assertThat(sanitizer.sanitize("   ")).isEmpty();
    }
}
