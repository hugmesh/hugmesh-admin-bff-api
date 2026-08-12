package net.hugmesh.adminbff.servicecatalog.scaffold;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The literal {@code {{TOKEN}}} renderer contract: substitute known tokens, strip the
 * {@code {{!}}} Handlebars empty-comment separator, and HARD-FAIL on any unresolved
 * {@code {{UPPER_SNAKE}}} residual (so a scaffold never ships with a broken literal token).
 */
class TokenRendererTest {

    private static final Map<String, String> CTX = Map.of(
            "APP_SLUG", "owncast", "CLUSTER_DOMAIN", "acme.test", "BRAND_TITLE", "Owncast");

    @Test
    void substitutesKnownTokens() {
        String out = TokenRenderer.render(
                "name: {{APP_SLUG}}-bff\ntitle: {{BRAND_TITLE}}\nhost: id.{{CLUSTER_DOMAIN}}", CTX);
        assertThat(out).isEqualTo("name: owncast-bff\ntitle: Owncast\nhost: id.acme.test");
    }

    @Test
    void stripsHandlebarsEmptyCommentSeparator() {
        // The skeletons use {{!}} so a "...{{CLUSTER_DOMAIN}}{{!}}}" sequence closes the ${...}
        // with a bare '}' instead of gluing into a triple-stache. After render the separator is
        // gone and the trailing literal '}' survives.
        String out = TokenRenderer.render("${X:https://id.{{CLUSTER_DOMAIN}}{{!}}}", CTX);
        assertThat(out).isEqualTo("${X:https://id.acme.test}");
    }

    @Test
    void hardFailsOnUnresolvedUpperSnakeToken() {
        assertThatThrownBy(() -> TokenRenderer.render("a {{APP_SLUG}} then {{MYSTERY_TOKEN}}", CTX))
                .isInstanceOf(TokenRenderer.UnrenderedTokenException.class)
                .hasMessageContaining("{{MYSTERY_TOKEN}}");
    }

    @Test
    void residualTokens_listsEveryUnresolvedTokenSortedAndDeduped() {
        assertThat(TokenRenderer.residualTokens("{{B_TOKEN}} {{A_TOKEN}} {{A_TOKEN}}"))
                .containsExactly("{{A_TOKEN}}", "{{B_TOKEN}}");
        assertThat(TokenRenderer.residualTokens("fully rendered, no tokens")).isEmpty();
    }

    @Test
    void emptyContentIsUnchanged() {
        assertThat(TokenRenderer.render("", CTX)).isEmpty();
    }
}
