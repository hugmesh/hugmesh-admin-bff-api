package net.hugmesh.adminbff.gamesservices;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * The digest-pin validator — the server-side gate that REJECTS mutable tag-only image
 * references (arbitrary-container exec containment). The catalog only ever accepts
 * {@code repo@sha256:<64 hex>}.
 */
class ImageRefTest {

    private static final String SHA64 =
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

    @Test
    void acceptsDigestPinnedReference() {
        assertThat(ImageRef.isDigestPinned("ghcr.io/org/game@sha256:" + SHA64)).isTrue();
        assertThat(ImageRef.isDigestPinned("registry.example.com:5000/a/b/c@sha256:" + SHA64)).isTrue();
        assertThatCode(() -> ImageRef.validate("docker.io/library/x@sha256:" + SHA64))
                .doesNotThrowAnyException();
    }

    @Test
    void rejectsTagOnlyReference() {
        assertThat(ImageRef.isDigestPinned("ghcr.io/org/game:latest")).isFalse();
        assertThat(ImageRef.isDigestPinned("ghcr.io/org/game:1.2.3")).isFalse();
        assertThat(ImageRef.isDigestPinned("ghcr.io/org/game")).isFalse();
        assertThatThrownBy(() -> ImageRef.validate("ghcr.io/org/game:latest"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("digest-pinned");
    }

    @Test
    void rejectsMalformedDigest() {
        // Wrong algo, short hex, uppercase hex, null.
        assertThat(ImageRef.isDigestPinned("x@sha512:" + SHA64)).isFalse();
        assertThat(ImageRef.isDigestPinned("x@sha256:abc")).isFalse();
        assertThat(ImageRef.isDigestPinned("x@sha256:" + SHA64.toUpperCase())).isFalse();
        assertThat(ImageRef.isDigestPinned(null)).isFalse();
    }
}
