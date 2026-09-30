package net.hugmesh.adminbff.domainregistry;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import net.hugmesh.adminbff.domainregistry.DomainExportModels.DomainEntry;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * DECISION 87e = A (hugmesh-admin-bff-api#100): {@code brand_title} and {@code headscale_url} are
 * carried on the signed export OUTSIDE the v1 canonical bytes, and a value the brand-repo renderer
 * would refuse is refused at the writer. Pure unit tests — no database, no Spring.
 */
class DomainBrandFieldsExportTest {

    private static DomainRegistration row(String brandTitle, String headscaleUrl) {
        return new DomainRegistration("id-1", "acme.test", "acme", "Org", "vault:pki/acme", "acme",
                "acme-org", "tag:acme", true, Instant.EPOCH, "sa", Instant.EPOCH, false, false, 0L,
                DomainIdp.OWN, "s0:c256", "s0:c257", brandTitle, headscaleUrl);
    }

    // ── export shape ────────────────────────────────────────────────────────────────

    @Test
    void exportEntry_carriesBrandTitleAndHeadscaleUrl() {
        DomainEntry e = DomainRegistryExportService.compile("fp",
                List.of(row("Acme Brand", "https://hs.acme.test"))).entries().get(0);
        assertThat(e.brandTitle()).isEqualTo("Acme Brand");
        assertThat(e.headscaleUrl()).isEqualTo("https://hs.acme.test");
    }

    @Test
    void exportEntry_notSet_isNull_neverADerivedDefault() {
        // null tells the node agent "not set" so it keeps its documented derivation; inventing a
        // value here would make the derived guess look authoritative.
        DomainEntry e = DomainRegistryExportService.compile("fp", List.of(row(null, null)))
                .entries().get(0);
        assertThat(e.brandTitle()).isNull();
        assertThat(e.headscaleUrl()).isNull();
    }

    @Test
    void canonicalBytes_areUnchanged_forAnExistingRow_whateverTheBrandFieldsHold() {
        String without = canonical(row(null, null));
        String with = canonical(row("Acme Brand", "https://hs.acme.test"));
        assertThat(with).as("the v1 signed bytes must not move when the two unsigned fields are set")
                .isEqualTo(without);
        assertThat(without).isEqualTo("v1-domain\nnode=fp\ngeneration=1\n"
                + "dom=acme.test\tbrand=acme\torg=Org\tca=vault:pki/acme\tns=acme\tcasdoor=acme-org"
                + "\tmesh=tag:acme\tca_prov=false\tappset=false\tgen=0\n");
        assertThat(with).doesNotContain("Acme Brand", "hs.acme.test", "title", "headscale");
    }

    private static String canonical(DomainRegistration r) {
        return new String(DomainRegistryExportService.canonicalBytes(
                DomainRegistryExportService.compile("fp", List.of(r))), StandardCharsets.UTF_8);
    }

    // ── write-time rules: generate-brand-repos.sh:113-138, verbatim ────────────────────

    @ParameterizedTest
    @ValueSource(strings = {"Acme", "Acme Brand 2", "Brand-B's place", "Ünïcode Brand", "a.b_c(d)"})
    void title_accepted(String title) {
        assertThat(DomainBrandFields.titleRefusal(title)).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "say \"hi\"", "back\\slash", "$HOME", "`id`", "a|b", "a&b",
            "{{HARBOR_PROJECT}}", "line\nbreak", "cr\rhere", "tab\there"})
    void title_refused(String title) {
        assertThat(DomainBrandFields.titleRefusal(title)).isPresent();
    }

    @Test
    void title_lengthCap_is128() {
        assertThat(DomainBrandFields.titleRefusal("x".repeat(128))).isEmpty();
        assertThat(DomainBrandFields.titleRefusal("x".repeat(129))).isPresent();
    }

    @ParameterizedTest
    @ValueSource(strings = {"https://headscale.acme.test", "http://10.0.0.1:8080",
            "https://hs.acme.test/path?x=1#f"})
    void headscaleUrl_accepted(String url) {
        assertThat(DomainBrandFields.headscaleUrlRefusal(url)).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "headscale.acme.test", "ftp://hs.acme.test", "https://a b",
            "https://a|b", "https://a&b", "https://a'b", "https://a\"b", "https://a`b"})
    void headscaleUrl_refused(String url) {
        assertThat(DomainBrandFields.headscaleUrlRefusal(url)).isPresent();
    }
}
