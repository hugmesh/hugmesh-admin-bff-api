package systems.hugmesh.adminbff.servicecatalog;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The data-driven per-service identity derivation (the V7 leg) — every per-service name
 * (Casdoor role, Vault PKI role, ESO ExternalSecret, target secret, namespace, CN) is
 * derived deterministically + DNS/label-safe from {@code (domain, serviceKey)}, so a new
 * service needs no hand-edited ESO/Vault block.
 */
class PerServiceIdentityTest {

    @Test
    void derivesCanonicalNames_forSimpleService() {
        PerServiceIdentity id = new PerServiceIdentity("acme.test", "owncast");
        assertThat(id.casdoorRole()).isEqualTo("ROLE_OWNCAST");
        assertThat(id.vaultPkiRole()).isEqualTo("acme-test-owncast");
        assertThat(id.externalSecretName()).isEqualTo("acme-test-owncast-tls");
        assertThat(id.targetSecretName()).isEqualTo("acme-test-owncast-tls");
        assertThat(id.destNamespace()).isEqualTo("acme-test-be");
        assertThat(id.commonName()).isEqualTo("owncast.acme.test");
        assertThat(id.urlPattern()).isEqualTo("/api/owncast/");
        assertThat(id.domainSlugGateway()).isEqualTo("acme-test-be-gateway");
    }

    @Test
    void sanitisesUnsafeServiceKey_intoDnsLabelSafeNames() {
        // A malformed serviceKey can never inject into a manifest name — non-alphanumerics
        // collapse to '-', and the Casdoor role upper-cases with '_'.
        PerServiceIdentity id = new PerServiceIdentity("Brand.X", "My Cool/Svc!");
        assertThat(id.vaultPkiRole()).isEqualTo("brand-x-my-cool-svc");
        assertThat(id.casdoorRole()).isEqualTo("ROLE_MY_COOL_SVC");
        assertThat(id.externalSecretName()).matches("[a-z0-9-]+");
    }

    @Test
    void templateContext_isOrdered_andComplete() {
        var ctx = new PerServiceIdentity("acme.test", "phpbb").toTemplateContext();
        assertThat(ctx).containsKeys("domain", "serviceSlug", "casdoorRole", "vaultPkiRole",
                "externalSecretName", "targetSecretName", "destNamespace", "commonName");
        assertThat(ctx.get("vaultPkiRole")).isEqualTo("acme-test-phpbb");
    }

    @Test
    void rejectsBlankInputs() {
        assertThatThrownBy(() -> new PerServiceIdentity("", "x"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new PerServiceIdentity("acme.test", " "))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void slug_neverBlank() {
        assertThat(PerServiceIdentity.slug("!!!")).isEqualTo("x");
        assertThat(PerServiceIdentity.slug(null)).isEqualTo("x");
    }
}
