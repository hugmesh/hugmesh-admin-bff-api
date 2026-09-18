package net.hugmesh.adminbff.domainregistry;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link DomainSlug} — operator DECISION 29a (2026-09-17): <em>"the slug rule is
 * {@code ns_prefix} — it also names the Vault path {@code secret/<slug>/casdoor}, so namespace
 * and secret path now agree, and a wrong slug mis-addresses a secret"</em>.
 *
 * <p>Pure unit tests, no database. These pin the RULE itself, so a later agent cannot quietly
 * move the slug back to {@code brand} or to something derived from {@code cluster_domain}: the
 * expansions asserted below are what the generator's per-domain base reads.
 */
class DomainSlugTest {

    @Test
    @DisplayName("the slug expands into the namespace and the Vault path — one value, both names")
    void expansions_areTheNamespaceAndTheVaultPath() {
        assertThat(DomainSlug.pkiNamespace("acme")).isEqualTo("acme-pki");
        assertThat(DomainSlug.vaultPath("acme")).isEqualTo("secret/acme/casdoor");
    }

    @Test
    @DisplayName("a DNS-1123 label is accepted")
    void validLabels_areAccepted() {
        assertThat(DomainSlug.isValid("acme")).isTrue();
        assertThat(DomainSlug.isValid("acme-example")).isTrue();
        assertThat(DomainSlug.isValid("a")).isTrue();
        assertThat(DomainSlug.isValid("a1-b2-c3")).isTrue();
        assertThat(DomainSlug.isValid("9lives")).isTrue();
    }

    @Test
    @DisplayName("an absent slug is refused, with the reason it is required")
    void absentSlug_isRefusedWithItsReason() {
        assertThat(DomainSlug.refusalReason(null))
                .hasValueSatisfying(reason -> assertThat(reason)
                        .contains("nsPrefix is required")
                        .contains("secret/<nsPrefix>/casdoor"));
        assertThat(DomainSlug.isValid("")).isFalse();
        assertThat(DomainSlug.isValid("   ")).isFalse();
    }

    @Test
    @DisplayName("a value that cannot be a Kubernetes namespace is refused")
    void nonLabelValues_areRefused() {
        // A dot is the one that matters most: "ns-alpha.test" produces the namespace
        // "ns-alpha.test-pki", which Kubernetes rejects — and the rejection surfaces as a
        // failed ArgoCD sync long after the SUPERADMIN pressed save, not as a 400.
        assertThat(DomainSlug.isValid("ns-alpha.test")).isFalse();
        assertThat(DomainSlug.isValid("Acme")).as("uppercase is not a DNS-1123 label").isFalse();
        assertThat(DomainSlug.isValid("-acme")).isFalse();
        assertThat(DomainSlug.isValid("acme-")).isFalse();
        assertThat(DomainSlug.isValid("acme_example")).isFalse();
        assertThat(DomainSlug.isValid("acme example")).isFalse();
        assertThat(DomainSlug.isValid("acme/../etc")).as("no path traversal into the Vault path")
                .isFalse();
        assertThat(DomainSlug.isValid(" acme")).isFalse();
    }

    @Test
    @DisplayName("the slug-uniqueness constraint is recognised in a wrapped driver error")
    void isSlugCollision_matchesTheConstraintAnywhereInTheChain() {
        assertThat(DomainSlug.isSlugCollision(new RuntimeException("executeMany",
                new RuntimeException("duplicate key value violates unique constraint "
                        + "\"uq_domain_registry_ns_prefix\""))))
                .as("R2DBC wraps the driver exception, so the match must walk the cause chain")
                .isTrue();
        assertThat(DomainSlug.isSlugCollision(
                new RuntimeException("UQ_DOMAIN_REGISTRY_NS_PREFIX")))
                .as("H2 upper-cases constraint names")
                .isTrue();
        assertThat(DomainSlug.isSlugCollision(
                new RuntimeException("uq_domain_registry_cluster_domain")))
                .as("a duplicate natural key is a DIFFERENT conflict with a different message")
                .isFalse();
        assertThat(DomainSlug.isSlugCollision(new RuntimeException((String) null))).isFalse();
    }

    @Test
    @DisplayName("the length cap leaves room for the -pki suffix, not just the label's own 63")
    void lengthCap_leavesRoomForTheNamespaceSuffix() {
        assertThat(DomainSlug.MAX_LENGTH)
                .as("""
                        The value that has to be a legal Kubernetes namespace is <slug>-pki, \
                        four characters longer than the slug. A cap of 63 here would accept a \
                        slug whose namespace is 67 characters and cannot be created.""")
                .isEqualTo(59);

        String atCap = "a".repeat(DomainSlug.MAX_LENGTH);
        assertThat(DomainSlug.isValid(atCap)).isTrue();
        assertThat(DomainSlug.pkiNamespace(atCap).length())
                .as("the derived namespace still fits a DNS-1123 label")
                .isLessThanOrEqualTo(63);
        assertThat(DomainSlug.isValid("a".repeat(DomainSlug.MAX_LENGTH + 1))).isFalse();
    }
}
