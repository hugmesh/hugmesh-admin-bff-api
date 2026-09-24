package net.hugmesh.adminbff.domainregistry;

import java.util.List;

/**
 * The wire shapes of the signed {@code domain_registry} export — CLONES
 * {@link net.hugmesh.adminbff.device.ExportModels} (the device-license-registry
 * export) and {@link net.hugmesh.adminbff.egressvpn.VpnExportModels} (egress-VPN).
 * The export is what the (not-yet-built) generator DOMAIN-RECONCILE agent compiles into the
 * per-domain CA loop + the brand-list ArgoCD ApplicationSet — the ONE missing export
 * symmetry for runtime add-domain provisioning (the {@code device_registry}, egress-VPN and
 * node-storage registries each already ship a signed {@code /export}; this adds it for
 * domains).
 *
 * <h3>Cross-domain by construction</h3>
 * Unlike the device/VPN/storage exports (which are PER-NODE — a node may see only its own
 * authorized set), {@code domain_registry} is the REGISTRY OF BRANDS itself: it carries NO
 * per-row tenant discriminator (see Liquibase 012) and the reconcile agent needs the WHOLE
 * brand list to materialise the ApplicationSet. So the body carries EVERY ENABLED domain.
 * The optional {@code node} fingerprint the caller addresses is pinned into the header as
 * PROVENANCE only (mirroring the device export's resolved-mesh header) — it does NOT scope
 * the body (there is nothing per-node to scope to).
 *
 * <p>The signature is DETACHED over the canonical body {@code {generation, node, entries}}
 * (a stable line-oriented UTF-8 encoding, NOT JSON, to avoid serializer field-ordering
 * ambiguity). The body carries the {@code caRef} (a CA *reference* — a Vault PKI path /
 * secret name / {@code "generate"}), NEVER the CA cert/key bytes; secrets stay off-DB +
 * off-export.
 */
public final class DomainExportModels {

    private DomainExportModels() {
    }

    /**
     * One compiled registry entry per ENABLED domain — the descriptors the reconcile agent
     * needs to materialise the per-brand namespaces / CA / Casdoor org / mesh and to gate the
     * "registered but not yet provisioned" state.
     *
     * <p><b>The three DECISION-29 fields ({@code idp} + the MCS pair) ride OUTSIDE the
     * signature.</b> See {@link DomainRegistryExportService#canonicalBytes}: the consumer half
     * (hugmesh-generator {@code specs/usr/lib/hugmesh/domain-verify.sh}) reconstructs the
     * canonical bytes from exactly the TEN v1 fields, byte for byte, and fails CLOSED on any
     * divergence — so adding a field to the SIGNED bytes is a lockstep two-repo change (the
     * consumer must accept v1 AND v2 before the producer moves). That is deliberately NOT done
     * here. The residual cost: something that gets past the export's mTLS could flip
     * {@code idp} or an MCS category without breaking the signature.
     *
     * @param clusterDomain   the brand's base domain (the UNIQUE natural key)
     * @param brand           the short slug used in names
     * @param org             the brand's organisation/owner label
     * @param caRef           the CA *reference* (Vault PKI path / secret name / "generate") —
     *                        NEVER the cert/key bytes
     * @param nsPrefix        the k8s namespace prefix the ApplicationSet expands into
     *                        {@code ${nsPrefix}-pki / -backend / -frontend}
     * @param casdoorOrg      the per-brand Casdoor organisation (the token issuer is the
     *                        per-domain discriminator)
     * @param meshTag         the headscale/tailnet mesh tag for the brand's nodes
     * @param caProvisioned   whether the per-domain CA has been provisioned (band-190 status;
     *                        the effector's own write surface — {@code false} until reconciled)
     * @param appsetRegistered whether the brand-list ApplicationSet entry has been registered
     *                        (band-190 status; {@code false} until reconciled)
     * @param generation      the per-domain monotonic generation (the row's
     *                        {@code last_reconciled_generation}) the agent's rollback guard
     *                        reads at the row grain
     * @param idp             the domain's identity-provider choice, {@code own} or
     *                        {@code superdomain} (operator DECISION 29b). The generator's
     *                        {@code hugmesh-domain-reconcile} ALREADY reads it
     *                        ({@code .body.entries[i].idp}) and validates it as a closed enum;
     *                        until this field existed it read absent, so every exported domain
     *                        reconciled as {@code superdomain} and no per-domain Casdoor was
     *                        ever provisioned
     * @param selinuxLevel    the MCS category allocated to the domain's Casdoor pod
     *                        ({@code s0:cNN}, DECISION 29c) — the element field
     *                        {@code selinuxLevel} in the 05b ApplicationSet; {@code null} on a
     *                        row registered before the allocator existed, which the consumer
     *                        must treat as NOT provisionable rather than substituting a default
     * @param selinuxLevelPg  the MCS category allocated to the domain's Postgres pod
     *                        ({@code s0:cNN}, DECISION 29c) — always the ODD half of the pair
     */
    public record DomainEntry(
            String clusterDomain,
            String brand,
            String org,
            String caRef,
            String nsPrefix,
            String casdoorOrg,
            String meshTag,
            boolean caProvisioned,
            boolean appsetRegistered,
            long generation,
            String idp,
            String selinuxLevel,
            String selinuxLevelPg) {
    }

    /**
     * The canonical (pre-signature) export body. {@code generation} is the EXPORT-level
     * monotonic counter ({@code max} over the contributing rows' {@code last_reconciled_
     * generation}, +1 floor when the registry is non-empty so a fresh registry advances past
     * 0) the agent's strict-monotonic rollback guard reads; {@code node} is the addressing
     * fingerprint pinned as PROVENANCE (empty for the unscoped/whole-registry fetch);
     * {@code entries} are sorted deterministically by {@code clusterDomain} so the
     * content-hash is stable + reproducible.
     */
    public record DomainExportBody(
            String node,
            long generation,
            List<DomainEntry> entries) {
    }

    /**
     * The signed envelope served by {@code GET /bff/admin/domains/export}. Mirrors
     * {@code SignedExport}/{@code SignedVpnExport}: {@code contentHash} is
     * SHA-256(canonical-body-bytes); {@code signature} is the detached Ed25519 over the
     * canonical body bytes (base64), or {@code null} when no signing key is configured (the
     * agent fail-closes and keeps its last-good cache); {@code publicKey} advertises the
     * verifying half (base64 X.509) when configured; {@code signed} mirrors
     * {@code signature != null}.
     */
    public record SignedDomainExport(
            DomainExportBody body,
            String contentHash,
            String signature,
            String publicKey,
            boolean signed) {
    }
}
