package net.hugmesh.adminbff.meshtoken;

import java.time.Instant;

/**
 * One issued HugMesh token, as the audit trail and {@code GET /bff/admin/mesh-tokens} show it.
 *
 * <p>There is deliberately NO token, pre-auth key, key prefix or signature here, and no field
 * that could carry one: the token is returned to the issuing admin once and never stored.
 * {@code preauthKeyId} is headscale's numeric key id, which lets an operator find (and expire)
 * the key in {@code headscale preauthkeys list} without the key itself.
 */
public record MeshTokenIssued(
        String id,
        String mesh,
        String domain,
        String role,
        boolean shell,
        String loginServer,
        String issuerFingerprint,
        String preauthKeyId,
        String nodeName,
        String issuedBy,
        Instant issuedAt,
        Instant expiresAt) {

    MeshTokenIssuedRow toNewRow() {
        return new MeshTokenIssuedRow(id, mesh, domain, role, shell, loginServer, issuerFingerprint,
                preauthKeyId, nodeName, issuedBy, issuedAt, expiresAt, true);
    }
}
