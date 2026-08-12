package net.hugmesh.adminbff.backup;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;

/**
 * One row of {@code backup_history} (Liquibase changeset 008) — the durable
 * record of a backup the admin started. The JSON shape is what the admin-ui
 * Backups history view reads.
 *
 * <p>Security: {@code encrypted} records only THAT a backup is password-encrypted;
 * the plaintext password is never persisted. {@code verifierSalt} +
 * {@code verifier} are a PBKDF2 verifier (see {@link BackupCrypto}) used ONLY to
 * confirm, on restore, that the supplied decryption password matches — they do
 * not reveal the key (one-way KDF). {@code scope} is the comma-separated list of
 * {@link BackupScope} names; {@code target} / {@code status} are closed enums
 * mirrored by DB CHECK constraints (parity with the platform's API↔DB rule).
 */
public record BackupRecord(
        String id,
        @JsonProperty("created_at") Instant createdAt,
        @JsonProperty("requested_by") String requestedBy,
        String scope,
        String target,
        boolean encrypted,
        String status,
        @JsonProperty("size_bytes") Long sizeBytes,
        String error,
        @JsonProperty("location_ref") String locationRef,
        // The two verifier columns are NEVER serialised to the UI (no @JsonProperty
        // would still leak them as camelCase keys), so they are explicitly hidden.
        @com.fasterxml.jackson.annotation.JsonIgnore String verifierSalt,
        @com.fasterxml.jackson.annotation.JsonIgnore String verifier) {
}
