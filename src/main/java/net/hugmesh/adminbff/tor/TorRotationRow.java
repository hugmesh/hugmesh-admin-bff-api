package net.hugmesh.adminbff.tor;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * One row of {@code tor_onion_rotation} (Liquibase changeset 420): how many times a new
 * onion address was asked for one Tor domain (hugmesh-generator#652). Written only through
 * {@link TorRotationRowRepository#increment}.
 */
@Table("tor_onion_rotation")
public record TorRotationRow(
        @Id @Column("domain") String domain,
        @Column("rotation_count") long rotationCount,
        @Column("requested_by") String requestedBy,
        @Column("requested_at") Instant requestedAt) {
}
