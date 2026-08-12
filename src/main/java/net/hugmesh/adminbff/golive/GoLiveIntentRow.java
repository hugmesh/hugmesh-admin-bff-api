package net.hugmesh.adminbff.golive;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * One row of {@code go_live_intent} (Liquibase changeset 270) — the durable shape for a
 * {@link GoLiveIntent}. PK is a varchar(36) DB-GENERATED UUID string (the changelog-200
 * {@code (gen_random_uuid())::text} idiom): the INSERT omits {@code id} and reads it back via
 * {@code RETURNING id}, so this entity is READ-ONLY from Spring Data's perspective (no
 * {@code save()} path — mutations are explicit CAS {@code @Query} UPDATEs). {@link
 * GoLiveIntentRepository} maps between the row and the domain record.
 */
@Table("go_live_intent")
public record GoLiveIntentRow(
        @Id @Column("id") String id,
        @Column("cluster_domain") String clusterDomain,
        @Column("target_state") String targetState,
        @Column("exposure_model") String exposureModel,
        @Column("provider") String provider,
        @Column("status") String status,
        @Column("note") String note,
        @Column("requested_by_subject") String requestedBySubject,
        @Column("created_at") Instant createdAt,
        @Column("updated_at") Instant updatedAt,
        @Column("generation") long generation,
        // HOST-AGENT ack surface (ships dark; the BFF never writes these — contract: the
        // in-cluster service records signed intent ONLY, the host agent flips the marker).
        @Column("applied_at") Instant appliedAt,
        @Column("applied_by") String appliedBy) {

    GoLiveIntent toDomain() {
        return new GoLiveIntent(id, clusterDomain, targetState, exposureModel, provider, status,
                note, requestedBySubject, createdAt, updatedAt, generation, appliedAt, appliedBy);
    }
}
