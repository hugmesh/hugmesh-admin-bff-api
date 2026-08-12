package net.hugmesh.adminbff.backingservices;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * One row of {@code backing_service_mode} (Liquibase changeset 310) — the durable, append-only
 * shape for a {@link BackingServiceMode}. The R2DBC-trio convention (the
 * {@link net.hugmesh.adminbff.notification.NotificationOutbox} worked example): a
 * {@code @Table} record with an APP-generated {@code varchar(36)} UUID PK, implementing
 * {@link Persistable} and reporting {@link #isNew()} from a {@code @Transient} flag — a non-null
 * assigned id would otherwise make {@code save} issue an UPDATE. New rows are built via
 * {@link #forInsert} ({@code isNew=true}); rows hydrated by the driver are existing.
 *
 * <p>APPEND-ONLY ledger (like {@code go_live_intent}): each PUT records a NEW row stamped with a
 * monotonic {@code generation}; the CURRENT mode of a service is the row with the highest
 * generation for that {@code service_id}. Rows are never mutated or deleted — the ledger is the
 * audit trail. {@link BackingServiceModeRepository} maps between the row and the domain record.
 */
@Table("backing_service_mode")
public record BackingServiceModeRow(
        @Id @Column("id") String id,
        @Column("service_id") String serviceId,
        @Column("mode") String mode,
        @Column("endpoint") String endpoint,
        @Column("creds_ref") String credsRef,
        @Column("requested_by_subject") String requestedBySubject,
        @Column("created_at") Instant createdAt,
        @Column("generation") long generation,
        @Transient boolean isNew) implements Persistable<String> {

    /** Persistence creator used by the R2DBC converter when HYDRATING a row (the transient
     *  {@code isNew} is not a column, so the read path supplies false). */
    @org.springframework.data.annotation.PersistenceCreator
    public BackingServiceModeRow(String id, String serviceId, String mode, String endpoint,
                                 String credsRef, String requestedBySubject, Instant createdAt,
                                 long generation) {
        this(id, serviceId, mode, endpoint, credsRef, requestedBySubject, createdAt, generation, false);
    }

    /** A fresh row to INSERT (app-generated id, {@code isNew=true} forces an INSERT even though
     *  the id is assigned; {@code created_at} stamped now). */
    public static BackingServiceModeRow forInsert(String id, String serviceId, String mode,
                                                  String endpoint, String credsRef,
                                                  String requestedBySubject, long generation) {
        return new BackingServiceModeRow(id, serviceId, mode, endpoint, credsRef,
                requestedBySubject, Instant.now(), generation, true);
    }

    BackingServiceMode toDomain() {
        return new BackingServiceMode(id, serviceId, mode, endpoint, credsRef,
                requestedBySubject, createdAt, generation);
    }

    @Override
    public String getId() {
        return id;
    }

    @Override
    public boolean isNew() {
        return isNew;
    }
}
