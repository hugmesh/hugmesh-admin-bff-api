package net.hugmesh.adminbff.notification;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * One row of {@code notification_cursor} (Liquibase changeset 062) — the per-consumer
 * delivery cursor {@code (consumer, last_seen, updated_at)}; {@code consumer} is the
 * natural-key PK. {@code last_seen} holds the outbox id of the last fully-processed row.
 *
 * <p>Spring Data R2DBC entity; PK is the natural key {@code consumer}, so the entity
 * implements {@link Persistable} to control INSERT vs UPDATE for the advance upsert.
 */
@Table("notification_cursor")
public record NotificationCursor(
        @Id @Column("consumer") String consumer,
        @Column("last_seen") String lastSeen,
        @Column("updated_at") Instant updatedAt,
        @Transient boolean isNew) implements Persistable<String> {

    @org.springframework.data.annotation.PersistenceCreator
    public NotificationCursor(String consumer, String lastSeen, Instant updatedAt) {
        this(consumer, lastSeen, updatedAt, false);
    }

    public static NotificationCursor of(String consumer, String lastSeen, boolean isNew) {
        return new NotificationCursor(consumer, lastSeen, Instant.now(), isNew);
    }

    @Override
    public String getId() {
        return consumer;
    }

    @Override
    public boolean isNew() {
        return isNew;
    }
}
