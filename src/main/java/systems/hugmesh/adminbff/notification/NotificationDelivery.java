package systems.hugmesh.adminbff.notification;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * One row of {@code notification_delivery} (Liquibase changeset 062 + 063) — the
 * per-channel exactly-once sent guard {@code (id, outbox_id, channel, status, sent_at)}
 * with {@code UNIQUE(outbox_id, channel)}.
 *
 * <p>Spring Data R2DBC entity. The PK is an app-generated UUID string ({@code
 * varchar(36)}), so the entity implements {@link Persistable} and reports {@code
 * isNew()} from a transient flag (a non-null assigned id would otherwise make {@code
 * save} issue an UPDATE). Rows are created via {@link #forInsert} (isNew=true).
 */
@Table("notification_delivery")
public record NotificationDelivery(
        @Id @Column("id") String id,
        @Column("outbox_id") String outboxId,
        @Column("channel") String channel,
        @Column("status") String status,
        @Column("sent_at") Instant sentAt,
        @Transient boolean isNew) implements Persistable<String> {

    @org.springframework.data.annotation.PersistenceCreator
    public NotificationDelivery(String id, String outboxId, String channel, String status, Instant sentAt) {
        this(id, outboxId, channel, status, sentAt, false);
    }

    /** A fresh delivery row to INSERT — {@code sent_at} stamped now (the original
     *  {@code now()} server default), isNew forces the INSERT. */
    public static NotificationDelivery forInsert(String id, String outboxId, String channel, String status) {
        return new NotificationDelivery(id, outboxId, channel, status, Instant.now(), true);
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
