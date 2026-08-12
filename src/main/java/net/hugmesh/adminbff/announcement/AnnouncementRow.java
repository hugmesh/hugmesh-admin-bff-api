package net.hugmesh.adminbff.announcement;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.PersistenceCreator;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.UUID;

/**
 * One row of {@code announcement} (Liquibase changeset 060 + the 061 {@code domain}
 * column) — the durable shape for an {@link Announcement}. PK is a {@code uuid}; the
 * timestamp columns are {@code timestamp} (no zone) so they map as {@link LocalDateTime}
 * (UTC, matching the facade's prior binds). {@link Announcement} stays the JSON projection
 * (string id, Instant times, {@code @JsonProperty} names); {@link AnnouncementRepository}
 * maps between the two. Implements {@link Persistable} so a new row INSERTs.
 */
@Table("announcement")
public record AnnouncementRow(
        @Id @Column("id") UUID id,
        @Column("title") String title,
        @Column("body_html") String bodyHtml,
        @Column("format") String format,
        @Column("state") String state,
        @Column("target_home") boolean targetHome,
        @Column("target_login") boolean targetLogin,
        @Column("target_akkoma") boolean targetAkkoma,
        @Column("target_forum") boolean targetForum,
        @Column("priority") int priority,
        @Column("starts_at") LocalDateTime startsAt,
        @Column("ends_at") LocalDateTime endsAt,
        @Column("timezone") String timezone,
        @Column("dismissible") boolean dismissible,
        @Column("created_by") String createdBy,
        @Column("akkoma_ref") String akkomaRef,
        @Column("created_at") LocalDateTime createdAt,
        @Column("updated_at") LocalDateTime updatedAt,
        @Column("domain") String domain,
        @Transient boolean isNew) implements Persistable<UUID> {

    @PersistenceCreator
    public AnnouncementRow(UUID id, String title, String bodyHtml, String format, String state,
                           boolean targetHome, boolean targetLogin, boolean targetAkkoma, boolean targetForum,
                           int priority, LocalDateTime startsAt, LocalDateTime endsAt, String timezone,
                           boolean dismissible, String createdBy, String akkomaRef,
                           LocalDateTime createdAt, LocalDateTime updatedAt, String domain) {
        this(id, title, bodyHtml, format, state, targetHome, targetLogin, targetAkkoma, targetForum,
                priority, startsAt, endsAt, timezone, dismissible, createdBy, akkomaRef,
                createdAt, updatedAt, domain, false);
    }

    private static Instant toInstant(LocalDateTime t) {
        return t == null ? null : t.toInstant(ZoneOffset.UTC);
    }

    static LocalDateTime toLocal(Instant i) {
        return i == null ? null : LocalDateTime.ofInstant(i, ZoneOffset.UTC);
    }

    Announcement toDomain() {
        return new Announcement(id.toString(), title, bodyHtml, format, state, targetHome, targetLogin,
                targetAkkoma, targetForum, priority, toInstant(startsAt), toInstant(endsAt), timezone,
                dismissible, createdBy, akkomaRef, toInstant(createdAt), toInstant(updatedAt), domain);
    }

    @Override
    public UUID getId() {
        return id;
    }

    @Override
    public boolean isNew() {
        return isNew;
    }
}
