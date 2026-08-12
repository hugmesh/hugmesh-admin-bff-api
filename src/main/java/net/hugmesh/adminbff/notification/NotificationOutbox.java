package net.hugmesh.adminbff.notification;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * One row of {@code notification_outbox} (Liquibase changeset 062) — the durable,
 * append-only TRANSACTIONAL-OUTBOX record that an effect occurred which should notify
 * the affected principal via the neutral per-domain {@code @system} sender. Schema in
 * {@code db/changelog/062-notification-outbox.xml}.
 *
 * <p>It is written in the SAME reactive transaction as the effect it describes (e.g.
 * the {@code access_suspension} ban/timeout row), so the outbox row exists IFF the
 * effect commits — the lossless transactional-outbox pattern. A later consumer (the
 * hugmesh-actions reconciler, PR4) tails this table and fans the notification to
 * the delivery channels; NOTHING reads it yet (this PR ships dark).
 *
 * <p><b>Identity rule.</b> {@link #payload} carries ONLY the {@code reason} / {@code
 * ttl} / target context needed to compose a neutral system message. The acting
 * mod/admin identity ({@code mod_action.actor} / {@code set_by}) is DELIBERATELY
 * EXCLUDED — the {@code @system} sender is neutral and must never expose who took the
 * action (the same rule the public {@code AppealContact} resolver follows: surface
 * nothing usable for reconnaissance / retaliation against the moderator).
 *
 * <p>This is a Spring Data R2DBC entity ({@code @Table}/{@code @Id}/{@code @Column}). The
 * primary key is an app-generated UUID string ({@code varchar(36)}), so the entity
 * implements {@link Persistable} and reports {@code isNew()} from a transient flag — a
 * non-null assigned id would otherwise make {@code save} issue an UPDATE. New rows are
 * built via {@link #forInsert} (isNew=true); rows hydrated by the driver are existing.
 */
@Table("notification_outbox")
public record NotificationOutbox(
        @Id @Column("id") String id,
        @Column("domain") String domain,
        @Column("source_table") String sourceTable,
        @Column("source_id") String sourceId,
        @Column("category") String category,
        @Column("payload") String payload,
        @Column("created_at") Instant createdAt,
        @Transient boolean isNew) implements Persistable<String> {

    /** Persistence creator used by the R2DBC converter when HYDRATING a row (the
     *  transient {@code isNew} is not a column, so the read path supplies false). */
    @org.springframework.data.annotation.PersistenceCreator
    public NotificationOutbox(String id, String domain, String sourceTable, String sourceId,
                              String category, String payload, Instant createdAt) {
        this(id, domain, sourceTable, sourceId, category, payload, createdAt, false);
    }

    /** The desired-state table account-restriction notifications are emitted from. */
    public static final String SOURCE_ACCESS_SUSPENSION = "access_suspension";

    /** The category for a ban / timeout / unban account-restriction notification. */
    public static final String CATEGORY_ACCOUNT_RESTRICTION = "account-restriction";

    /** The category for an INFRA-IMPACTING notification (a platform change that may
     *  temporarily affect a service the user uses) — Notifications PR7. */
    public static final String CATEGORY_INFRA_IMPACTING = "infra-impacting";

    /** The category for a FEATURE-AVAILABILITY notification (a feature on the service was
     *  enabled/disabled/changed for the user) — Notifications PR7. */
    public static final String CATEGORY_FEATURE_AVAILABILITY = "feature-availability";

    /** The synthetic source-table for trigger-emitted (non-effect) feature/infra
     *  notifications — distinguishes them from desired-state-derived rows. */
    public static final String SOURCE_PLATFORM_EVENT = "platform_event";

    /** The desired-state table backup/restore notifications are emitted from (the
     *  {@code backup_set} catalog row, schema 160). The {@code (source_table, source_id,
     *  category)} natural key dedups a re-emitted event for the same set. */
    public static final String SOURCE_BACKUP_SET = "backup_set";

    /** The category for a BACKUP-STARTED infra event — a per-domain / total-cloud backup
     *  run was requested. Payload carries scope/version/services-count/destination ONLY
     *  (never the acting admin/superadmin identity). */
    public static final String CATEGORY_BACKUP_STARTED = "backup-started";

    /** The category for a RESTORE-STARTED infra event — a (step-up-gated) restore of a
     *  backup set version was requested. Payload carries scope/version/services-count ONLY
     *  (never the acting admin/superadmin identity). */
    public static final String CATEGORY_RESTORE_STARTED = "restore-started";

    /** The desired-state table managed-backing-service mode intents are emitted from (the
     *  {@code backing_service_mode} ledger, schema 310). CROSS-DOMAIN infra: the row is
     *  stamped with the {@code default} single-issuer sentinel domain, not a per-brand one. */
    public static final String SOURCE_BACKING_SERVICE_MODE = "backing_service_mode";

    /** The category for a BACKING-SERVICE MODE-CHANGE infra event — a superadmin recorded a
     *  self-hosted/managed mode intent for a backing service. Payload carries
     *  service-id/kind/tier/mode ONLY — NEVER the acting superadmin identity, the managed
     *  endpoint, or the creds reference. */
    public static final String CATEGORY_BACKING_SERVICE_MODE_CHANGED = "backing-service-mode-changed";

    /** A fresh row to INSERT. {@code created_at} is stamped now (equivalent to the
     *  original {@code now()} server-side default the INSERT relied on); isNew forces
     *  an INSERT even though the id is assigned. */
    public static NotificationOutbox forInsert(String id, String domain, String sourceTable,
                                               String sourceId, String category, String payload) {
        return new NotificationOutbox(id, domain, sourceTable, sourceId, category, payload,
                Instant.now(), true);
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
