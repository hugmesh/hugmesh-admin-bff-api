package net.hugmesh.adminbff.appeal;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.PersistenceCreator;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * One row of {@code account_appeal} (Liquibase changeset 250) — the durable shape for
 * an {@link AccountAppeal}. PK is an app-generated {@code varchar(36)} UUID string; the
 * entity implements {@link Persistable} so a freshly-minted row INSERTs.
 * {@link AccountAppealRepository} maps between the two.
 */
@Table("account_appeal")
public record AccountAppealRow(
        @Id @Column("id") String id,
        @Column("user_sub") String userSub,
        @Column("handle") String handle,
        @Column("domain") String domain,
        @Column("reason") String reason,
        @Column("contact_email") String contactEmail,
        @Column("status") String status,
        @Column("submitted_at") Instant submittedAt,
        @Column("decided_at") Instant decidedAt,
        @Column("decided_by") String decidedBy,
        @Transient boolean isNew) implements Persistable<String> {

    @PersistenceCreator
    public AccountAppealRow(String id, String userSub, String handle, String domain,
                            String reason, String contactEmail, String status,
                            Instant submittedAt, Instant decidedAt, String decidedBy) {
        this(id, userSub, handle, domain, reason, contactEmail, status, submittedAt,
                decidedAt, decidedBy, false);
    }

    AccountAppeal toDomain() {
        return new AccountAppeal(id, userSub, handle, domain, reason, contactEmail,
                status, submittedAt, decidedAt, decidedBy);
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
