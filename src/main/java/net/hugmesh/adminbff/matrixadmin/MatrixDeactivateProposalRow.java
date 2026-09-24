package net.hugmesh.adminbff.matrixadmin;

import java.time.Instant;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.PersistenceCreator;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

/**
 * One row of {@code matrix_admin_deactivate_proposal} (Liquibase changeset 370): a single
 * PROPOSE of an ADMIN-only Matrix account deactivate, and — once confirmed — its outcome.
 *
 * <p>The raw confirmation token is NEVER stored: only its SHA-256 ({@code token_hash}), so a
 * database read cannot be replayed as a confirm. Rows are never deleted; the table is the
 * audit trail of both calls ({@code proposed_by}/{@code proposed_at} for the propose,
 * {@code confirmed_at}/{@code outcome} for the confirm). Same R2DBC-trio convention as
 * {@code BackingServiceModeRow}: app-generated varchar(36) id + a {@code @Transient isNew}
 * so {@code save} INSERTs.
 */
@Table("matrix_admin_deactivate_proposal")
public record MatrixDeactivateProposalRow(
        @Id @Column("id") String id,
        @Column("token_hash") String tokenHash,
        @Column("mxid") String mxid,
        @Column("proposed_by") String proposedBy,
        @Column("proposed_at") Instant proposedAt,
        @Column("expires_at") Instant expiresAt,
        @Column("state") String state,
        @Column("confirmed_at") Instant confirmedAt,
        @Column("outcome") String outcome,
        @Transient boolean isNew) implements Persistable<String> {

    public static final String STATE_PROPOSED = "proposed";
    public static final String STATE_CONFIRMED = "confirmed";

    /** Hydration constructor (the transient {@code isNew} is not a column). */
    @PersistenceCreator
    public MatrixDeactivateProposalRow(String id, String tokenHash, String mxid, String proposedBy,
                                       Instant proposedAt, Instant expiresAt, String state,
                                       Instant confirmedAt, String outcome) {
        this(id, tokenHash, mxid, proposedBy, proposedAt, expiresAt, state, confirmedAt, outcome, false);
    }

    /** A fresh {@code proposed} row to INSERT. */
    public static MatrixDeactivateProposalRow forInsert(String id, String tokenHash, String mxid,
                                                        String proposedBy, Instant proposedAt,
                                                        Instant expiresAt) {
        return new MatrixDeactivateProposalRow(id, tokenHash, mxid, proposedBy, proposedAt, expiresAt,
                STATE_PROPOSED, null, null, true);
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
