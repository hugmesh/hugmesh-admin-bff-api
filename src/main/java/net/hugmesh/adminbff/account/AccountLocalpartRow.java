package net.hugmesh.adminbff.account;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

/**
 * A narrow, admin-bff-LOCAL projection of the shared {@code account} table (Liquibase
 * changeset 004, owned end-to-end in JAVA by auth-core's {@code AccountRow}/{@code
 * AccountStore}/{@code AccountRowRepository}) covering ONLY the {@code id} +
 * {@code localpart} (Liquibase changeset 290) + {@code mastodon_localpart}
 * (Liquibase changeset 291) columns.
 *
 * <p>Deliberately NOT added as a field on auth-core's {@code AccountRow}/{@code Account}:
 * auth-core is a separately-versioned Maven dependency shared with user-bff-api (see
 * this module's {@code pom.xml}), so adding a field there would force a version-bump
 * chain through BOTH consumers for what is otherwise a single-repo concern — admin-bff
 * owns the {@code account} table's data (and now its {@code localpart} column)
 * end-to-end; user-bff only ever reads it back over {@code /bff/internal/**}.
 *
 * <p>Spring Data R2DBC is completely fine with two entities mapping DIFFERENT column
 * subsets of the SAME physical table: {@link AccountLocalpartRepository} only ever
 * reads/writes the {@code localpart} column here, and NEVER touches (or even knows
 * about) the columns {@code AccountRowRepository} (auth-core) owns — {@code provider},
 * {@code handle}, {@code registration_complete}, {@code roles}, {@code updated_at}.
 *
 * <p>{@code mastodonLocalpart} (changeset 291) is the coarser Mastodon/Akkoma fold
 * ({@code [a-z0-9_]}, 30-cap) layered on top of {@code localpart} — its OWN {@code
 * UNIQUE} constraint, so the Mastodon mint can never collapse two distinct accounts
 * onto one homeserver identity (the residual half of the account-takeover-by-collision
 * fix; see {@link AccountLocalpartService}).
 *
 * @see AccountLocalpartService the single chokepoint that resolves + persists both
 *      localpart columns at every account-creation call site
 */
@Table("account")
public record AccountLocalpartRow(@Id @Column("id") String id, @Column("localpart") String localpart,
                                  @Column("mastodon_localpart") String mastodonLocalpart) {
}
