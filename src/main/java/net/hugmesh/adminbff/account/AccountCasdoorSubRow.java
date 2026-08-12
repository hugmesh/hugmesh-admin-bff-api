package net.hugmesh.adminbff.account;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

/**
 * A narrow, admin-bff-LOCAL projection of the shared {@code account} table covering
 * ONLY the {@code id} + {@code casdoor_sub} (Liquibase changeset 292) columns — the
 * A5 part-B cross-carrier route-pin fix.
 *
 * <p>{@code casdoor_sub} is the raw Casdoor {@code sub} UUID, captured at the ONE
 * place the native-login mint path decodes the raw id_token
 * ({@code InternalAccountController#ensureAccount}, {@code provider="casdoor"}) and
 * read back by {@code /bff/internal/session/introspect} as the nullable
 * {@code casdoorSub} field, so the gateway's {@code GatewayRouteAccessFilter} can
 * match a UUID-form {@code casdoor_user} route pin for a bff_ session carrier the
 * same way it already does for a Casdoor-JWT carrier. Null for every row that
 * predates the column or was created off the casdoor mint path (google/discord
 * invite accounts have no Casdoor UUID at this layer) — such rows self-heal on the
 * account's next native login, because {@code ensureAccount} re-runs on every
 * sign-in.
 *
 * <p>Deliberately NOT a field on auth-core's {@code AccountRow}/{@code Account} and
 * deliberately a SEPARATE projection from {@link AccountLocalpartRow}: the same
 * single-repo-concern rationale as that row's class doc (auth-core is a
 * separately-versioned shared dependency; a field there forces a version-bump chain
 * through both consumers), and keeping the sub-stamping surface disjoint from the
 * collision-checked localpart chokepoint means neither concern's reads/writes can
 * regress the other. Spring Data R2DBC is fine with multiple entities mapping
 * different column subsets of the same physical table (see {@link
 * AccountLocalpartRow}); {@link AccountCasdoorSubRepository} only ever touches the
 * one column this projection owns.
 *
 * @see AccountCasdoorSubService the stamp/read chokepoint
 */
@Table("account")
public record AccountCasdoorSubRow(@Id @Column("id") String id,
                                   @Column("casdoor_sub") String casdoorSub) {
}
