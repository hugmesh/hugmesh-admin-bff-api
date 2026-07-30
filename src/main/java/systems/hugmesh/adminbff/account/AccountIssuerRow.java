package systems.hugmesh.adminbff.account;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

/**
 * A narrow, admin-bff-LOCAL projection of the shared {@code account} table covering
 * ONLY the {@code id} + {@code account_issuer} (Liquibase changeset 301) columns — the
 * multi-brand bff_-session domain-scope fix.
 *
 * <p>{@code account_issuer} is the account's OWN Casdoor issuer URI (the brand
 * discriminator — the platform runs one Casdoor per brand), captured at the ONE place
 * the native-login mint path decodes the raw id_token
 * ({@code InternalAccountController#ensureAccount}, {@code provider="casdoor"}) and read
 * back by {@code /bff/internal/session/introspect} as the nullable {@code issuer} field,
 * so user-bff's {@code BffSessionAuthenticationWebFilter#syntheticJwt} can stamp the
 * RIGHT brand's {@code iss} for a bff_ session carrier instead of stamping nothing (and
 * so failing every domain-scoped read/write closed) on a genuinely multi-issuer cluster.
 *
 * <p><b>Only ever a VALIDATED issuer reaches this column.</b> The id_token is decoded
 * WITHOUT signature re-verification and its handle is user-bff-supplied, so
 * {@link AccountIssuerService#stamp} writes the value ONLY when it is a member of the
 * configured, non-empty trusted-issuer set. Null for every row that predates the column,
 * was created off the casdoor mint path (google/discord invite accounts), or whose token
 * carried an issuer this deployment does not trust. Such rows self-heal on the account's
 * next native login (from a trusted issuer), because {@code ensureAccount} re-runs on
 * every sign-in; until then introspect returns null and user-bff degrades to exactly its
 * pre-301 {@code singleTrustedIssuerOrNull} behavior.
 *
 * <p>Deliberately NOT a field on auth-core's {@code AccountRow}/{@code Account} and
 * deliberately a SEPARATE projection from {@link AccountLocalpartRow} / {@link
 * AccountCasdoorSubRow}: the same single-repo-concern rationale as those rows' class docs
 * (auth-core is a separately-versioned shared dependency; a field there forces a
 * version-bump chain through both consumers), and keeping each stamping surface disjoint
 * means no concern's reads/writes can regress another's. Spring Data R2DBC is fine with
 * multiple entities mapping different column subsets of the same physical table; {@link
 * AccountIssuerRepository} only ever touches the one column this projection owns.
 *
 * @see AccountIssuerService the validate/stamp/read chokepoint
 */
@Table("account")
public record AccountIssuerRow(@Id @Column("id") String id,
                               @Column("account_issuer") String accountIssuer) {
}
