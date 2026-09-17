package net.hugmesh.adminbff.mfa;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.LocalDateTime;

/**
 * One row of {@code role_mfa_policy} (Liquibase changeSet {@code 150-role-mfa-policy}): the
 * per-(domain, role) MFA REQUIREMENT policy the 150 band created "consumed DARK".
 *
 * <p>Column semantics are the changelog's, restated here so the Java side cannot drift from
 * the DDL comments:
 * <ul>
 *   <li>{@code domain} — the validated-issuer-derived tenant discriminator (the 010 pattern;
 *       {@code default} on a single-issuer cluster).</li>
 *   <li>{@code role} — the lowercase Casdoor role name ({@code superadmin} / {@code admin} /
 *       {@code mod} / {@code user} / …).</li>
 *   <li>{@code required} — whether MFA is REQUIRED for the role in the domain.</li>
 *   <li>{@code methods} — CSV of allowed methods ({@code webauthn,otp,recovery});
 *       {@code NULL} = any.</li>
 *   <li>{@code grace_seconds} — re-prompt grace window; {@code 0} = always re-prompt.</li>
 * </ul>
 *
 * <p>{@code created_at} is deliberately NOT mapped: the column carries a {@code now()}
 * DEFAULT and the only write path is the {@link RoleMfaPolicyR2dbcRepository#upsert}
 * {@code @Query}, which omits it. The PK is an app-generated {@code varchar(36)} UUID string
 * (band 210 gave the 151/152 MFA tables a DB-generated default but left this one alone), so
 * the upsert supplies one on INSERT and the {@code (domain, role)} UNIQUE constraint
 * ({@code uq_role_mfa_policy_domain_role}) is what the ON CONFLICT arm converges on.
 */
@Table("role_mfa_policy")
public record RoleMfaPolicyRow(
        @Id @Column("id") String id,
        @Column("domain") String domain,
        @Column("role") String role,
        @Column("required") boolean required,
        @Column("methods") String methods,
        @Column("grace_seconds") long graceSeconds,
        @Column("updated_by") String updatedBy,
        @Column("updated_at") LocalDateTime updatedAt) {
}
