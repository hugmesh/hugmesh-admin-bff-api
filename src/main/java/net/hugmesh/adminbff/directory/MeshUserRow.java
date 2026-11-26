package net.hugmesh.adminbff.directory;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

/**
 * Narrow read projection over the SAME {@code account} table auth-core and the localpart/issuer
 * projections already map. Only the columns a member-facing directory may show: the Casdoor
 * username, the Matrix localpart and the issuer (to resolve the domain). Never the invite handle
 * (an e-mail address).
 */
@Table("account")
public record MeshUserRow(@Id @Column("id") String id,
                          @Column("casdoor_username") String casdoorUsername,
                          @Column("localpart") String localpart,
                          @Column("account_issuer") String accountIssuer) {
}
