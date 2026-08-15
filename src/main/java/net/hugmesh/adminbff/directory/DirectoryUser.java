package net.hugmesh.adminbff.directory;

/**
 * One typeahead row returned by {@code GET /bff/admin/users/search} — the shape an admin
 * console's user picker renders and submits.
 *
 * <p>Three fields, and the distinction between the first two is the whole reason this DTO
 * exists rather than the picker consuming the raw {@code GET /bff/admin/allowlist} string
 * list:
 *
 * <ul>
 *   <li>{@link #username} — the CASDOOR username, derived here by the SAME
 *       {@code CasdoorAdminClient.usernameOf(provider, handle)} the mint path uses. This is
 *       the identifier every write surface actually keys on
 *       ({@code POST /bff/admin/roles/{roleName}/{user}},
 *       {@code POST /bff/admin/access-roles/{role}/{user}},
 *       {@code POST /bff/admin/domain-lock/{role}/{user}}), so the picker submits THIS and
 *       an admin never has to know that {@code alice@example.org} becomes {@code alice}.</li>
 *   <li>{@link #handle} — the invite handle as stored ({@code alice@example.org},
 *       {@code alice#1234}). Shown as the secondary line so two accounts that collapse to
 *       the same Casdoor username stay distinguishable to the human picking.</li>
 *   <li>{@link #provider} — {@code google} | {@code discord}; disambiguates the above and
 *       lets the picker badge the row.</li>
 *   <li>{@link #domain} — the brand the invite row belongs to. Always the caller's own
 *       domain for a scoped ADMIN (the query never returns another brand's rows); a
 *       SUPERADMIN is unscoped and needs this to tell two brands' users apart.</li>
 * </ul>
 */
public record DirectoryUser(
        String username,
        String handle,
        String provider,
        String domain) {
}
