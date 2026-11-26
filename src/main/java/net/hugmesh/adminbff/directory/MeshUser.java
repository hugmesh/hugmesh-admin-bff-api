package net.hugmesh.adminbff.directory;

/**
 * One row of the MESH USER directory a signed-in member's pickers (start a chat, invite to a room
 * or a game) autofill from — {@code GET /bff/user/directory/search} in user-bff, served by
 * {@code /bff/internal/directory/search} here.
 *
 * <p>Deliberately NOT {@link DirectoryUser}: that one is the admin console's row and carries the
 * invite {@code handle}, which is an e-mail address. A member's picker must never be able to read
 * another member's e-mail, so this record has exactly the fields a person is addressed by on the
 * mesh and nothing that identifies them outside it.
 *
 * @param username the Casdoor username (what the platform's own surfaces key on)
 * @param matrixLocalpart the Matrix localpart, i.e. the {@code name} of {@code @name:server}; null
 *                        for an account that has not been given one yet
 * @param domain the brand/domain the account belongs to
 */
public record MeshUser(String username, String matrixLocalpart, String domain) {
}
