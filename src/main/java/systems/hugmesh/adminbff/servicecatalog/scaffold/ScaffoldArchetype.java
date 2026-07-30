package systems.hugmesh.adminbff.servicecatalog.scaffold;

/**
 * One entry of the embedded SCAFFOLD catalog — an example starter codebase a SUPERADMIN can
 * render for a brand from the Service-Store wizard. The catalog is served by
 * {@code GET /bff/superadmin/service-store/scaffold/archetypes}
 * ({@link ScaffoldService#archetypes()}); a create request names one of these by {@link #name()}.
 *
 * <ul>
 *   <li>{@link #name()} — the stable {@code ^[a-z0-9-]{1,64}$} archetype id (the request
 *       {@code archetype} field is matched against this; it is also the classpath directory
 *       under {@code resources/scaffold/} the renderer reads).</li>
 *   <li>{@link #displayName()} — the human label for the wizard.</li>
 *   <li>{@link #description()} — a one-line summary of what the archetype renders.</li>
 *   <li>{@link #kind()} — the federation nature of the produced service ({@code backend} for a
 *       BFF, {@code remote-shell}/{@code host}/{@code fragment} for a UI), advisory for the
 *       wizard's later federate step.</li>
 * </ul>
 *
 * <p>The four archetypes are vendored from the generator's {@code templates/archetypes/*}
 * skeletons (see {@code resources/scaffold/README.md} for provenance + resync).
 */
public record ScaffoldArchetype(String name, String displayName, String description, String kind) {
}
