package systems.hugmesh.adminbff.iso;

/** A delivered ISO artifact (name + gateway-internal download URL). The KEYS
 *  material is never part of these images, so nothing secret is exposed. */
public record IsoArtifact(String name, String url) {
}
