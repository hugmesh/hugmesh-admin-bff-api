package net.hugmesh.adminbff.web.dto;

import com.fasterxml.jackson.databind.JsonNode;
import org.jspecify.annotations.Nullable;

import java.util.ArrayList;
import java.util.List;

/**
 * The mesh-manifest SEED the batch assembles for the Casdoor seeder / KEYS MagicDNS channel —
 * the admin-bff twin of the generator {@code worklist_driver.manifest_v2()} wire format
 * ({@code hugmesh-mesh-manifest.json}). SERVER-authoritative: {@code brand} / {@code org} /
 * {@code superdomain} / {@code clusterDomain} are derived from the caller's validated issuer +
 * config (NEVER client-picked); {@code domains} / {@code users} ride the worklist {@code base}
 * as CONTENT (and MUST have passed the own-domain wall on {@code domains[].name} and
 * {@code users[].domain} before assembly), {@code images} come from the batch entries.
 *
 * <p>DELIVERY is structural/deferred: the real Casdoor seed consumption of this manifest
 * (over mTLS / a per-batch ConfigMap) needs live Casdoor. The ASSEMBLY (this factory) + the
 * own-domain wall are fully unit-verifiable.
 */
public record MeshManifest(
        int format,
        String brand,
        String brandTitle,
        String org,
        String clusterDomain,
        String superdomain,
        List<Domain> domains,
        List<User> users,
        List<Image> images) {

    /** The wire format version the generator emits ({@code manifest_v2}). */
    public static final int FORMAT_V2 = 2;

    public record Domain(String name, String title, List<String> optionalServices, List<String> images) { }

    public record User(String username, String domain, String role, String email) { }

    public record Image(String id, String role, String platform, String board, String flavor,
                        String encryptRoot) { }

    /**
     * Assemble the seed from the validated worklist {@code base} (CONTENT: domains + users) and
     * the batch {@code entries} (images), stamping the SERVER-derived brand/org/superdomain/
     * cluster-domain. Defensive throughout — a missing/oddly-typed CONTENT field yields an empty
     * string rather than throwing (the envelope validator already fenced the security-relevant
     * shapes upstream).
     */
    public static MeshManifest from(@Nullable JsonNode base, List<BatchImageSpec> entries,
                                    String brand, String brandTitle, String org,
                                    String clusterDomain, String superdomain) {
        List<Domain> domains = new ArrayList<>();
        List<User> users = new ArrayList<>();
        if (base != null) {
            JsonNode ds = base.get("domains");
            if (ds != null && ds.isArray()) {
                for (JsonNode d : ds) {
                    domains.add(new Domain(
                            text(d, "name"),
                            text(d, "title"),
                            stringArray(d.get("optional_services")),
                            stringArray(d.get("images"))));
                }
            }
            JsonNode us = base.get("users");
            if (us != null && us.isArray()) {
                for (JsonNode u : us) {
                    users.add(new User(
                            text(u, "username"),
                            text(u, "domain"),
                            text(u, "role"),
                            text(u, "email")));
                }
            }
        }
        List<Image> images = new ArrayList<>();
        if (entries != null) {
            for (BatchImageSpec e : entries) {
                JsonNode spec = e.imageSpec();
                String platform = e.hardwareClass();
                String role = spec != null && spec.hasNonNull("role")
                        ? spec.get("role").asText() : e.imageType();
                images.add(new Image(
                        role + "." + platform,
                        role,
                        platform,
                        spec == null ? "" : text(spec, "board"),
                        spec == null ? "" : text(spec, "flavor"),
                        spec == null ? "" : text(spec, "encrypt_root")));
            }
        }
        return new MeshManifest(FORMAT_V2, brand, brandTitle, org, clusterDomain, superdomain,
                List.copyOf(domains), List.copyOf(users), List.copyOf(images));
    }

    private static String text(@Nullable JsonNode n, String field) {
        if (n == null) return "";
        JsonNode v = n.get(field);
        return v == null || v.isNull() ? "" : v.asText("");
    }

    private static List<String> stringArray(@Nullable JsonNode n) {
        List<String> out = new ArrayList<>();
        if (n != null && n.isArray()) {
            for (JsonNode e : n) {
                if (e != null && !e.isNull()) out.add(e.asText(""));
            }
        }
        return List.copyOf(out);
    }
}
