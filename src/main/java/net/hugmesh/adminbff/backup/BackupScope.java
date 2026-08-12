package net.hugmesh.adminbff.backup;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * The selectable things an admin can back up / restore. A small, fixed
 * vocabulary (closed enum) so the API and the worker script agree on exactly
 * what each scope means, and so a bad scope name is a clean 400 at the edge
 * rather than a no-op in the worker.
 *
 * <ul>
 *   <li>{@link #ETCD} — a cluster etcd snapshot (control-plane state / cluster
 *       Secrets live here).</li>
 *   <li>{@link #SECRETS} — Kubernetes Secrets (sealed/raw) across namespaces.</li>
 *   <li>{@link #POSTGRES} — the platform Postgres databases (pg_dump).</li>
 *   <li>{@link #PVC} — PersistentVolumeClaim data (rsync of mounted volumes).</li>
 *   <li>{@link #CONFIG} — ConfigMaps / platform config manifests.</li>
 * </ul>
 */
public enum BackupScope {
    ETCD, SECRETS, POSTGRES, PVC, CONFIG;

    /** The wire name (lowercase) the UI + worker use. */
    public String wire() {
        return name().toLowerCase();
    }

    /** Parse a wire name (case-insensitive), or null if it is not a known scope. */
    public static BackupScope from(String s) {
        if (s == null) return null;
        try {
            return BackupScope.valueOf(s.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /** Validate + normalise a requested scope list into the canonical lowercase
     *  comma-joined string persisted in {@code backup_history.scope}. Throws
     *  {@link IllegalArgumentException} (mapped to 400 by the controller) when any
     *  entry is unknown or the list is empty after de-duping. */
    public static String normalise(List<String> requested) {
        if (requested == null || requested.isEmpty()) {
            throw new IllegalArgumentException("at least one scope is required");
        }
        Set<BackupScope> parsed = new LinkedHashSet<>();
        for (String s : requested) {
            BackupScope sc = from(s);
            if (sc == null) {
                throw new IllegalArgumentException("unknown scope '" + s + "'; valid: "
                        + Arrays.stream(values()).map(BackupScope::wire).collect(Collectors.joining(", ")));
            }
            parsed.add(sc);
        }
        return parsed.stream().map(BackupScope::wire).collect(Collectors.joining(","));
    }
}
