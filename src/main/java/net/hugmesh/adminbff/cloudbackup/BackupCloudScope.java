package net.hugmesh.adminbff.cloudbackup;

/**
 * The SCOPE of a cloud backup — a small, fixed vocabulary (closed enum) so the API, the
 * catalog row CHECK, and the role gate agree on exactly what each value means, and so a bad
 * scope name is a clean 400 at the edge rather than a no-op deeper down.
 *
 * <ul>
 *   <li>{@link #DOMAIN} — a per-BRAND backup: a domain admin (or a superadmin acting for the
 *       brand) backs up THEIR OWN brand's selected running services. The row's {@code domain}
 *       is the VALIDATED-ISSUER brand, and a scoped admin reads/writes ONLY their own brand's
 *       rows.</li>
 *   <li>{@link #TOTAL} — the TOTAL-CLOUD backup: every brand's state at once. SUPERADMIN-ONLY
 *       (the infra control plane). The role gate ({@code hasRole('SUPERADMIN')}) is enforced
 *       in the service/controller; an ADMIN requesting a TOTAL backup is a clean 403.</li>
 * </ul>
 *
 * <p>This is DISTINCT from the legacy USB {@code BackupScope} (etcd/secrets/postgres/pvc/
 * config) in the {@code backup} package — that enumerates WHAT a USB backup captures; this
 * enumerates WHOSE cloud is captured (a brand vs the whole cloud).
 */
public enum BackupCloudScope {
    DOMAIN, TOTAL;

    /** The wire name (UPPERCASE, matching the {@code backup_set.scope} CHECK vocabulary). */
    public String wire() {
        return name();
    }

    /** Parse a wire name (case-insensitive), or {@code null} if it is not a known scope. */
    public static BackupCloudScope from(String s) {
        if (s == null) return null;
        try {
            return BackupCloudScope.valueOf(s.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /** True iff this is the SUPERADMIN-only total-cloud scope. */
    public boolean isTotal() {
        return this == TOTAL;
    }
}
