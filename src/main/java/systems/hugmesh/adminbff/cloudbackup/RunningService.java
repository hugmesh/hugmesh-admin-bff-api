package systems.hugmesh.adminbff.cloudbackup;

/**
 * One entry in the per-service backup MENU — a running service an admin may select to back
 * up. The {@code key} is the stable service identifier persisted in
 * {@code backup_set.services} / {@code backup_artifact.service}; {@code displayName} is the UI
 * label; {@code defaultKind} is the artifact kind the worker would produce (db_dump for a
 * DB-backed service, pv_snapshot for a volume-backed one, config for a config-only service).
 *
 * <ul>
 *   <li>{@code key} — the stable service key (e.g. {@code postgres}, {@code matrix},
 *       {@code akkoma}).</li>
 *   <li>{@code displayName} — the UI label.</li>
 *   <li>{@code defaultKind} — {@code db_dump} / {@code pv_snapshot} / {@code config}.</li>
 *   <li>{@code optional} — whether this is an OPTIONAL add/remove-by-command service (akkoma /
 *       matrix / phpBB / games / tube / owncast), greyed-out when not installed.</li>
 * </ul>
 */
public record RunningService(
        String key,
        String displayName,
        String defaultKind,
        boolean optional) {
}
