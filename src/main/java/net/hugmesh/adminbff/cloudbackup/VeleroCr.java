package net.hugmesh.adminbff.cloudbackup;

import java.util.Locale;
import java.util.Set;

/**
 * A PURE, fabric8-free projection of ONE Velero ({@code velero.io/v1}) {@code Backup} or
 * {@code Restore} custom resource — just the fields the status sweep needs: the CR name/kind, its
 * terminal {@code .status.phase} (or the generator's mirrored annotation), and the two identifiers
 * the effector stamped so the CR can be correlated back to its {@code backup_set} row.
 *
 * <p>Separating this projection from the fabric8 read (see {@link VeleroStatusReader} /
 * {@code Fabric8VeleroStatusReader}) is the SAME split the effector leg uses between the pure
 * {@code VeleroResourceFactory} and the cluster-applying {@code VeleroBackupEffector}: the CR→set
 * MAPPING + the terminal-phase classification + the idempotent status decision are unit-testable
 * WITHOUT a cluster (the reader just hands the reconciler whatever it projected).
 *
 * <h3>CR → backup_set identity (the reliable mapping)</h3>
 * The effector ({@code VeleroResourceFactory.cr}) stamps the set identity onto every CR it builds:
 * <ul>
 *   <li>label {@code hugmesh.net/backup-set-id} = {@code PerServiceIdentity.slug(set.id())};
 *       a {@code backup_set} id is an app-generated UUID, which is already
 *       lowercase-hex-with-single-hyphens — the DNS/label-safe charset — so {@code slug(uuid)}
 *       equals the raw UUID byte-for-byte (proven in the reconciler test). The label is therefore a
 *       RELIABLE, round-trippable key, NOT a lossy slug, FOR THIS SCHEMA.</li>
 *   <li>annotation {@code hugmesh.net/backup-set-id} = the RAW set id (annotations are not
 *       charset-restricted). The sweep PREFERS this so the mapping stays correct even if the id
 *       scheme ever changes to one the slug would mangle. The effector leg (#76) currently stamps
 *       only the label; until it also stamps this annotation, {@link #setId()} falls back to the
 *       label value (which is lossless today). Adding the annotation in the effector is the tiny,
 *       optional follow-on documented in this leg's PR body.</li>
 * </ul>
 * {@link #setId()} returns the annotation when present, else the label — the single reliable key the
 * reconciler resolves via {@code BackupSetRepository.findById}.
 */
public record VeleroCr(String kind, String name, String phase, String setIdAnnotation,
                       String setIdLabel) {

    /** The metadata annotation carrying the RAW backup_set id (preferred mapping key). */
    public static final String SET_ID_ANNOTATION = "hugmesh.net/backup-set-id";
    /** The metadata label carrying {@code slug(backup_set id)} (the effector's current stamp;
     *  lossless for the UUID id schema, the fallback mapping key). */
    public static final String SET_ID_LABEL = "hugmesh.net/backup-set-id";

    /** Velero terminal {@code .status.phase} values — the worker is DONE reconciling the CR and
     *  the outcome will not change, so the catalog row may be flipped off {@code running}. Lower-
     *  cased for case-insensitive matching. */
    private static final Set<String> TERMINAL_PHASES = Set.of(
            "completed", "partiallyfailed", "failed", "failedvalidation");
    /** Terminal phases that map to a SUCCESS catalog status. {@code PartiallyFailed} is treated as
     *  success-with-warnings (Velero captured most of the backup) so the row is not surfaced as a
     *  hard failure; only outright {@code Failed}/{@code FailedValidation} are failures. */
    private static final Set<String> SUCCESS_PHASES = Set.of("completed", "partiallyfailed");

    /** The reliable CR→set key: the RAW-id annotation when stamped, else the (lossless-for-UUID)
     *  label slug. {@code null}/blank when the CR carries neither — such a CR is UNMAPPABLE and the
     *  reconciler skips it (logged, never crashes). */
    public String setId() {
        if (setIdAnnotation != null && !setIdAnnotation.isBlank()) {
            return setIdAnnotation.trim();
        }
        if (setIdLabel != null && !setIdLabel.isBlank()) {
            return setIdLabel.trim();
        }
        return null;
    }

    /** True iff the CR is in a Velero TERMINAL phase (the worker is finished). A null/blank or
     *  in-flight phase ({@code New}/{@code InProgress}/{@code Deleting}/...) is NON-terminal — the
     *  sweep leaves the set {@code running} and revisits next tick. */
    public boolean isTerminal() {
        return phase != null && TERMINAL_PHASES.contains(phase.trim().toLowerCase(Locale.ROOT));
    }

    /** The catalog status this terminal CR maps to ({@code complete} / {@code failed}). Only
     *  meaningful when {@link #isTerminal()}. */
    public String catalogStatus() {
        if (phase != null && SUCCESS_PHASES.contains(phase.trim().toLowerCase(Locale.ROOT))) {
            return BackupSet.STATUS_COMPLETE;
        }
        return BackupSet.STATUS_FAILED;
    }
}
