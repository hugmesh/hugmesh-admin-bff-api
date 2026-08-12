package net.hugmesh.adminbff.cloudbackup;

import io.swagger.v3.oas.annotations.Operation;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.web.ApiException;

import java.util.Map;

/**
 * SUPERADMIN-only ON-DEMAND trigger for the catalog-write status sweep at
 * {@code POST /bff/superadmin/cloud-backups/sweep} — runs ONE {@link BackupStatusReconciler}
 * pass immediately (instead of waiting for the scheduled tick) and returns the number of backup
 * sets flipped terminal. Useful right after a backup completes, or for an operator verifying the
 * loop.
 *
 * <h3>SHIPS DARK (gated on the SAME flag as the reconciler)</h3>
 * {@code @ConditionalOnProperty(app.backups.effector.enabled=true)}: with the flag OFF (the
 * default) this controller bean is ABSENT — the {@link BackupStatusReconciler} it depends on does
 * not exist either — so the route is simply not mapped (404). It is the SAME gate that keeps the
 * scheduler dark, so the manual and scheduled triggers dark/light together.
 *
 * <h3>Authorization (fail-closed, mirrors {@link BackupSuperadminController})</h3>
 * <ol>
 *   <li>the {@code /bff/superadmin/**} coarse path gate ({@code hasRole('SUPERADMIN')}) — an ADMIN
 *       never even reaches this controller;</li>
 *   <li>the per-method {@code @PreAuthorize("hasRole('SUPERADMIN')")} (ADMIN/MOD/USER -> 403,
 *       unauthenticated -> 401).</li>
 * </ol>
 * The sweep is a cross-domain control-plane operation (it reconciles EVERY brand's sets from the
 * cluster's Velero CRs), so it is restricted to the cross-domain super-role — the same reasoning as
 * the TOTAL-cloud backup surface. The sweep itself carries NO domain scope: it only reads CR status
 * and writes the matching catalog rows via the sole-writer repository.
 *
 * <h3>Error surfacing (distinct from the scheduled loop)</h3>
 * The on-demand path calls {@link BackupStatusReconciler#sweepNow()} (NOT {@code runOnce()}): a
 * successful pass returns {@code 200 {"reconciled":<n>}} ({@code 0} legitimately meaning "nothing to
 * do"), while a cluster-read failure PROPAGATES and is mapped to {@code 503}. This lets an operator
 * tell "nothing to reconcile" apart from "the cluster was unreachable" — the scheduled loop
 * deliberately keeps swallowing+retrying that same failure and is unaffected.
 */
@RestController
@RequestMapping("/bff/superadmin/cloud-backups")
@ConditionalOnProperty(name = "app.backups.effector.enabled", havingValue = "true")
public class BackupSweepController {

    private final BackupStatusReconciler reconciler;

    public BackupSweepController(BackupStatusReconciler reconciler) {
        this.reconciler = reconciler;
    }

    /** Run one status-sweep pass now — SUPERADMIN-only. On success returns
     *  {@code 200 {"reconciled": <n>}} where {@code n} is the number of sets flipped terminal by this
     *  pass ({@code 0} legitimately meaning "nothing to do"). Unlike the scheduled loop (which
     *  swallows+retries), the on-demand path uses {@link BackupStatusReconciler#sweepNow()} so a
     *  cluster-read failure PROPAGATES and is surfaced as {@code 503} — letting the operator
     *  distinguish "nothing to do" from "the cluster was unreachable" rather than always seeing
     *  {@code reconciled:0}. */
    @PreAuthorize("hasRole('SUPERADMIN')")
    @Operation(summary = "Sweep", operationId = "backupSweepSweep")
    @PostMapping("/sweep")
    public Mono<ResponseEntity<Map<String, Long>>> sweep() {
        return reconciler.sweepNow()
                .map(n -> ResponseEntity.ok(Map.of("reconciled", n)))
                .onErrorMap(e -> !(e instanceof ApiException),
                        e -> ApiException.serviceUnavailable(
                                "cloud-backup sweep failed: the cluster could not be reached"));
    }
}
