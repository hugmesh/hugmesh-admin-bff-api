package systems.hugmesh.adminbff.cloudbackup;

import reactor.core.publisher.Flux;
import systems.hugmesh.commons.security.PrincipalDomain;

/**
 * Enumerates the RUNNING services available for the per-service backup MENU
 * ({@code GET /bff/admin/cloud-backups/services}). The list is brand-scoped: a domain admin
 * sees the services running in THEIR brand; a superadmin sees the full installed set.
 *
 * <p><b>FOUNDATION-leg seam.</b> The authoritative source is the installed-services ConfigMap
 * the generator writes per brand. By default the bean is {@link StubRunningServiceProvider},
 * which returns the DOCUMENTED installed-services list (the core platform services + the
 * optional add-by-command services) with no live cluster read. The generator (Velero) leg's
 * {@link ConfigMapRunningServiceProvider} replaces the stub behind this same interface,
 * filtering that documented list down to what the caller's brand ConfigMap actually reports —
 * wired and tested, but dark by default behind {@code app.backups.effector.enabled}.
 */
public interface RunningServiceProvider {

    /** The running services selectable for a backup, scoped to the caller's brand. */
    Flux<RunningService> runningServices(PrincipalDomain scope);
}
