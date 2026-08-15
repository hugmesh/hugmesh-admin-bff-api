package net.hugmesh.adminbff.desktop;

import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;
import net.hugmesh.authcore.casdoor.CasdoorAdminClient;
import net.hugmesh.authcore.provision.GatewayRevocationClient;

/**
 * The REAL {@link DesktopSudoClaimSync}: mirrors the {@code OidcFirstLoginController} Casdoor
 * write idiom (the shared auth-core {@link CasdoorAdminClient}, {@code @Nullable} — absent
 * unless {@code casdoor.admin.enabled=true}, in which case this leg is a logged DRY-RUN and
 * the row honestly stays {@code pending}).
 *
 * <h3>Desired membership = "any active grant"</h3>
 * The seeded Casdoor role ({@value #CASDOOR_ROLE}, generator casdoor-init) is PER-SUBJECT,
 * not per-device: membership mints the {@code desktop-sudo} roles-claim on EVERY token for
 * that subject. The per-device boundary is the entitlement read
 * ({@code /bff/internal/desktop/sudo/entitlement}), which the IdP/desktop consults per
 * (subject, device). So an ACTIVE grant ADDs the subject
 * ({@link CasdoorAdminClient#addUserToRole} — idempotent, Casdoor dedups members) and a
 * REVOKED grant REMOVEs the subject ONLY when no other active grant remains for them
 * (removing while another device's grant is live would strip that device's claim too).
 *
 * <h3>Stale-session leg (parity with AdminController role grant/revoke)</h3>
 * After a successful membership write this posts a best-effort {@code subject:<subject>}
 * gateway revocation ({@link GatewayRevocationClient#revokeSubject}, itself gated on
 * {@code broker.gateway-revocation.enabled} and error-swallowing) so a live custody JWT is
 * re-minted with the NEW role set instead of riding out its natural TTL (~1 h) — the SAME
 * treatment {@code AdminController.grantRole}/{@code revokeRole} give every direct role
 * change. The kept-membership branch skips it (nothing about the token changed). There is
 * deliberately NO desktop session-kill: see the {@link DesktopSudoGrantService} javadoc for
 * the platform's honest refresh-time revocation model.
 *
 * <p>Failure of the Casdoor write yields {@code failed} (never an error) — the
 * {@link DesktopSudoClaimReconciler} sweep retries it. Fail-safe by direction: a failed ADD
 * under-grants (no claim yet), a failed REMOVE leaves the row {@code failed} + the retry
 * loop converging, with the entitlement read already denying the device.
 */
public class CasdoorDesktopSudoClaimSync implements DesktopSudoClaimSync {

    private static final Logger log = LoggerFactory.getLogger(CasdoorDesktopSudoClaimSync.class);

    /** The generator-seeded Casdoor role (casdoor-init: {@code name: "desktop-sudo"}) whose
     *  membership carries the desktop-sudo claim. NOT {@code ROLE_}-prefixed — the seed name
     *  is the wire name, exactly as {@code AdminController.grantRole} passes seeded names. */
    public static final String CASDOOR_ROLE = "desktop-sudo";

    /** TTL for the subject revocation key — ≥ the custody JWT lifetime (default 3 600 s),
     *  the same value AdminController's role grant/revoke uses. */
    private static final long SUBJECT_REVOKE_TTL_SECONDS = 3_600L;

    @Nullable
    private final CasdoorAdminClient casdoor;
    private final DesktopSudoGrantRepository repo;
    private final GatewayRevocationClient revocations;

    public CasdoorDesktopSudoClaimSync(@Nullable CasdoorAdminClient casdoor,
                                       DesktopSudoGrantRepository repo,
                                       GatewayRevocationClient revocations) {
        this.casdoor = casdoor;
        this.repo = repo;
        this.revocations = revocations;
    }

    @Override
    public Mono<String> propagate(DesktopSudoGrant grant) {
        // DRY-RUN: Casdoor admin disabled (the dark default) — log what WOULD be written and
        // leave the row honestly pending (the OidcFirstLoginController idiom).
        if (casdoor == null) {
            log.info("[desktop-sudo-claim] DRY-RUN (casdoor.admin disabled) — would sync "
                            + "desktop-sudo role for subject={} (grant id={} state={})",
                    grant.subject(), grant.id(), grant.state());
            return Mono.just(DesktopSudoGrant.PROP_PENDING);
        }
        if (grant.isActive()) {
            return casdoor.addUserToRole(CASDOOR_ROLE, memberIdOf(grant.subject()))
                    .then(revocations.revokeSubject(grant.subject(), "desktop-sudo-grant",
                            SUBJECT_REVOKE_TTL_SECONDS))
                    .doOnSuccess(v -> log.info("[desktop-sudo-claim] ADDED {} to Casdoor role {} "
                            + "(grant id={})", grant.subject(), CASDOOR_ROLE, grant.id()))
                    .thenReturn(DesktopSudoGrant.PROP_APPLIED)
                    .onErrorResume(e -> failed(grant, "add", e));
        }
        return repo.hasActiveForSubject(grant.subject())
                .flatMap(stillEntitled -> stillEntitled
                        ? keepMembership(grant)
                        : removeMembership(grant))
                .onErrorResume(e -> failed(grant, "remove", e));
    }

    /** The subject still holds another ACTIVE grant — the role membership stays (removing it
     *  would strip the OTHER device's claim); THIS row's revocation is fully propagated
     *  because the per-device entitlement read already denies this device. */
    private Mono<String> keepMembership(DesktopSudoGrant grant) {
        log.info("[desktop-sudo-claim] subject={} keeps Casdoor role {} (other active grant "
                + "remains); revoked grant id={} applied", grant.subject(), CASDOOR_ROLE, grant.id());
        return Mono.just(DesktopSudoGrant.PROP_APPLIED);
    }

    /** No active grant remains for the subject — drop the role membership + best-effort
     *  invalidate the live custody JWT so the stale role cannot ride out its TTL. */
    private Mono<String> removeMembership(DesktopSudoGrant grant) {
        return casdoor.removeUserFromRole(CASDOOR_ROLE, memberIdOf(grant.subject()))
                .then(revocations.revokeSubject(grant.subject(), "desktop-sudo-revoke",
                        SUBJECT_REVOKE_TTL_SECONDS))
                .doOnSuccess(v -> log.info("[desktop-sudo-claim] REMOVED {} from Casdoor role {} "
                        + "(grant id={})", grant.subject(), CASDOOR_ROLE, grant.id()))
                .thenReturn(DesktopSudoGrant.PROP_APPLIED);
    }

    private Mono<String> failed(DesktopSudoGrant grant, String op, Throwable e) {
        log.warn("[desktop-sudo-claim] Casdoor {} for subject={} (grant id={}) FAILED "
                        + "(worker retries): {}", op, grant.subject(), grant.id(), e.toString());
        return Mono.just(DesktopSudoGrant.PROP_FAILED);
    }

    /** The Casdoor member id ({@code org/subject}) for a grant subject. A subject already in
     *  {@code org/username} form passes through (the AbstractAccessSyncAction#userIdFor
     *  guard); otherwise the stored Casdoor subject is prefixed with the client's
     *  organization, exactly as OidcFirstLoginController builds its userRef. */
    private String memberIdOf(String subject) {
        if (subject.contains("/")) return subject;
        return casdoor.organization() + "/" + subject;
    }

    @Override
    public boolean isReal() {
        return true;
    }
}
