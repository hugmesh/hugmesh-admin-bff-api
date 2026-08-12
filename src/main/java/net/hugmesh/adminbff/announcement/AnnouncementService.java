package net.hugmesh.adminbff.announcement;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.security.PrincipalDomain;
import net.hugmesh.commons.web.ApiException;
import net.hugmesh.adminbff.web.dto.AnnouncementRequest;

import java.time.Instant;

/**
 * Announcement application service (reactive). Owns the rules the controller must
 * not duplicate:
 * <ul>
 *   <li>SERVER-SIDE SANITISE of {@code body_html} on every create/update (jsoup
 *       Safelist via {@link AnnouncementSanitizer}) — the stored body is never raw
 *       admin HTML;</li>
 *   <li>cross-field validation: at-least-one target flag, and a valid window
 *       ({@code starts_at < ends_at}) → 400;</li>
 *   <li>akkoma propagation: when a {@code target_akkoma} announcement becomes
 *       PUBLISHED, create a LOCAL-ONLY akkoma announcement (via the SAFE GATED
 *       {@link AnnouncementMastodonClient} stub-seam) and persist its
 *       {@code akkoma_ref}; on unpublish/archive/expire/delete REMOVE it. Best-
 *       effort — a akkoma failure NEVER fails the admin write;</li>
 *   <li>a {@link #reconcileAkkoma() @Scheduled} sweep that removes akkoma posts for
 *       expired/unpublished/de-targeted announcements (idempotent).</li>
 * </ul>
 *
 * <p>The active-surface reads ({@link #activeForHome}/{@link #activeForLogin}/
 * {@link #activeForForum}) are thin pass-throughs to the repository's window query.
 *
 * <p>DOMAIN SCOPING (multi-tenancy P1 fix — changeset 061): every admin read/write
 * operation accepts a {@link PrincipalDomain} resolved from the caller's JWT. A scoped
 * admin sees and mutates only their own brand's announcements; SUPERADMIN is
 * unscoped. The domain is stamped on every new row at create time from the scope's
 * {@link PrincipalDomain#domain()} — never a user-settable value. The active-surface
 * endpoints remain unscoped (the login feed is public/unauthenticated).
 */
@Service
public class AnnouncementService {

    private static final Logger log = LoggerFactory.getLogger(AnnouncementService.class);

    private final AnnouncementRepository repo;
    private final AnnouncementSanitizer sanitizer;
    private final AnnouncementMastodonClient akkoma;

    public AnnouncementService(AnnouncementRepository repo, AnnouncementSanitizer sanitizer,
                               AnnouncementMastodonClient akkoma) {
        this.repo = repo;
        this.sanitizer = sanitizer;
        this.akkoma = akkoma;
    }

    // ── Reads ───────────────────────────────────────────────────────────
    /**
     * All announcements VISIBLE to the acting tenant scope. A scoped admin sees only
     * their brand's rows; SUPERADMIN sees all. Fail-closed: a null scope collapses to
     * the {@link PrincipalDomain#NO_DOMAIN} sentinel (matches nothing).
     */
    public Flux<Announcement> list(PrincipalDomain scope) {
        return repo.list(scope);
    }

    /**
     * One announcement by id, scoped to the acting tenant. A scoped admin cannot
     * resolve another brand's announcement — it is invisible (→ 404) rather than a
     * data-leaking response. SUPERADMIN resolves any id.
     */
    public Mono<Announcement> get(String id, PrincipalDomain scope) {
        return parseId(id).flatMap(uuid -> repo.find(id, scope))
                .switchIfEmpty(Mono.error(notFound(id)));
    }

    public Flux<Announcement> activeForHome() {
        return repo.activeForHome(Instant.now());
    }

    public Flux<Announcement> activeForLogin() {
        return repo.activeForLogin(Instant.now());
    }

    public Flux<Announcement> activeForForum() {
        return repo.activeForForum(Instant.now());
    }

    // ── Create ──────────────────────────────────────────────────────────
    /**
     * Create a new announcement, stamping the acting principal's domain on the row so
     * only their brand sees it. The domain is derived from the cryptographically-
     * validated JWT issuer via {@link PrincipalDomain} — never a user-settable value.
     */
    public Mono<Announcement> create(AnnouncementRequest req, String createdBy, PrincipalDomain scope) {
        return validated(req).flatMap(v -> {
            Announcement toInsert = toEntity(null, req, createdBy, null, scope);
            return repo.insert(toInsert)
                    // A brand-new announcement created already-published + akkoma-
                    // targeted must propagate immediately.
                    .flatMap(saved -> propagateAkkomaForState(null, saved));
        });
    }

    // ── Update ──────────────────────────────────────────────────────────
    /**
     * Update an existing announcement. A scoped admin can only update their own
     * brand's announcements; another brand's id resolves to empty → 404 (invisible,
     * not a data-leaking 403). SUPERADMIN may update any id. The domain stamp is
     * preserved from the existing row (UPDATE does not re-stamp domain).
     */
    public Mono<Announcement> update(String id, AnnouncementRequest req, String editor, PrincipalDomain scope) {
        return parseId(id)
                .flatMap(uuid -> repo.find(id, scope).switchIfEmpty(Mono.error(notFound(id))))
                .flatMap(existing -> validated(req).flatMap(v -> {
                    // Preserve created_by + the current akkoma_ref across the edit; the
                    // ref is then reconciled by propagateAkkomaForState below.
                    Announcement toUpdate = toEntity(id, req, existing.createdBy(), existing.akkomaRef(), scope);
                    return repo.update(id, toUpdate)
                            .flatMap(saved -> propagateAkkomaForState(existing, saved));
                }));
    }

    // ── Delete ──────────────────────────────────────────────────────────
    /**
     * Delete an announcement. A scoped admin can only delete their own brand's
     * announcements — another brand's id resolves to empty → 404 (invisible). SUPERADMIN
     * deletes any id. The akkoma post (if present) is removed first (best-effort).
     */
    public Mono<Void> delete(String id, PrincipalDomain scope) {
        return parseId(id)
                .flatMap(uuid -> repo.find(id, scope).switchIfEmpty(Mono.error(notFound(id))))
                // Remove any live akkoma post first (best-effort), then drop the row.
                .flatMap(existing -> removeAkkomaIfPresent(existing).thenReturn(existing))
                .flatMap(existing -> repo.delete(id, scope));
    }

    /**
     * Reconcile akkoma posts for announcements that should no longer have one
     * (expired window, unpublished, archived, or akkoma flag cleared) but still
     * carry an {@code akkoma_ref}. Idempotent: removing an already-removed post is a
     * no-op OK (client-side 404 swallow) and the ref is cleared; a STUBBED/degraded
     * outcome keeps the ref so the next sweep retries (never orphan on an unconfirmed
     * removal). Runs on a fixed delay; best-effort so an akkoma outage never throws
     * out of the scheduler.
     */
    @Scheduled(fixedDelayString = "${announcement.akkoma.reconcile-interval-ms:300000}",
            initialDelayString = "${announcement.akkoma.reconcile-initial-delay-ms:60000}")
    public void reconcileAkkoma() {
        reconcileAkkomaReactive()
                .doOnError(e -> log.warn("[akkoma] reconcile sweep failed: {}", e.toString()))
                .onErrorResume(e -> Mono.empty())
                .subscribe();
    }

    /** The testable reactive body of the scheduled sweep. */
    Mono<Void> reconcileAkkomaReactive() {
        Instant now = Instant.now();
        return repo.expiredWithAkkomaRef(now)
                .flatMap(stale -> akkoma.removeAnnouncement(stale.akkomaRef())
                        .flatMap(outcome -> {
                            if (!outcome.isOk()) {
                                // Unconfirmed removal (stubbed/degraded) — keep the ref;
                                // the next sweep retries.
                                log.warn("[akkoma] reconcile remove for {} not confirmed ({}); "
                                        + "keeping akkoma_ref", stale.id(), outcome.result());
                                return Mono.empty();
                            }
                            return repo.setAkkomaRef(stale.id(), null);
                        })
                        .onErrorResume(e -> {
                            log.warn("[akkoma] reconcile remove for {} failed (will retry): {}",
                                    stale.id(), e.toString());
                            return Mono.empty();
                        }))
                .then();
    }

    // ── akkoma propagation helpers ──────────────────────────────────────
    /**
     * Reconcile the akkoma post for a single announcement after a create/update,
     * based on its NEW state vs its PREVIOUS state. Always returns the (possibly
     * akkoma_ref-updated) row; akkoma failures are swallowed (best-effort).
     */
    @SuppressWarnings("PMD.UnusedFormalParameter")
    private Mono<Announcement> propagateAkkomaForState(Announcement previous, Announcement saved) {
        boolean shouldHave = isAkkomaLive(saved);
        boolean hadRef = saved.akkomaRef() != null && !saved.akkomaRef().isBlank();

        if (shouldHave && !hadRef) {
            // Newly published+akkoma-targeted → create the local-only post.
            return akkoma.createLocalAnnouncement(saved)
                    .flatMap(outcome -> {
                        if (outcome.isOk() && outcome.ref() != null) {
                            return repo.setAkkomaRef(saved.id(), outcome.ref())
                                    .thenReturn(withAkkomaRef(saved, outcome.ref()));
                        }
                        // STUBBED / degraded — nothing to persist; row stands.
                        log.info("[akkoma] announcement {} publish propagation: {}",
                                saved.id(), outcome.result());
                        return Mono.just(saved);
                    })
                    .onErrorResume(e -> {
                        log.warn("[akkoma] create for {} failed (announcement kept): {}",
                                saved.id(), e.toString());
                        return Mono.just(saved);
                    });
        }
        if (!shouldHave && hadRef) {
            // Unpublished / archived / akkoma-flag-cleared / expired → remove the post.
            // Clear the ref ONLY on a confirmed-OK removal: a STUBBED/degraded outcome
            // (e.g. the live-verified force-HTTPS 308) keeps the ref so the reconcile
            // sweep can retry instead of orphaning the live Akkoma post.
            return akkoma.removeAnnouncement(saved.akkomaRef())
                    .flatMap(outcome -> {
                        if (!outcome.isOk()) {
                            log.warn("[akkoma] remove for {} not confirmed ({}); keeping "
                                    + "akkoma_ref for reconcile", saved.id(), outcome.result());
                            return Mono.just(saved);
                        }
                        return repo.setAkkomaRef(saved.id(), null)
                                .thenReturn(withAkkomaRef(saved, null));
                    })
                    .onErrorResume(e -> {
                        log.warn("[akkoma] remove for {} failed (will reconcile): {}",
                                saved.id(), e.toString());
                        return Mono.just(saved);
                    });
        }
        return Mono.just(saved);
    }

    private Mono<Void> removeAkkomaIfPresent(Announcement a) {
        if (a.akkomaRef() == null || a.akkomaRef().isBlank()) {
            return Mono.empty();
        }
        return akkoma.removeAnnouncement(a.akkomaRef())
                .then()
                .onErrorResume(e -> {
                    log.warn("[akkoma] remove on delete for {} failed: {}", a.id(), e.toString());
                    return Mono.empty();
                });
    }

    /** True when the announcement should currently have a live akkoma post:
     *  published + akkoma-targeted + inside its active window. */
    private static boolean isAkkomaLive(Announcement a) {
        return "published".equals(a.state()) && a.targetAkkoma() && inWindow(a, Instant.now());
    }

    private static boolean inWindow(Announcement a, Instant now) {
        if (a.startsAt() != null && a.startsAt().isAfter(now)) return false;
        if (a.endsAt() != null && !a.endsAt().isAfter(now)) return false;
        return true;
    }

    // ── Validation + mapping ────────────────────────────────────────────
    /**
     * Cross-field validation the bean annotations cannot express: at least one
     * target surface, and a coherent window. Surfaced as a 400 with the same
     * {@code {error,fields}} shape ValidationExceptionHandler produces — here via an
     * {@link ApiException} carrying the per-field message in its body, so the UI
     * still gets a clean 400.
     */
    private Mono<AnnouncementRequest> validated(AnnouncementRequest req) {
        boolean anyTarget = bool(req.targetHome()) || bool(req.targetLogin())
                || bool(req.targetAkkoma()) || bool(req.targetForum());
        if (!anyTarget) {
            return Mono.error(ApiException.badRequest(
                    "at least one target surface (target_home/target_login/target_akkoma/target_forum) is required"));
        }
        if (req.startsAt() != null && req.endsAt() != null
                && !req.endsAt().isAfter(req.startsAt())) {
            return Mono.error(ApiException.badRequest("ends_at must be after starts_at"));
        }
        return Mono.just(req);
    }

    /**
     * Build the entity to persist from the request: sanitise body_html, default the
     * enums/flags, carry forward created_by + akkoma_ref, stamp the domain from the
     * acting principal's {@link PrincipalDomain}. Timestamps are set by the DB DDL
     * (now()) on insert; on update only the editable fields are written (domain is
     * not re-stamped on update — it is preserved from the existing row by the repo).
     */
    private Announcement toEntity(String id, AnnouncementRequest req, String createdBy,
                                  String akkomaRef, PrincipalDomain scope) {
        String format = (req.format() == null || req.format().isBlank()) ? "html" : req.format();
        String state = (req.state() == null || req.state().isBlank()) ? "draft" : req.state();
        String domain = scope == null ? PrincipalDomain.NO_DOMAIN : scope.domain();
        return new Announcement(
                id,
                req.title().trim(),
                sanitizer.sanitize(req.bodyHtml()),
                format,
                state,
                bool(req.targetHome()),
                bool(req.targetLogin()),
                bool(req.targetAkkoma()),
                bool(req.targetForum()),
                req.priority() == null ? 0 : req.priority(),
                req.startsAt(),
                req.endsAt(),
                (req.timezone() == null || req.timezone().isBlank()) ? null : req.timezone(),
                req.dismissible() == null || req.dismissible(),
                createdBy,
                akkomaRef,
                null,
                null,
                domain);
    }

    private static Announcement withAkkomaRef(Announcement a, String ref) {
        return new Announcement(a.id(), a.title(), a.bodyHtml(), a.format(), a.state(),
                a.targetHome(), a.targetLogin(), a.targetAkkoma(), a.targetForum(),
                a.priority(), a.startsAt(), a.endsAt(), a.timezone(), a.dismissible(),
                a.createdBy(), ref, a.createdAt(), a.updatedAt(), a.domain());
    }

    private static boolean bool(Boolean b) {
        return Boolean.TRUE.equals(b);
    }

    private static Mono<java.util.UUID> parseId(String id) {
        try {
            return Mono.just(java.util.UUID.fromString(id));
        } catch (IllegalArgumentException e) {
            return Mono.error(notFound(id));
        }
    }

    private static ApiException notFound(String id) {
        return new ApiException(org.springframework.http.HttpStatus.NOT_FOUND,
                "announcement '" + id + "' not found");
    }
}
