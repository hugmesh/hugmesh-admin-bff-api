package net.hugmesh.adminbff.notification;

import io.swagger.v3.oas.annotations.Operation;

import jakarta.validation.Valid;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.PrincipalDomain;
import net.hugmesh.adminbff.web.dto.AnnouncementSuppressionRequest;

import java.util.Map;

/**
 * ADMIN|SUPERADMIN-gated toggle for the per-domain {@code @system} BROADCAST
 * kill-switch ({@code announcement_suppressed}, changeset 062). The flag lets a domain
 * admin silence the {@code @system} broadcast channel for their own brand WITHOUT
 * touching individual announcements.
 *
 * <p>Admin gating is DEFENCE IN DEPTH, identical to
 * {@link net.hugmesh.adminbff.AdminController} and
 * {@link net.hugmesh.adminbff.announcement.AnnouncementAdminController}: the
 * gateway denies {@code /bff/admin/**} to non-admins, the resource-server filter
 * re-applies {@code hasRole('ADMIN')} on the path, AND
 * {@code @PreAuthorize("hasRole('ADMIN')")} re-checks at the method (a non-admin
 * therefore gets 403). SUPERADMIN holds ADMIN here too (the role hierarchy maps
 * superadmin → admin), so both may toggle.
 *
 * <p>DOMAIN SCOPING: the acting principal's domain is resolved ONCE from the validated
 * JWT issuer via {@link PrincipalDomain} — never user-settable. A scoped admin only ever
 * reads/writes THEIR OWN brand's flag; SUPERADMIN carries a home domain for the row it
 * writes. The flag row's natural key is the domain.
 *
 * <p>SHIPS DARK: this PR does NOT make the notifications subsystem (or
 * {@code AnnouncementService}) consult the flag yet — only this endpoint reads/writes
 * it. The broadcast channel will honour it in a later PR.
 */
@RestController
@RequestMapping("/bff/admin/announcements/suppression")
@Validated
public class AnnouncementSuppressionController {

    private final AnnouncementSuppressionRepository repo;
    private final DomainRegistry domainRegistry;

    public AnnouncementSuppressionController(AnnouncementSuppressionRepository repo,
                                             DomainRegistry domainRegistry) {
        this.repo = repo;
        this.domainRegistry = domainRegistry;
    }

    /** The current suppression flag for the acting principal's domain. */
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Get", operationId = "announcementSuppressionGet")
    @GetMapping
    public Mono<Map<String, Object>> get(Authentication auth) {
        String domain = scope(auth).domain();
        return repo.isSuppressed(domain)
                .map(suppressed -> Map.of("domain", domain, "suppressed", suppressed));
    }

    /** Toggle the suppression flag for the acting principal's domain. */
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Put", operationId = "announcementSuppressionPut")
    @PutMapping
    public Mono<Map<String, Object>> put(@Valid @RequestBody AnnouncementSuppressionRequest body,
                                         Authentication auth) {
        String domain = scope(auth).domain();
        return repo.setSuppressed(domain, Boolean.TRUE.equals(body.suppressed()), actor(auth))
                .map(suppressed -> Map.of("domain", domain, "suppressed", suppressed));
    }

    private PrincipalDomain scope(Authentication auth) {
        return PrincipalDomain.of(auth, domainRegistry);
    }

    private static String actor(Authentication auth) {
        return auth == null ? "admin" : auth.getName();
    }
}
