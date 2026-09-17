package net.hugmesh.adminbff.mfa;

import net.hugmesh.commons.web.ApiException;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * The {@code role_mfa_policy} CONSUMER the 150 changelog deferred to "a later wave": resolves
 * the effective per-(domain, role) MFA requirement and owns the only write path.
 *
 * <p><b>What this wave does and does not do.</b> This service is a READ MODEL plus an admin
 * write path. Nothing in the request pipeline consults it yet — {@code /bff/login},
 * {@code /bff/session}, {@code /bff/internal/session/introspect} and the step-up gates all
 * behave exactly as before this class existed, and the gateway's route-level
 * {@code mfa_required} enforcement stays behind {@code app.mfa.enabled} in the gateway chart.
 * Wiring {@link #requiredForAny} into those seams is the next numbered slice on
 * hugmesh-admin-bff-api#3 and carries its own flag; landing the resolver first lets an
 * operator SEE and SET the per-role posture (and lets the skeptic pin the floor semantics)
 * before any request is ever denied by it.
 *
 * <p><b>Built-in defaults</b> (the issue's stated per-role defaults — "superadmin/admin
 * required, mod relaxable, user optional"): {@code superadmin=true}, {@code admin=true},
 * {@code mod=false}, {@code user=false}; any role without a row and without an entry here
 * resolves {@code false}.
 *
 * <p><b>The privileged floor is NOT relaxable.</b> {@code superadmin} and {@code admin}
 * resolve {@code required=true} regardless of what a row says (defence in depth against a
 * hand-edited row), and a write that tries to set them {@code required=false} is refused
 * with 400 BEFORE anything is persisted. This mirrors the gateway runbook's posture
 * (docs/MFA-ROLLOUT.md: the privileged floor is "not exempt for SUPERADMIN"). A row for a
 * floor role can still carry {@code methods} / {@code grace_seconds}.
 *
 * <p><b>Fail-closed direction.</b> Every resolver default is the SAFER answer for an
 * unknown: an unknown role is {@code false} (no lockout of a role nobody enrolled), but a
 * floor role is {@code true} even when the table is unreadable for that row (an empty
 * lookup never relaxes it).
 */
@Service
public class RoleMfaPolicyService {

    /** Roles whose {@code required} is pinned {@code true} — never relaxable by a row or a write. */
    public static final Set<String> FLOOR_ROLES = Set.of("superadmin", "admin");

    /** The per-role defaults applied when no row exists (issue #3 body). */
    public static final Map<String, Boolean> DEFAULT_REQUIRED = Map.of(
            "superadmin", true,
            "admin", true,
            "mod", false,
            "user", false);

    /** The canonical roles a listing always reports, even with an empty table. */
    static final List<String> CANONICAL_ROLES = List.of("superadmin", "admin", "mod", "user");

    /** The method vocabulary the 150 changelog documents for the {@code methods} CSV. */
    public static final Set<String> KNOWN_METHODS = Set.of("webauthn", "otp", "recovery");

    /** 30 days — the same ceiling the revocation TTLs use; a grace longer than that is a typo. */
    public static final long MAX_GRACE_SECONDS = 2_592_000L;

    private static final Pattern ROLE_SHAPE = Pattern.compile("[a-z0-9_-]{1,64}");

    private final RoleMfaPolicyR2dbcRepository repo;

    public RoleMfaPolicyService(RoleMfaPolicyR2dbcRepository repo) {
        this.repo = repo;
    }

    // ── resolvers ──────────────────────────────────────────────────────────────────

    /** The effective policy for one (domain, role): the row if present, else the default. */
    public Mono<RoleMfaPolicy> effectiveFor(String domain, String role) {
        String r = normaliseRole(role);
        return repo.findByDomainAndRole(domain, r)
                .map(row -> fromRow(row))
                .defaultIfEmpty(defaultFor(domain, r));
    }

    /**
     * Every effective policy for a domain: the four canonical roles (row or default) plus any
     * further role that has a row, role-ordered with the canonical four first.
     */
    public Flux<RoleMfaPolicy> listEffective(String domain) {
        return repo.findByDomainOrderByRole(domain)
                .collectList()
                .flatMapMany(rows -> {
                    Map<String, RoleMfaPolicy> byRole = new LinkedHashMap<>();
                    for (String canonical : CANONICAL_ROLES) {
                        byRole.put(canonical, defaultFor(domain, canonical));
                    }
                    for (RoleMfaPolicyRow row : rows) {
                        byRole.put(row.role(), fromRow(row));
                    }
                    return Flux.fromIterable(byRole.values());
                });
    }

    /**
     * {@code true} iff MFA is required for ANY of the principal's roles in the domain — the
     * OR the future login / session / introspect consumers will ask. Roles are normalised
     * ({@code ROLE_ADMIN} → {@code admin}); an empty role set resolves {@code false} (the
     * bare {@code user} default), never an error.
     */
    public Mono<Boolean> requiredForAny(String domain, Collection<String> roles) {
        Set<String> wanted = new LinkedHashSet<>();
        if (roles != null) {
            for (String role : roles) {
                if (role != null && !role.isBlank()) {
                    wanted.add(normaliseRole(role));
                }
            }
        }
        if (wanted.isEmpty()) {
            return Mono.just(false);
        }
        // The floor short-circuits without a read: a floor role is required no matter what.
        for (String role : wanted) {
            if (FLOOR_ROLES.contains(role)) {
                return Mono.just(true);
            }
        }
        return repo.findByDomainAndRoleIn(domain, wanted)
                .collectList()
                .map(rows -> {
                    Map<String, Boolean> answer = new LinkedHashMap<>();
                    for (String role : wanted) {
                        answer.put(role, DEFAULT_REQUIRED.getOrDefault(role, false));
                    }
                    for (RoleMfaPolicyRow row : rows) {
                        answer.put(row.role(), row.required());
                    }
                    return answer.values().stream().anyMatch(Boolean::booleanValue);
                });
    }

    // ── the write path ─────────────────────────────────────────────────────────────

    /**
     * Upsert one (domain, role) policy after validating the role shape, the method vocabulary
     * and the grace bound, and after refusing any attempt to relax the privileged floor.
     * Returns the effective policy as re-read from the store, so the caller sees exactly
     * what the resolver will now answer (floor included).
     */
    public Mono<RoleMfaPolicy> upsert(String domain, String role, boolean required,
                                      List<String> methods, long graceSeconds, String updatedBy) {
        String r = normaliseRole(role);
        if (!ROLE_SHAPE.matcher(r).matches()) {
            return Mono.error(ApiException.badRequest(
                    "role must match [a-z0-9_-]{1,64} (got '" + role + "')"));
        }
        if (FLOOR_ROLES.contains(r) && !required) {
            return Mono.error(ApiException.badRequest(
                    "role '" + r + "' is on the privileged MFA floor and cannot be set required=false"
                            + " (the floor is not relaxable; see docs/MFA-ROLLOUT.md)"));
        }
        if (graceSeconds < 0 || graceSeconds > MAX_GRACE_SECONDS) {
            return Mono.error(ApiException.badRequest(
                    "graceSeconds must be between 0 and " + MAX_GRACE_SECONDS));
        }
        String csv;
        try {
            csv = toCsv(methods);
        } catch (IllegalArgumentException e) {
            return Mono.error(ApiException.badRequest(e.getMessage()));
        }
        return repo.upsert(UUID.randomUUID().toString(), domain, r, required, csv, graceSeconds, updatedBy)
                .then(effectiveFor(domain, r));
    }

    // ── helpers ────────────────────────────────────────────────────────────────────

    /** Lower-case and strip a {@code ROLE_} authority prefix so both spellings resolve alike. */
    static String normaliseRole(String role) {
        String r = role == null ? "" : role.trim().toLowerCase(Locale.ROOT);
        return r.startsWith("role_") ? r.substring("role_".length()) : r;
    }

    private static RoleMfaPolicy fromRow(RoleMfaPolicyRow row) {
        boolean floor = FLOOR_ROLES.contains(row.role());
        return new RoleMfaPolicy(row.domain(), row.role(),
                floor || row.required(), fromCsv(row.methods()), row.graceSeconds(),
                true, floor, row.updatedBy(), row.updatedAt());
    }

    private static RoleMfaPolicy defaultFor(String domain, String role) {
        boolean floor = FLOOR_ROLES.contains(role);
        return new RoleMfaPolicy(domain, role,
                floor || DEFAULT_REQUIRED.getOrDefault(role, false), List.of(), 0L,
                false, floor, null, null);
    }

    /** CSV → list; {@code NULL}/blank means any → empty list. */
    static List<String> fromCsv(String csv) {
        if (csv == null || csv.isBlank()) {
            return List.of();
        }
        List<String> out = new ArrayList<>();
        for (String m : csv.split(",")) {
            String t = m.trim();
            if (!t.isEmpty()) {
                out.add(t);
            }
        }
        return List.copyOf(out);
    }

    /**
     * List → CSV; empty/null means any → {@code NULL}. Rejects anything outside
     * {@link #KNOWN_METHODS} (fail closed: a typo'd method must not silently become "any").
     */
    static String toCsv(List<String> methods) {
        if (methods == null || methods.isEmpty()) {
            return null;
        }
        Set<String> uniq = new LinkedHashSet<>();
        for (String m : methods) {
            String t = m == null ? "" : m.trim().toLowerCase(Locale.ROOT);
            if (!KNOWN_METHODS.contains(t)) {
                throw new IllegalArgumentException(
                        "unknown MFA method '" + m + "' (allowed: webauthn, otp, recovery)");
            }
            uniq.add(t);
        }
        return String.join(",", uniq);
    }
}
