package net.hugmesh.adminbff.servicecatalog;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.web.ApiException;
import net.hugmesh.adminbff.web.FieldValidationException;

import java.util.List;
import java.util.Map;

/**
 * CRUD surface for {@code app_profile} — the reusable, SUPERADMIN-owned deploy templates
 * (App-Store PR1 data layer). GLOBAL (cross-domain) — there is no tenant scoping; the
 * controller's {@code @PreAuthorize("hasRole('SUPERADMIN')")} is the only gate (mirrors
 * {@link net.hugmesh.adminbff.domainregistry.DomainRegistryService}).
 *
 * <p>{@code name} is the UNIQUE natural key: a find-before-insert check surfaces a clean
 * 409, with the DB UNIQUE index as the race backstop (also mapped to 409).
 *
 * <h3>{@code profileJson} is validated on save (issue #55)</h3>
 * It is no longer opaque on the way IN. {@link #create} and {@link #update} validate it against
 * {@link AppProfileSchema} — the byte-identical copy of the console's committed JSON Schema —
 * before the write, so a direct API call or a stale browser tab cannot store a body the console
 * would refuse. Un-parked by operator decision 37 (2026-09-17, hugmesh-generator#347), which
 * ratified the three choices the schema had to make: {@code ROLE_<UPPER>} role names, STRICT on
 * unknown keys, and keeping {@code exposure.mfaRequired}.
 *
 * <p>Three things this deliberately does NOT do:
 * <ul>
 *   <li>It does not REWRITE anything. The operator's text is stored verbatim, exactly as before;
 *       validation only decides whether the write happens.</li>
 *   <li>It does not validate on the way OUT. {@link #list} and {@link #get} always return what is
 *       stored — a row written before the schema existed (the flat {@code {"cpu","memory"}} form)
 *       stays readable and editable. They only WARN, once per offending row, so a superadmin read
 *       reports the rows a human has to move rather than hiding them.</li>
 *   <li>It does not RESOLVE the values. Nothing reads resources/roles/certs/exposure yet — that is
 *       the effector, still open on catalog-ui#3.</li>
 * </ul>
 */
@Service
public class AppProfileService {

    private static final Logger log = LoggerFactory.getLogger(AppProfileService.class);

    private final AppProfileRepository repo;

    public AppProfileService(AppProfileRepository repo) {
        this.repo = repo;
    }

    /** Every profile (the SUPERADMIN list surface). Reports, never rewrites — see {@link #reportIfLegacy}. */
    public Flux<AppProfile> list() {
        return repo.findAll().doOnNext(AppProfileService::reportIfLegacy);
    }

    /** A single profile by {@code name}, or a 404. Reports, never rewrites. */
    public Mono<AppProfile> get(String name) {
        return repo.findByName(name)
                .doOnNext(AppProfileService::reportIfLegacy)
                .switchIfEmpty(Mono.error(ApiException.notFound(
                        "no app_profile named '" + name + "'")));
    }

    /**
     * WARN once per row whose STORED body does not match the schema, on the SUPERADMIN read
     * surface — the "report them, never rewrite them" half of the #55 contract. A row written
     * before the schema existed (the flat {@code {"cpu","memory"}} pair is the known legacy
     * shape) is still returned in full and still editable; the console shows its field errors the
     * moment it is opened. Rewriting it here would silently change an operator's stored template,
     * and refusing the READ would make the row unfixable through the console.
     */
    private static void reportIfLegacy(AppProfile profile) {
        Map<String, String> invalid = schemaErrors(profile.profileJson());
        if (!invalid.isEmpty()) {
            log.warn("[app-profile] stored profile_json does not match the schema for '{}' (id={}): {}"
                    + " - NOT rewritten; edit it in the Service Catalog console to fix it",
                    profile.name(), profile.id(), invalid);
        }
    }

    /** Field path → message for every schema violation in {@code profileJson}; empty when valid. */
    private static Map<String, String> schemaErrors(String profileJson) {
        List<AppProfileSchema.FieldError> errors = AppProfileSchema.validate(profileJson);
        return errors.isEmpty() ? Map.of() : AppProfileSchema.asFields(errors);
    }

    /**
     * Create a profile, stamping {@code created_by_subject} from the SUPERADMIN's JWT
     * subject. Validates {@code name} non-blank + UNIQUE (find-before-insert 409; the DB
     * UNIQUE index is the race backstop, also mapped to 409).
     */
    public Mono<AppProfile> create(String name, String profileJson, String createdBySubject) {
        String n = name == null ? null : name.trim();
        if (n == null || n.isBlank()) {
            return Mono.error(ApiException.badRequest("name is required"));
        }
        Map<String, String> invalid = schemaErrors(profileJson);
        if (!invalid.isEmpty()) {
            return Mono.error(new FieldValidationException(invalid));
        }
        return repo.findByName(n)
                .flatMap(existing -> Mono.<AppProfile>error(ApiException.conflict(
                        "app_profile '" + n + "' already exists")))
                .switchIfEmpty(Mono.defer(() -> repo.insert(n, profileJson, createdBySubject)
                        .doOnNext(p -> log.info("[app-profile] created '{}' by {} (id={})",
                                p.name(), createdBySubject, p.id()))
                        // Race backstop: a concurrent insert that beat the find-check trips
                        // the name UNIQUE index. Re-check the row: if it now exists this was a
                        // duplicate -> the same clean 409; otherwise propagate the original error.
                        .onErrorResume(e -> repo.findByName(n)
                                .flatMap(now -> Mono.<AppProfile>error(ApiException.conflict(
                                        "app_profile '" + n + "' already exists")))
                                .switchIfEmpty(Mono.error(e)))));
    }

    /**
     * Update the mutable {@code profile_json} of an existing profile (matched by
     * {@code name}). The PK, name, created_at and created_by_subject are IMMUTABLE. A 404 if
     * no such profile exists.
     */
    public Mono<AppProfile> update(String name, String profileJson) {
        Map<String, String> invalid = schemaErrors(profileJson);
        if (!invalid.isEmpty()) {
            return Mono.error(new FieldValidationException(invalid));
        }
        return repo.findByName(name)
                .switchIfEmpty(Mono.error(ApiException.notFound(
                        "no app_profile named '" + name + "'")))
                .flatMap(current -> repo.updateJson(name, profileJson)
                        .doOnNext(p -> log.info("[app-profile] updated '{}' (id={})", p.name(), p.id())));
    }

    /** Delete a profile by {@code name} (a reusable template a superadmin may remove). A 404
     *  if no such profile exists. */
    public Mono<Void> delete(String name) {
        return repo.deleteByName(name)
                .flatMap(n -> n == 0
                        ? Mono.error(ApiException.notFound("no app_profile named '" + name + "'"))
                        : Mono.<Void>empty().doOnSubscribe(s ->
                                log.info("[app-profile] deleted '{}'", name)))
                .then();
    }
}
