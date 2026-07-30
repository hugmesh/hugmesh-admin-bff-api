package systems.hugmesh.adminbff.servicecatalog;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.web.ApiException;

/**
 * CRUD surface for {@code app_profile} — the reusable, SUPERADMIN-owned deploy templates
 * (App-Store PR1 data layer). GLOBAL (cross-domain) — there is no tenant scoping; the
 * controller's {@code @PreAuthorize("hasRole('SUPERADMIN')")} is the only gate (mirrors
 * {@link systems.hugmesh.adminbff.domainregistry.DomainRegistryService}).
 *
 * <p>{@code name} is the UNIQUE natural key: a find-before-insert check surfaces a clean
 * 409, with the DB UNIQUE index as the race backstop (also mapped to 409). {@code
 * profileJson} is opaque template data — the app does not parse it in PR1.
 */
@Service
public class AppProfileService {

    private static final Logger log = LoggerFactory.getLogger(AppProfileService.class);

    private final AppProfileRepository repo;

    public AppProfileService(AppProfileRepository repo) {
        this.repo = repo;
    }

    /** Every profile (the SUPERADMIN list surface). */
    public Flux<AppProfile> list() {
        return repo.findAll();
    }

    /** A single profile by {@code name}, or a 404. */
    public Mono<AppProfile> get(String name) {
        return repo.findByName(name)
                .switchIfEmpty(Mono.error(ApiException.notFound(
                        "no app_profile named '" + name + "'")));
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
