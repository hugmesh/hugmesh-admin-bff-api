package net.hugmesh.adminbff.appearance;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Domain-scoped facade over {@link MastodonAppearanceDefaultR2dbcRepository} for
 * {@code mastodon_appearance_default} — the admin-configured platform-wide default
 * appearance the {@code /bff/mastodon/appearance-default} (read) and
 * {@code /bff/admin/mastodon/appearance-default} (write) endpoints serve/upsert. Mirrors
 * {@code UserPreferencesStoreRepository} in hugmesh-user-bff-api.
 */
@Repository
public class MastodonAppearanceDefaultRepository {

    private final MastodonAppearanceDefaultR2dbcRepository repo;

    public MastodonAppearanceDefaultRepository(MastodonAppearanceDefaultR2dbcRepository repo) {
        this.repo = repo;
    }

    /** The brand's stored default (may be a PARTIAL set — only the fields an admin has
     *  explicitly configured; absence of a key is honest "no admin opinion yet"). */
    public Mono<Map<String, String>> findAll(String domain) {
        return repo.findByDomainOrderByPrefKeyAsc(domain).collectList().map(list -> {
            Map<String, String> out = new LinkedHashMap<>();
            for (MastodonAppearanceDefaultEntity e : list) out.put(e.prefKey(), e.prefValue());
            return out;
        });
    }

    /**
     * Upsert one field of the brand's default. Portable (Postgres + H2): UPDATE first
     * (domain AND key scoped), INSERT only if absent.
     */
    public Mono<Void> upsert(String domain, String key, String value, String updatedBy) {
        return repo.update(domain, key, value, updatedBy)
                .flatMap(updated -> updated > 0 ? Mono.empty()
                        : repo.insertRow(domain, key, value, updatedBy).then());
    }
}
