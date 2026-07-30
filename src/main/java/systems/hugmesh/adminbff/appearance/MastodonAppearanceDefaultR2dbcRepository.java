package systems.hugmesh.adminbff.appearance;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Reactive (R2DBC) Spring Data store for {@code mastodon_appearance_default} (changeset
 * 240). Derived finders cover the per-domain list/find; the UPDATE-first/INSERT-if-absent
 * upsert legs are {@code @Query} static-final constants (server-side {@code now()}) —
 * mirrors {@code UserPreferencesStoreR2dbcRepository} in hugmesh-user-bff-api.
 */
public interface MastodonAppearanceDefaultR2dbcRepository
        extends ReactiveCrudRepository<MastodonAppearanceDefaultEntity, String> {

    Flux<MastodonAppearanceDefaultEntity> findByDomainOrderByPrefKeyAsc(String domain);

    Mono<MastodonAppearanceDefaultEntity> findByDomainAndPrefKey(String domain, String prefKey);

    // ---- UPSERT (@Query) ----

    String UPDATE =
            "UPDATE mastodon_appearance_default SET pref_value = :value, updated_by = :updatedBy, "
            + "updated_at = now() WHERE domain = :domain AND pref_key = :key";

    String INSERT =
            "INSERT INTO mastodon_appearance_default (domain, pref_key, pref_value, updated_by, updated_at) "
            + "VALUES (:domain, :key, :value, :updatedBy, now())";

    @Modifying
    @Query(UPDATE)
    Mono<Long> update(@Param("domain") String domain, @Param("key") String key,
                      @Param("value") String value, @Param("updatedBy") String updatedBy);

    @Modifying
    @Query(INSERT)
    Mono<Long> insertRow(@Param("domain") String domain, @Param("key") String key,
                         @Param("value") String value, @Param("updatedBy") String updatedBy);
}
