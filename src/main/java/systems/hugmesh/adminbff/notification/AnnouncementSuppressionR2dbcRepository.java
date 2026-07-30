package systems.hugmesh.adminbff.notification;

import org.springframework.data.repository.reactive.ReactiveCrudRepository;

/**
 * Reactive (R2DBC) Spring Data store for {@code announcement_suppressed} (Liquibase
 * changeset 062). The PK is the natural key {@code domain}; the {@link
 * AnnouncementSuppressionRepository} facade composes {@code findById}/{@code save}
 * into the portable insert-or-update upsert.
 */
public interface AnnouncementSuppressionR2dbcRepository
        extends ReactiveCrudRepository<AnnouncementSuppression, String> {
}
