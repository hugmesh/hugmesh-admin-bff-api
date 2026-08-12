package net.hugmesh.adminbff.notification;

import org.springframework.data.repository.reactive.ReactiveCrudRepository;

/**
 * Reactive (R2DBC) Spring Data store for {@code notification_cursor} (Liquibase
 * changeset 062). PK is the natural key {@code consumer}; the {@link
 * NotificationCursorRepository} facade composes {@code findById}/{@code save} into the
 * portable advance upsert.
 */
public interface NotificationCursorR2dbcRepository
        extends ReactiveCrudRepository<NotificationCursor, String> {
}
