package net.hugmesh.adminbff.notification;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.transaction.ReactiveTransactionManager;
import org.springframework.transaction.reactive.TransactionalOperator;

/**
 * Exposes the {@link TransactionalOperator} the {@code SuspensionService} uses to wrap
 * the access_suspension effect write + the notification_outbox write in ONE reactive
 * transaction (the lossless transactional-outbox pattern, Notifications PR2).
 *
 * <p>Spring Boot's R2DBC auto-configuration already contributes a
 * {@link ReactiveTransactionManager} ({@code R2dbcTransactionManager}) bound to the
 * application's {@code ConnectionFactory}; this config just derives a programmatic
 * {@link TransactionalOperator} from it so the service can {@code .as(tx::transactional)}
 * a specific reactive pipeline (rather than relying on declarative {@code @Transactional}
 * AOP, which the codebase does not otherwise use). {@code @ConditionalOnMissingBean}
 * lets a test supply its own operator (e.g. over the H2 test {@code ConnectionFactory}).
 */
@Configuration(proxyBeanMethods = false)
public class NotificationTxConfig {

    @Bean
    @ConditionalOnMissingBean
    public TransactionalOperator notificationTransactionalOperator(ReactiveTransactionManager txManager) {
        return TransactionalOperator.create(txManager);
    }
}
