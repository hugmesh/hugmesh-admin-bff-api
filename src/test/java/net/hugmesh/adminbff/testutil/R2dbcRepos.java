package net.hugmesh.adminbff.testutil;

import org.springframework.data.r2dbc.core.R2dbcEntityTemplate;
import org.springframework.data.r2dbc.repository.support.R2dbcRepositoryFactory;
import org.springframework.r2dbc.core.DatabaseClient;

/**
 * Test-only factory that materialises a Spring Data R2DBC repository interface from a
 * {@code DatabaseClient} / {@code R2dbcEntityTemplate} (the bean a {@code @DataR2dbcTest}
 * slice autowires).
 *
 * <p>The data-access refactor moved every facade off the raw {@code DatabaseClient} onto a
 * {@code ReactiveCrudRepository} interface; the existing {@code @DataR2dbcTest} parity
 * slices construct the facades manually ({@code new XxxRepository(db)}). Rather than
 * rewrite each slice to depend on the Spring context's repository proxies, this helper
 * builds the interface proxy on demand from the same {@code DatabaseClient}, so a test
 * swaps {@code new XxxRepository(db)} for
 * {@code new XxxRepository(R2dbcRepos.of(template, XxxRowRepository.class))}. The proxy is
 * a real Spring Data repository (derived finders + {@code @Query} all execute against the
 * H2 store), so the slices remain a true parity net for the migrated code paths.
 */
public final class R2dbcRepos {

    private R2dbcRepos() {
    }

    /** Build the repository interface proxy from an autowired {@link R2dbcEntityTemplate}. */
    public static <R> R of(R2dbcEntityTemplate template, Class<R> repositoryInterface) {
        return new R2dbcRepositoryFactory(template).getRepository(repositoryInterface);
    }

    /** Build the repository interface proxy from a {@link DatabaseClient} (resolves the
     *  dialect from the client's connection factory). */
    public static <R> R of(DatabaseClient db, Class<R> repositoryInterface) {
        R2dbcEntityTemplate template = new R2dbcEntityTemplate(db,
                org.springframework.data.r2dbc.dialect.DialectResolver.getDialect(
                        db.getConnectionFactory()));
        return of(template, repositoryInterface);
    }
}
