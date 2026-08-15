package net.hugmesh.adminbff.theme;

import org.springframework.data.r2dbc.core.R2dbcEntityTemplate;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Persistence for {@link DomainTheme}. R2DBC throughout — this BFF is fully reactive and
 * a blocking JDBC call here would stall the event loop for every other request.
 *
 * The domain is the PRIMARY KEY, so a write is an UPSERT rather than an insert-or-update
 * dance: two admins saving the same domain at once must converge on one row, not race
 * into a constraint violation that surfaces as "your theme did not save".
 */
@Repository
public class DomainThemeRepository {

    private static final String UPSERT = """
            INSERT INTO domain_theme
                (domain, preset, ramp, style, primary_hex, secondary_hex, updated_at, updated_by,
                 rendered_css, rendered_by)
            VALUES (:domain, :preset, :ramp, :style, :primaryHex, :secondaryHex, now(), :updatedBy,
                    :renderedCss, :renderedBy)
            ON CONFLICT (domain) DO UPDATE SET
                preset = EXCLUDED.preset,
                ramp = EXCLUDED.ramp,
                style = EXCLUDED.style,
                primary_hex = EXCLUDED.primary_hex,
                secondary_hex = EXCLUDED.secondary_hex,
                updated_at = now(),
                updated_by = EXCLUDED.updated_by,
                rendered_css = EXCLUDED.rendered_css,
                rendered_by = EXCLUDED.rendered_by
            """;

    private static final String SELECT_ALL = """
            SELECT domain, preset, ramp, style, primary_hex, secondary_hex, updated_by,
                   rendered_css, rendered_by
            FROM domain_theme ORDER BY domain
            """;

    private static final String SELECT_ONE = """
            SELECT domain, preset, ramp, style, primary_hex, secondary_hex, updated_by,
                   rendered_css, rendered_by
            FROM domain_theme WHERE domain = :domain
            """;

    private final R2dbcEntityTemplate template;

    public DomainThemeRepository(R2dbcEntityTemplate template) {
        this.template = template;
    }

    public Flux<DomainTheme> findAll() {
        return template.getDatabaseClient().sql(SELECT_ALL).map(DomainThemeRepository::map).all();
    }

    /** One domain's row, or empty. Never falls back to the mesh default here — that
     *  decision belongs to the service, which knows whether it is RESOLVING a theme to
     *  render or LISTING what has actually been configured. Folding it in would make
     *  "this domain has no override" indistinguishable from "it chose the default". */
    public Mono<DomainTheme> findByDomain(String domain) {
        return template.getDatabaseClient().sql(SELECT_ONE)
                .bind("domain", DomainTheme.normalizeDomain(domain))
                .map(DomainThemeRepository::map)
                .one();
    }

    public Mono<DomainTheme> upsert(DomainTheme t) {
        return template.getDatabaseClient().sql(UPSERT)
                .bind("domain", t.domain())
                .bind("preset", t.preset())
                .bind("ramp", t.ramp())
                .bind("style", t.style())
                .bind("primaryHex", t.primaryHex() == null ? io.r2dbc.spi.Parameters.in(String.class) : io.r2dbc.spi.Parameters.in(t.primaryHex()))
                .bind("secondaryHex", t.secondaryHex() == null ? io.r2dbc.spi.Parameters.in(String.class) : io.r2dbc.spi.Parameters.in(t.secondaryHex()))
                .bind("updatedBy", t.updatedBy() == null ? io.r2dbc.spi.Parameters.in(String.class) : io.r2dbc.spi.Parameters.in(t.updatedBy()))
                .bind("renderedCss", t.renderedCss() == null ? io.r2dbc.spi.Parameters.in(String.class) : io.r2dbc.spi.Parameters.in(t.renderedCss()))
                .bind("renderedBy", t.renderedBy() == null ? io.r2dbc.spi.Parameters.in(String.class) : io.r2dbc.spi.Parameters.in(t.renderedBy()))
                .fetch().rowsUpdated()
                .then(findByDomain(t.domain()));
    }

    public Mono<Void> delete(String domain) {
        return template.getDatabaseClient()
                .sql("DELETE FROM domain_theme WHERE domain = :domain")
                .bind("domain", DomainTheme.normalizeDomain(domain))
                .fetch().rowsUpdated().then();
    }

    private static DomainTheme map(io.r2dbc.spi.Row row, io.r2dbc.spi.RowMetadata meta) {
        return new DomainTheme(
                row.get("domain", String.class),
                row.get("preset", String.class),
                row.get("ramp", String.class),
                row.get("style", String.class),
                row.get("primary_hex", String.class),
                row.get("secondary_hex", String.class),
                row.get("updated_by", String.class),
                row.get("rendered_css", String.class),
                row.get("rendered_by", String.class));
    }
}
