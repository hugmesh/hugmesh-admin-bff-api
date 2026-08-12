package net.hugmesh.adminbff.config;

import org.springframework.aot.hint.MemberCategory;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.RuntimeHintsRegistrar;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportRuntimeHints;
import net.hugmesh.authcore.account.Account;
import net.hugmesh.adminbff.announcement.Announcement;
import net.hugmesh.adminbff.iso.IsoArtifact;
import net.hugmesh.adminbff.routeaccess.RouteRule;
import net.hugmesh.adminbff.urlregistry.UrlRoute;
import net.hugmesh.adminbff.usage.UsageEvent;
import net.hugmesh.adminbff.usage.UsageEventConsumer;
import net.hugmesh.adminbff.device.Device;
import net.hugmesh.adminbff.device.SshLicense;
import net.hugmesh.adminbff.device.DeviceWithLicenses;
import net.hugmesh.adminbff.device.ExportModels;
import net.hugmesh.adminbff.web.dto.AnnouncementRequest;
import net.hugmesh.adminbff.web.dto.GrantLicenseRequest;
import net.hugmesh.adminbff.web.dto.RegisterDeviceRequest;

/**
 * GraalVM native-image / AOT reachability hints for the bits the static analyzer
 * cannot see through on its own — mirrors hugmesh-actions/gateway
 * {@code NativeHintsConfig}.
 *
 * <p>Spring Boot's own AOT processing covers the framework surface (the WebFlux
 * WebClient codecs, the reactive OAuth2 resource-server JWT pipeline, R2DBC, and
 * the Jackson auto-configuration). What it cannot always infer:
 *
 * <ul>
 *   <li><b>JSON-bound DTOs</b> reached reflectively through Jackson — the records
 *       crossing the HTTP / Kafka boundary ({@link Account}, {@link RouteRule},
 *       {@link UrlRoute}, {@link IsoArtifact}, {@link UsageEvent}). The Casdoor /
 *       ClickHouse / Synapse clients deserialize into raw {@code Map}/{@code List}
 *       (already reflection-safe), but the typed records need explicit binding
 *       hints so their constructors/accessors survive native image.</li>
 *   <li><b>The {@code @KafkaListener} bean</b> — keep the consumer + its advised
 *       listener method reachable for the AOT-generated container.</li>
 *   <li><b>The springdoc Swagger UI webjar resources</b> — the
 *       {@code springdoc-openapi-starter-webflux-ui} starter serves the Swagger UI
 *       static assets out of {@code META-INF/resources/webjars/swagger-ui/}.
 *       native-image strips classpath resources by default, so the bundled
 *       {@code swagger-config} / {@code index.html} 404 without an explicit
 *       resource-include pattern. The raw {@code /v3/api-docs} JSON (what
 *       ng-openapi-gen + the docs pipeline actually consume) is produced by
 *       springdoc's own AOT-covered beans and does not need the webjar, so the
 *       spec endpoint works even if the UI hint here proves insufficient.</li>
 * </ul>
 *
 * <p>Best-effort: a full {@code -Pnative native:compile} on a GraalVM-equipped
 * host is the authoritative check; {@code add-reachability-metadata} (from the
 * parent's {@code native} profile) supplies the library-side metadata for the
 * WebClient/Netty/Jackson/r2dbc/kafka jars on top of these app-specific hints.
 * springdoc ships its own reachability-metadata for the OpenAPI model classes,
 * so the only app-side gap is the Swagger-UI webjar resource bundle covered
 * below. If a native Swagger UI render still 404s, widen the include pattern (or
 * front the spec with the static {@code openapi.fallback.json} the docs pipeline
 * keeps) — see openIssues.
 */
@Configuration(proxyBeanMethods = false)
@ImportRuntimeHints(NativeHintsConfig.Hints.class)
public class NativeHintsConfig {

    static class Hints implements RuntimeHintsRegistrar {
        @Override
        public void registerHints(RuntimeHints hints, ClassLoader classLoader) {
            hints.reflection()
                    .registerType(Account.class, dtoCategories())
                    .registerType(RouteRule.class, dtoCategories())
                    .registerType(UrlRoute.class, dtoCategories())
                    .registerType(IsoArtifact.class, dtoCategories())
                    .registerType(UsageEvent.class, dtoCategories())
                    // Announcement (R2DBC row → JSON out) + AnnouncementRequest
                    // (JSON in) cross the Jackson boundary reflectively.
                    .registerType(Announcement.class, dtoCategories())
                    .registerType(AnnouncementRequest.class, dtoCategories())
                    // Device-license registry: the DTOs that cross the Jackson boundary
                    // (R2DBC row → JSON out on Device/SshLicense/DeviceWithLicenses + the
                    // signed-export ExportModels records; JSON in on the two request DTOs).
                    .registerType(Device.class, dtoCategories())
                    .registerType(SshLicense.class, dtoCategories())
                    .registerType(DeviceWithLicenses.class, dtoCategories())
                    .registerType(ExportModels.AuthorizedOperator.class, dtoCategories())
                    .registerType(ExportModels.ExportBody.class, dtoCategories())
                    .registerType(ExportModels.SignedExport.class, dtoCategories())
                    .registerType(RegisterDeviceRequest.class, dtoCategories())
                    .registerType(GrantLicenseRequest.class, dtoCategories());

            hints.reflection()
                    .registerType(UsageEventConsumer.class, proxyTargetCategories());

            // Swagger UI static assets shipped inside the springdoc webflux-ui
            // starter's webjar. native-image drops classpath resources unless
            // explicitly included; without this the Swagger UI page 404s its own
            // bundle under a native binary. The /v3/api-docs JSON (the artefact
            // ng-openapi-gen + the docs pipeline consume) is bean-produced and
            // unaffected, so the spec stays available regardless.
            hints.resources()
                    .registerPattern("META-INF/resources/webjars/swagger-ui/*")
                    .registerPattern("META-INF/resources/webjars/swagger-ui/**");
        }

        private static MemberCategory[] dtoCategories() {
            return new MemberCategory[] {
                    MemberCategory.INVOKE_DECLARED_CONSTRUCTORS,
                    MemberCategory.INVOKE_DECLARED_METHODS,
                    MemberCategory.DECLARED_FIELDS,
            };
        }

        private static MemberCategory[] proxyTargetCategories() {
            return new MemberCategory[] {
                    MemberCategory.INVOKE_DECLARED_CONSTRUCTORS,
                    MemberCategory.INVOKE_DECLARED_METHODS,
            };
        }
    }
}
