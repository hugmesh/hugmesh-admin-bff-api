package net.hugmesh.adminbff;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.AutoConfigurationPackage;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Import;
import org.springframework.scheduling.annotation.EnableScheduling;

/** Admin BFF — backend namespace, behind the be-gateway. Owns the Gmail/Discord
 *  registration allowlist + per-user namespace access, brokers Matrix/Mastodon
 *  service tokens, and aggregates ClickHouse usage. Invites users in Casdoor via
 *  the hugmesh-pki gateway. Reference behaviour: the verified mock in
 *  catalyst-scripts tests/stack/mock-bff.mjs.
 *
 *  {@code @EnableScheduling} activates BOTH {@code @Scheduled} sweeps:
 *    - the announcement akkoma-reconcile sweep (removes akkoma posts for
 *      expired/unpublished announcements; idempotent);
 *    - the access_suspension reconcile + expiry loop (MatrixAccessSyncAction /
 *      MastodonAccessSyncAction / SuspensionExpiryAction — the single-writer
 *      effector of the access-role ban / timed-suspension desired state).
 *
 *  <p>The shared account/session/MFA/Casdoor stack now lives in
 *  {@code net.hugmesh.authcore.*} (the hugmesh-auth-core jar). Two wirings make it
 *  visible to this app WITHOUT regressing the test slices:
 *  <ul>
 *    <li>{@code scanBasePackages} adds {@code authcore} so its {@code @Component}/
 *        {@code @Configuration} beans (AccountStore, CasdoorAdminConfig, the MFA + filter beans;
 *        the conditional Casdoor/OIDC configs stay inert) are component-scanned.</li>
 *    <li>{@link AuthCorePackages} registers {@code authcore} as an auto-configuration package so
 *        Boot's R2DBC repository AUTO-config discovers the relocated repos. We do this instead of
 *        a direct {@code @EnableR2dbcRepositories}, because an explicit enable is UNCONDITIONAL —
 *        it would force every repository to instantiate inside {@code @WebFluxTest} slices that
 *        have no {@code r2dbcEntityTemplate}. Routing through the auto-config (which slices
 *        correctly exclude) keeps the web-slice tests loading exactly as before.</li>
 *  </ul> */
@SuppressWarnings("checkstyle:HideUtilityClassConstructor")
@SpringBootApplication(scanBasePackages = {"net.hugmesh.adminbff", "net.hugmesh.authcore"})
@Import(AdminBffApplication.AuthCorePackages.class)
@EnableScheduling
public class AdminBffApplication {
    public static void main(String[] args) { SpringApplication.run(AdminBffApplication.class, args); }

    /** Adds {@code net.hugmesh.authcore} to Spring Boot's auto-configuration packages (in
     *  addition to {@code adminbff} from {@code @SpringBootApplication}) so the slice-excludable
     *  R2DBC repository auto-config scans the relocated auth-core repositories. */
    @AutoConfigurationPackage(basePackages = "net.hugmesh.authcore")
    static class AuthCorePackages {
    }
}
