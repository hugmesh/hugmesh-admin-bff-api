package net.hugmesh.adminbff.config;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import net.hugmesh.adminbff.AuthController;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Pins both postures of the legacy-path kill switch (hugmesh-admin-bff-api#86), Docker-free:
 * the SHIPS-DARK default serves every one of the eleven legacy mappings exactly as before, and a
 * switched-off path answers a clean 404 (pinned; not 410), never reaches the handler, and logs
 * enough to identify the caller.
 */
class LegacyAuthPathsKillSwitchWebFilterTest {

    /** The five paths issue #2's audit named as "shadowed" (and #86's Done-when requires). */
    private static final List<String> AUDITED_FIVE = List.of(
            "POST /bff/register/google",
            "POST /bff/register/discord",
            "GET /bff/me/namespaces",
            "POST /bff/provision/matrix",
            "POST /bff/provision/mastodon");

    private Logger logger;
    private ListAppender<ILoggingEvent> appender;

    @BeforeEach
    void captureLogs() {
        logger = (Logger) LoggerFactory.getLogger(LegacyAuthPathsKillSwitchWebFilter.class);
        appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        logger.setLevel(Level.INFO);
    }

    @AfterEach
    void releaseLogs() {
        logger.detachAppender(appender);
    }

    // ── helpers ─────────────────────────────────────────────────────────

    private static MockServerWebExchange exchange(String key) {
        return exchange(key, null);
    }

    private static MockServerWebExchange exchange(String key, String uriOverride) {
        int sp = key.indexOf(' ');
        HttpMethod method = HttpMethod.valueOf(key.substring(0, sp));
        String uri = uriOverride != null ? uriOverride : key.substring(sp + 1);
        return MockServerWebExchange.from(MockServerHttpRequest.method(method, java.net.URI.create(uri))
                .remoteAddress(new InetSocketAddress("10.1.2.3", 51234))
                .header("User-Agent", "kill-switch-test/1.0")
                .header("X-Forwarded-For", "203.0.113.9")
                .build());
    }

    /** Runs the filter and returns how many times the downstream chain was invoked. */
    private static int run(LegacyAuthPathsKillSwitchWebFilter filter, MockServerWebExchange ex) {
        AtomicInteger calls = new AtomicInteger();
        WebFilterChain chain = e -> {
            calls.incrementAndGet();
            return Mono.empty();
        };
        StepVerifier.create(filter.filter(ex, chain)).verifyComplete();
        return calls.get();
    }

    private static void assertServed(LegacyAuthPathsKillSwitchWebFilter filter, String key) {
        MockServerWebExchange ex = exchange(key);
        assertThat(run(filter, ex)).as("%s must reach the handler", key).isEqualTo(1);
        assertThat(ex.getResponse().getStatusCode()).as("%s must not be answered by the filter", key).isNull();
        assertThat(ex.getResponse().getHeaders().getFirst("X-Bff-Denied")).isNull();
    }

    private static void assertSwitchedOff(LegacyAuthPathsKillSwitchWebFilter filter, String key) {
        MockServerWebExchange ex = exchange(key);
        assertThat(run(filter, ex)).as("%s must NOT reach the handler", key).isZero();
        assertThat(ex.getResponse().getStatusCode().value()).as("%s status", key).isEqualTo(404);
        assertThat(ex.getResponse().getHeaders().getFirst("X-Bff-Denied")).isEqualTo("legacy-path-disabled");
    }

    // ── posture 1: SHIPS DARK (the defaults) ────────────────────────────

    @Test
    void defaults_everyLegacyPathServesExactlyAsBefore() {
        var filter = new LegacyAuthPathsKillSwitchWebFilter(new MockEnvironment());

        assertThat(filter.switchedOff()).isEmpty();
        for (String key : LegacyAuthPathsKillSwitchWebFilter.LEGACY_PATHS) {
            assertServed(filter, key);
        }
        assertThat(appender.list).as("the default posture logs nothing").isEmpty();
    }

    @Test
    void emptyEnvVar_isTheDefaultNotAnError() {
        // application.yml maps APP_AUTH_LEGACY_PATHS_DISABLED to "" when unset.
        var env = new MockEnvironment().withProperty(LegacyAuthPathsKillSwitchWebFilter.DISABLED_PROPERTY, "")
                .withProperty(LegacyAuthPathsKillSwitchWebFilter.ENABLED_PROPERTY, "true");

        assertThat(new LegacyAuthPathsKillSwitchWebFilter(env).switchedOff()).isEmpty();
    }

    @Test
    void theEnvVarNamesDocumentedInApplicationYmlReallyDriveTheSwitch() throws Exception {
        // README and application.yml promise these two env names; a typo in the placeholder would
        // ship a switch no operator can flip, and the other tests set the property directly.
        var yaml = new org.springframework.boot.env.YamlPropertySourceLoader()
                .load("application", new org.springframework.core.io.ClassPathResource("application.yml"));
        var env = new org.springframework.core.env.StandardEnvironment();
        env.getPropertySources().remove(org.springframework.core.env.StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME);
        env.getPropertySources().remove(org.springframework.core.env.StandardEnvironment.SYSTEM_PROPERTIES_PROPERTY_SOURCE_NAME);
        yaml.forEach(env.getPropertySources()::addLast);
        assertThat(new LegacyAuthPathsKillSwitchWebFilter(env).switchedOff()).as("yml defaults").isEmpty();

        env.getPropertySources().addFirst(new org.springframework.core.env.MapPropertySource("fake-env", java.util.Map.of(
                "APP_AUTH_LEGACY_PATHS_DISABLED", "POST /bff/login,GET /bff/me")));
        assertThat(new LegacyAuthPathsKillSwitchWebFilter(env).switchedOff())
                .containsExactlyInAnyOrder("POST /bff/login", "GET /bff/me");

        env.getPropertySources().addFirst(new org.springframework.core.env.MapPropertySource("fake-env2", java.util.Map.of(
                "APP_AUTH_LEGACY_PATHS_ENABLED", "false")));
        assertThat(new LegacyAuthPathsKillSwitchWebFilter(env).switchedOff())
                .isEqualTo(LegacyAuthPathsKillSwitchWebFilter.LEGACY_PATHS);
    }

    // ── posture 2: switched OFF ─────────────────────────────────────────

    @Test
    void globalSwitchOff_everyOneOfTheElevenAnswers404AndNoneReachesTheHandler() {
        var filter = new LegacyAuthPathsKillSwitchWebFilter(false, List.of());

        assertThat(LegacyAuthPathsKillSwitchWebFilter.LEGACY_PATHS).hasSize(11);
        for (String key : LegacyAuthPathsKillSwitchWebFilter.LEGACY_PATHS) {
            assertSwitchedOff(filter, key);
        }
    }

    @Test
    void perPath_theFiveAuditedPathsCanEachBeSwitchedOffAlone() {
        for (String target : AUDITED_FIVE) {
            var filter = new LegacyAuthPathsKillSwitchWebFilter(true, List.of(target));
            for (String key : LegacyAuthPathsKillSwitchWebFilter.LEGACY_PATHS) {
                if (key.equals(target)) {
                    assertSwitchedOff(filter, key);
                } else {
                    assertServed(filter, key);
                }
            }
        }
    }

    @Test
    void disabledStatusIs404Not410() {
        assertThat(LegacyAuthPathsKillSwitchWebFilter.DISABLED_STATUS.value()).isEqualTo(404);
    }

    @Test
    void propertyBinding_listFormAndCommaFormBothWork_andNormaliseCaseAndSpacing() {
        var indexed = new MockEnvironment()
                .withProperty(LegacyAuthPathsKillSwitchWebFilter.DISABLED_PROPERTY + "[0]", "POST /bff/login")
                .withProperty(LegacyAuthPathsKillSwitchWebFilter.DISABLED_PROPERTY + "[1]", "get   /bff/me");
        var comma = new MockEnvironment()
                .withProperty(LegacyAuthPathsKillSwitchWebFilter.DISABLED_PROPERTY,
                        "POST /bff/login, get   /bff/me");

        for (var env : List.of(indexed, comma)) {
            var filter = new LegacyAuthPathsKillSwitchWebFilter(env);
            assertThat(filter.switchedOff()).containsExactlyInAnyOrder("POST /bff/login", "GET /bff/me");
            assertSwitchedOff(filter, "POST /bff/login");
            assertSwitchedOff(filter, "GET /bff/me");
            assertServed(filter, "GET /bff/session");
        }
    }

    @Test
    void globalFlagFalseFromTheEnvironment_switchesEverythingOff() {
        var env = new MockEnvironment().withProperty(LegacyAuthPathsKillSwitchWebFilter.ENABLED_PROPERTY, "false");

        var filter = new LegacyAuthPathsKillSwitchWebFilter(env);

        assertThat(filter.switchedOff()).isEqualTo(LegacyAuthPathsKillSwitchWebFilter.LEGACY_PATHS);
    }

    @Test
    void anUnknownEntryFailsTheBoot_soATypoCannotReadAsADeadPath() {
        assertThatThrownBy(() -> new LegacyAuthPathsKillSwitchWebFilter(true, List.of("POST /bff/regster/google")))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("POST /bff/regster/google")
                .hasMessageContaining("POST /bff/register/google");
        // the right path with the wrong verb is also not one of the eleven
        assertThatThrownBy(() -> new LegacyAuthPathsKillSwitchWebFilter(true, List.of("GET /bff/login")))
                .isInstanceOf(IllegalStateException.class);
        // and a bare path with no verb
        assertThatThrownBy(() -> new LegacyAuthPathsKillSwitchWebFilter(true, List.of("/bff/login")))
                .isInstanceOf(IllegalStateException.class);
        // even when the global switch is already off the list is still validated
        assertThatThrownBy(() -> new LegacyAuthPathsKillSwitchWebFilter(false, List.of("POST /bff/nope")))
                .isInstanceOf(IllegalStateException.class);
    }

    // ── scope: what the switch must NOT touch ───────────────────────────

    @Test
    void nonLegacyPathsAreNeverGated_evenWithTheGlobalSwitchOff() {
        var filter = new LegacyAuthPathsKillSwitchWebFilter(false, List.of());

        for (String key : List.of("GET /bff/admin/allowlist", "POST /bff/register", "GET /bff/public/theme",
                "DELETE /bff/session", "GET /bff/login", "POST /bff/me", "GET /actuator/health")) {
            assertServed(filter, key);
        }
    }

    @Test
    void optionsIsNeverGated_soCorsPreflightStaysOwnedByTheCorsLayer() {
        var filter = new LegacyAuthPathsKillSwitchWebFilter(false, List.of());

        assertServed(filter, "OPTIONS /bff/login");
    }

    @Test
    void headIsTreatedAsGet_soAGetPathCannotBeProbedWithHeadWhileSwitchedOff() {
        var filter = new LegacyAuthPathsKillSwitchWebFilter(true, List.of("GET /bff/session"));

        MockServerWebExchange head = exchange("HEAD /bff/session");
        assertThat(run(filter, head)).isZero();
        assertThat(head.getResponse().getStatusCode().value()).isEqualTo(404);
    }

    @Test
    void encodedAndParameterisedSpellingsCannotSlipPastASwitchTheControllerWouldStillAnswer() {
        var filter = new LegacyAuthPathsKillSwitchWebFilter(true, List.of("POST /bff/login"));

        for (String uri : List.of("/bff/%6Cogin", "/bff/login;jsessionid=x")) {
            MockServerWebExchange ex = exchange("POST /bff/login", uri);
            assertThat(run(filter, ex)).as(uri).isZero();
            assertThat(ex.getResponse().getStatusCode().value()).as(uri).isEqualTo(404);
        }
        // a different path that merely starts the same way is not swallowed
        assertServed(filter, "POST /bff/login/local");
        MockServerWebExchange prefix = exchange("POST /bff/login", "/bff/loginx");
        assertThat(run(filter, prefix)).isEqualTo(1);
    }

    // ── logging ─────────────────────────────────────────────────────────

    @Test
    void aSwitchedOffHitLogsWhichPathAndWhoCalled() {
        var filter = new LegacyAuthPathsKillSwitchWebFilter(true, List.of("POST /bff/register/google"));
        appender.list.clear();

        run(filter, exchange("POST /bff/register/google"));

        assertThat(appender.list).hasSize(1);
        ILoggingEvent event = appender.list.get(0);
        assertThat(event.getLevel()).isEqualTo(Level.WARN);
        assertThat(event.getFormattedMessage())
                .contains("POST /bff/register/google")
                .contains("10.1.2.3")
                .contains("203.0.113.9")
                .contains("kill-switch-test/1.0");
    }

    @Test
    void aServedPathLogsNothing() {
        var filter = new LegacyAuthPathsKillSwitchWebFilter(true, List.of("POST /bff/register/google"));
        appender.list.clear();

        run(filter, exchange("GET /bff/session"));

        assertThat(appender.list).isEmpty();
    }

    @Test
    void headerValuesCannotForgeLogLinesOrFloodTheLog() {
        var filter = new LegacyAuthPathsKillSwitchWebFilter(true, List.of("POST /bff/login"));
        appender.list.clear();
        MockServerWebExchange ex = MockServerWebExchange.from(MockServerHttpRequest.post("/bff/login")
                .header("User-Agent", "evil\r\nINFO forged line \u0085 \u2028 \u2029 " + "x".repeat(5000))
                .build());

        run(filter, ex);

        String message = appender.list.get(0).getFormattedMessage();
        assertThat(message).doesNotContain("\r").doesNotContain("\n")
                .doesNotContain("\u0085").doesNotContain("\u2028").doesNotContain("\u2029");
        assertThat(message.length()).isLessThan(1000);
        assertThat(message).contains("(truncated)");
    }

    @Test
    void constructingWithSwitchedOffPathsLogsThemOnce_soBootLogsShowTheActivePosture() {
        appender.list.clear();

        new LegacyAuthPathsKillSwitchWebFilter(true, List.of("GET /bff/me"));

        assertThat(appender.list).hasSize(1);
        assertThat(appender.list.get(0).getFormattedMessage()).contains("GET /bff/me");
    }

    // ── drift and placement ─────────────────────────────────────────────

    /** The mappings AuthController really declares, read off its annotations. */
    private static Set<String> declaredByAuthController() {
        String prefix = AnnotatedElementUtils.findMergedAnnotation(AuthController.class, RequestMapping.class)
                .path()[0];
        Set<String> declared = new TreeSet<>();
        for (Method m : AuthController.class.getDeclaredMethods()) {
            RequestMapping mapping = AnnotatedElementUtils.findMergedAnnotation(m, RequestMapping.class);
            if (mapping == null) {
                continue;
            }
            for (var verb : mapping.method()) {
                for (String path : mapping.path()) {
                    declared.add(verb.name() + " " + prefix + path);
                }
            }
        }
        return declared;
    }

    @Test
    void theKnownSetIsExactlyWhatAuthControllerDeclares() {
        assertThat(declaredByAuthController())
                .as("the kill switch's LEGACY_PATHS must list every AuthController mapping, no more, no fewer")
                .isNotEmpty()
                .isEqualTo(new TreeSet<>(LegacyAuthPathsKillSwitchWebFilter.LEGACY_PATHS));
    }

    @Test
    void theFilterRunsAheadOfTheSessionBridgeAndTheSecurityChain() {
        Order order = LegacyAuthPathsKillSwitchWebFilter.class.getAnnotation(Order.class);

        // BffRawTokenContextWebFilter is HIGHEST_PRECEDENCE+9, the bff_ cookie bridge +10, the
        // suspension gate +11, and Spring Security's WebFilterChainProxy is at -100.
        assertThat(order.value()).isLessThan(Ordered.HIGHEST_PRECEDENCE + 9);
    }
}
