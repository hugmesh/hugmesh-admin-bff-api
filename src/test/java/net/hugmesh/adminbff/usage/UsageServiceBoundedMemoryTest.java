package net.hugmesh.adminbff.usage;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.core.env.PropertySource;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.io.ClassPathResource;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * hugmesh-admin-bff-api#105 (decision 105 = A): {@code UsageService}'s in-memory fallback log is
 * a fixed-capacity ring plus exact running counters. RED on the pre-fix code, where it was an
 * unbounded {@code ConcurrentLinkedQueue} that every {@code record()} appended to and nothing
 * removed from (the issue measured 7 -> 507 after 500 calls).
 *
 * <p>ClickHouse is pointed at a closed port and Kafka is absent, so {@code aggregate()} takes
 * the in-memory fallback — the only data source for the admin Usage view when ClickHouse is
 * down. {@code record()} appends eagerly and returns a lazy Mono, so these calls never dial.
 */
class UsageServiceBoundedMemoryTest {

    private static final Duration WAIT = Duration.ofSeconds(30);

    private static UsageService service(int capacity) {
        return new UsageService("http://127.0.0.1:9", "", "", "usage_events", null, capacity);
    }

    @Test
    void defaultCapacityPlus500Records_holdsExactlyCapacityEvents_andTotalsStayExact() {
        int capacity = UsageService.DEFAULT_IN_MEMORY_CAPACITY;
        UsageService usage = service(capacity);
        for (int i = 0; i < capacity + 500; i++) {
            usage.record("user-" + i, List.of("user"), "login");
        }
        assertThat(usage.inMemoryEventCount()).isEqualTo(capacity);

        Map<String, Object> view = usage.aggregate().block(WAIT);
        assertThat(view).containsEntry("source", "in-memory");
        assertThat(view.get("totalEvents")).isEqualTo((long) capacity + 500);
        assertThat(view.get("windowEvents")).isEqualTo(capacity);
        assertThat(moduleRow(view, "login-ui"))
                .containsEntry("events", (long) capacity + 500)
                // distinct users are "over the last N events": the oldest 500 aged out.
                .containsEntry("users", capacity);
    }

    @Test
    void perModuleCountsStayExact_afterAModuleHasAgedOutOfTheRing() {
        UsageService usage = service(50);
        for (int i = 0; i < 3; i++) {
            usage.record("early-" + i, List.of(), "register");            // login-ui
        }
        for (int i = 0; i < 120; i++) {
            usage.record("admin-" + (i % 7), List.of("admin"), "admin.invite");  // admin-ui
        }
        assertThat(usage.inMemoryEventCount()).isEqualTo(50);

        Map<String, Object> view = usage.aggregate().block(WAIT);
        assertThat(view.get("totalEvents")).isEqualTo(123L);
        assertThat(moduleRow(view, "admin-ui")).containsEntry("events", 120L).containsEntry("users", 7);
        // Every login-ui event is out of the window, yet its exact count survives.
        assertThat(moduleRow(view, "login-ui")).containsEntry("events", 3L).containsEntry("users", 0);
        // Window-based figures cover the last 50 events only.
        assertThat(view.get("activeUsers")).isEqualTo(7);
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> byAction = (List<Map<String, Object>>) view.get("byAction");
        assertThat(byAction).hasSize(1);
        assertThat(byAction.get(0)).containsEntry("action", "admin.invite").containsEntry("events", 50L);
        // byModule is ordered by exact event count, descending.
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> byModule = (List<Map<String, Object>>) view.get("byModule");
        assertThat(byModule).extracting(r -> r.get("module")).containsExactly("admin-ui", "login-ui");
    }

    @Test
    void concurrentRecords_neverExceedTheCapacity_andCountEveryEvent() throws Exception {
        UsageService usage = service(100);
        int threads = 8;
        int each = 2_000;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch go = new CountDownLatch(1);
        List<Future<?>> done = new ArrayList<>();
        try {
            for (int t = 0; t < threads; t++) {
                int id = t;
                done.add(pool.submit(() -> {
                    go.await();
                    for (int i = 0; i < each; i++) {
                        usage.record("t" + id + "-" + i, List.of(), i % 2 == 0 ? "login" : "admin.grant");
                    }
                    return null;
                }));
            }
            go.countDown();
            for (Future<?> f : done) {
                f.get(60, TimeUnit.SECONDS);
            }
        } finally {
            pool.shutdownNow();
        }
        assertThat(usage.inMemoryEventCount()).isEqualTo(100);
        Map<String, Object> view = usage.aggregate().block(WAIT);
        assertThat(view.get("totalEvents")).isEqualTo((long) threads * each);
        assertThat(moduleRow(view, "login-ui")).containsEntry("events", (long) threads * each / 2);
        assertThat(moduleRow(view, "admin-ui")).containsEntry("events", (long) threads * each / 2);
    }

    @Test
    void aNonPositiveCapacity_isRefusedAtConstruction() {
        assertThatThrownBy(() -> service(0)).isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("app.usage.in-memory-capacity");
    }

    /** The packaged application.yml documents the same default the code falls back to. */
    @Test
    void packagedYamlDefault_equalsTheCodeDefault() throws Exception {
        StandardEnvironment env = new StandardEnvironment();
        env.getPropertySources().remove(StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME);
        env.getPropertySources().remove(StandardEnvironment.SYSTEM_PROPERTIES_PROPERTY_SOURCE_NAME);
        for (PropertySource<?> ps : new YamlPropertySourceLoader()
                .load("application.yml", new ClassPathResource("application.yml"))) {
            env.getPropertySources().addLast(ps);
        }
        assertThat(Binder.get(env).bind("app.usage.in-memory-capacity", Integer.class).get())
                .isEqualTo(UsageService.DEFAULT_IN_MEMORY_CAPACITY);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> moduleRow(Map<String, Object> view, String module) {
        return ((List<Map<String, Object>>) view.get("byModule")).stream()
                .filter(r -> module.equals(r.get("module")))
                .findFirst()
                .orElseThrow(() -> new AssertionError("no byModule row for " + module + " in " + view));
    }
}
