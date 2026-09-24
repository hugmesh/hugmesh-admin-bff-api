package net.hugmesh.adminbff.usage;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.security.RoleName;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Usage analytics — reactive. Every meaningful action ({@code register},
 * {@code login}, {@code complete}, {@code matrix.entitled}, {@code admin.invite},
 * {@code admin.grant}, {@code admin.route}, …) is recorded; the admin Usage view
 * aggregates by module and action.
 *
 * <p><b>Kafka is the durable bus.</b> When {@code app.kafka.enabled=true} a
 * {@link KafkaTemplate} is wired and {@link #record} PRODUCES the usage event to
 * the {@code app.kafka.topic.usage-events} topic — the BFF dogfoods its own bus;
 * the durable consumer ({@code UsageEventConsumer}) then writes the row to
 * ClickHouse. When Kafka is disabled / unwired, {@link #record} falls back to a
 * CLEARLY-MARKED DEGRADED MODE: a direct ClickHouse write. An in-memory log is
 * always kept so the {@code /bff/admin/usage} view still reflects this run when
 * ClickHouse is empty/unreachable.
 *
 * <p>ClickHouse access is reactive (WebClient); the aggregate queries return the
 * exact JSON shape the admin Usage view expects
 * ({@code {byModule, byAction, activeUsers, totalEvents}}).
 */
@Service
public class UsageService {

    private static final Logger log = LoggerFactory.getLogger(UsageService.class);

    static final Map<String, String> MODULE_OF = Map.ofEntries(
            Map.entry("login", "login-ui"), Map.entry("register", "login-ui"),
            Map.entry("complete", "login-ui"), Map.entry("admin.invite", "admin-ui"),
            Map.entry("admin.grant", "admin-ui"), Map.entry("admin.route", "admin-ui"),
            Map.entry("matrix.entitled", "matrix-ui"), Map.entry("mastodon.entitled", "mastodon-ui"),
            // ── FORUM ──────────────────────────────────────────────────────
            // Two stats truths: PLATFORM usage = these events (forum-ui content
            // actions + admin-ui forum-console actions) aggregated from ClickHouse
            // with the in-memory fallback; FORUM CONTENT counts (topics/posts/active
            // users/queue depth) are read live from the phpBB extension /stats (the
            // ForumAdminController GET /stats surface), NOT from these events.
            // forum-ui content actions (the forum-bff producer path emits these).
            Map.entry("forum.post", "forum-ui"), Map.entry("forum.reply", "forum-ui"),
            Map.entry("forum.login", "forum-ui"), Map.entry("forum.topic", "forum-ui"),
            // admin-ui Forum Console actions (recorded by ForumAdminController).
            Map.entry("admin.forum.stats", "admin-ui"), Map.entry("admin.forum.usage", "admin-ui"),
            Map.entry("admin.forum.users", "admin-ui"), Map.entry("admin.forum.user", "admin-ui"),
            Map.entry("admin.forum.ban", "admin-ui"), Map.entry("admin.forum.unban", "admin-ui"),
            Map.entry("admin.forum.group", "admin-ui"),
            Map.entry("admin.forum.categories", "admin-ui"),
            Map.entry("admin.forum.category.create", "admin-ui"),
            Map.entry("admin.forum.moderation-queue", "admin-ui"),
            Map.entry("admin.forum.moderation.approve", "admin-ui"),
            Map.entry("admin.forum.moderation.reject", "admin-ui"),
            Map.entry("admin.forum.style.install", "admin-ui"),
            Map.entry("admin.forum.extension.install", "admin-ui"),
            Map.entry("admin.forum.audit", "admin-ui"));

    /** Shipped default for {@code app.usage.in-memory-capacity} (the ring size). */
    static final int DEFAULT_IN_MEMORY_CAPACITY = 10_000;

    // ── In-memory fallback log: BOUNDED (decision 105 = A, hugmesh-admin-bff-api#105) ──
    // A fixed-capacity ring of the most recent events plus separate running counters. The
    // counters keep totalEvents and the per-module event counts EXACT for the life of the
    // process; the ring (and so the fallback's distinct-users-per-module, active-in-last-hour
    // and per-action figures) covers only the last `memCapacity` events. Per-module counters
    // are safe to keep exactly because the module set is closed (MODULE_OF values + "host");
    // per-action counts are NOT kept as exact counters because `action` is caller-supplied
    // (POST /bff/internal/usage) and an exact map keyed on it would be unbounded again.
    // All four fields are guarded by `memLock` so a fallback snapshot is self-consistent.
    private final Object memLock = new Object();
    private final int memCapacity;
    private final ArrayDeque<UsageEvent> mem;
    private long memTotal;
    private final Map<String, Long> memModuleEvents = new HashMap<>();

    private final ObjectMapper json = new ObjectMapper();

    private final WebClient ch;
    private final String topic;
    @Nullable private final KafkaTemplate<String, String> kafka;

    public UsageService(
            @Value("${clickhouse.url:http://clickhouse:8123}") String chUrl,
            @Value("${clickhouse.user:snap}") String chUser,
            @Value("${clickhouse.password:snap}") String chPass,
            @Value("${app.kafka.topic.usage-events:usage_events}") String topic,
            @Nullable KafkaTemplate<String, String> kafka,
            @Value("${app.usage.in-memory-capacity:" + DEFAULT_IN_MEMORY_CAPACITY + "}") int inMemoryCapacity) {
        if (inMemoryCapacity < 1) {
            throw new IllegalArgumentException(
                    "app.usage.in-memory-capacity must be >= 1, got " + inMemoryCapacity);
        }
        this.memCapacity = inMemoryCapacity;
        this.mem = new ArrayDeque<>(Math.min(inMemoryCapacity, 1024));
        WebClient.Builder b = WebClient.builder().baseUrl(chUrl);
        if (chUser != null && !chUser.isBlank()) {
            String basic = Base64.getEncoder().encodeToString((chUser + ":" + chPass).getBytes());
            b.defaultHeader(HttpHeaders.AUTHORIZATION, "Basic " + basic);
        }
        this.ch = b.build();
        this.topic = topic;
        this.kafka = kafka;
    }

    public static String moduleOf(String action) {
        return MODULE_OF.getOrDefault(action, "host");
    }

    /**
     * Record one usage event. Always logged in-memory (bounded: the ring keeps the last
     * {@code app.usage.in-memory-capacity} events, the counters stay exact); then — if Kafka is the bus
     * — PRODUCED to the usage-event topic (the consumer persists it); otherwise
     * written DIRECTLY to ClickHouse as a degraded fallback. Returns a Mono the
     * caller may subscribe to; callers on the request path fire-and-forget.
     */
    public Mono<Void> record(String actor, List<String> roles, String action) {
        // The recorded role collapses to one of the CLOSED base tokens: an admin
        // actor's event is tagged "admin", everything else floors to "user". The
        // tokens come from the RoleName enum so the comparison key + emitted value
        // stay byte-identical to the prior "admin"/"user" literals (the ClickHouse
        // `role` column + UsageEvent JSON are unchanged).
        String role = roles != null && roles.contains(RoleName.ADMIN.value())
                ? RoleName.ADMIN.value() : RoleName.USER.value();
        String module = moduleOf(action);
        UsageEvent event = new UsageEvent(String.valueOf(actor), role, action, module,
                System.currentTimeMillis());
        remember(event);

        if (kafka != null) {
            // Kafka is the durable bus: produce + let the consumer write ClickHouse.
            return Mono.fromFuture(kafka.send(topic, event.actor(), toJson(event))
                            .toCompletableFuture())
                    .then()
                    .doOnError(e -> log.warn("[usage] kafka produce failed for {}: {}", action, e.toString()))
                    .onErrorResume(e -> insert(event));   // last-resort degraded write
        }
        // DEGRADED MODE (no Kafka bus): direct ClickHouse write, best-effort.
        return insert(event)
                .onErrorResume(e -> {
                    log.debug("[usage] degraded direct clickhouse insert skipped: {}", e.toString());
                    return Mono.empty();
                })
                .then();
    }

    /**
     * Persist one event to ClickHouse (the same INSERT the consumer issues).
     * Public so {@code UsageEventConsumer} can call it directly off the Kafka
     * listener thread (non-blocking WebClient write).
     */
    public Mono<Void> insert(UsageEvent e) {
        String sql = "INSERT INTO hugmesh.usage_events (actor, role, action, module) VALUES ('"
                + esc(e.actor()) + "','" + e.role() + "','" + esc(e.action()) + "','" + e.module() + "')";
        return exec(sql).then();
    }

    /** The admin Usage view payload. Tries ClickHouse; falls back to in-memory. */
    public Mono<Map<String, Object>> aggregate() {
        Mono<List<JsonNode>> byModule = chJson(
                "SELECT module, count() AS events, uniqExact(actor) AS users "
                + "FROM hugmesh.usage_events GROUP BY module ORDER BY events DESC");
        Mono<List<JsonNode>> byAction = chJson(
                "SELECT action, count() AS events FROM hugmesh.usage_events "
                + "GROUP BY action ORDER BY events DESC");
        Mono<Long> active = chScalar("SELECT uniqExact(actor) AS n FROM hugmesh.usage_events "
                + "WHERE ts > now() - INTERVAL 1 HOUR");
        Mono<Long> total = chScalar("SELECT count() AS n FROM hugmesh.usage_events");

        return Mono.zip(byModule, byAction, active, total)
                .map(t -> {
                    long totalEvents = t.getT4();
                    if (totalEvents <= 0) return fromMemory();
                    Map<String, Object> out = new LinkedHashMap<>();
                    out.put("byModule", t.getT1().stream().map(UsageService::objModule).toList());
                    out.put("byAction", t.getT2().stream().map(UsageService::objAction).toList());
                    out.put("activeUsers", t.getT3());
                    out.put("totalEvents", totalEvents);
                    return out;
                })
                .onErrorResume(e -> {
                    log.debug("[usage] clickhouse unavailable, using in-memory: {}", e.toString());
                    return Mono.just(fromMemory());
                });
    }

    /** Append to the bounded ring (evicting the oldest at capacity) and bump the exact counters. */
    private void remember(UsageEvent event) {
        synchronized (memLock) {
            if (mem.size() >= memCapacity) {
                mem.pollFirst();
            }
            mem.addLast(event);
            memTotal++;
            memModuleEvents.merge(event.module(), 1L, Long::sum);
        }
    }

    /** Test seam: how many events the ring currently holds (never more than the capacity). */
    int inMemoryEventCount() {
        synchronized (memLock) {
            return mem.size();
        }
    }

    // ── In-memory fallback aggregation (mirrors mock usageFromMemory) ───
    //
    // Exact, from the counters: totalEvents and byModule[].events.
    // Over the last N events only (N = app.usage.in-memory-capacity, reported as
    // windowEvents): byModule[].users (distinct actors), byAction, activeUsers (distinct
    // actors in the last hour). A module whose events have all aged out of the ring still
    // shows its exact event count, with users = 0.
    Map<String, Object> fromMemory() {
        List<UsageEvent> window;
        long total;
        Map<String, Long> moduleEvents;
        synchronized (memLock) {
            window = new ArrayList<>(mem);
            total = memTotal;
            moduleEvents = new LinkedHashMap<>(memModuleEvents);
        }
        long hourAgo = System.currentTimeMillis() - 3_600_000L;
        Map<String, Set<String>> modUsers = new HashMap<>();
        Map<String, long[]> actEvents = new LinkedHashMap<>();
        Set<String> recent = new HashSet<>();
        for (UsageEvent e : window) {
            modUsers.computeIfAbsent(e.module(), k -> new HashSet<>()).add(e.actor());
            actEvents.computeIfAbsent(e.action(), k -> new long[1])[0]++;
            if (e.ts() > hourAgo) recent.add(e.actor());
        }
        List<Map<String, Object>> byModule = new ArrayList<>();
        moduleEvents.forEach((m, c) -> {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("module", m);
            row.put("events", c);
            Set<String> users = modUsers.get(m);
            row.put("users", users == null ? 0 : users.size());
            byModule.add(row);
        });
        byModule.sort((a, b) -> Long.compare((Long) b.get("events"), (Long) a.get("events")));
        List<Map<String, Object>> byAction = new ArrayList<>();
        actEvents.forEach((a, c) -> {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("action", a);
            row.put("events", c[0]);
            byAction.add(row);
        });
        byAction.sort((a, b) -> Long.compare((Long) b.get("events"), (Long) a.get("events")));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("byModule", byModule);
        out.put("byAction", byAction);
        out.put("activeUsers", recent.size());
        out.put("totalEvents", total);
        out.put("source", "in-memory");
        out.put("windowEvents", window.size());
        return out;
    }

    private static Map<String, Object> objModule(JsonNode n) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("module", n.path("module").asText());
        m.put("events", n.path("events").asLong());
        m.put("users", n.path("users").asLong());
        return m;
    }

    private static Map<String, Object> objAction(JsonNode n) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("action", n.path("action").asText());
        m.put("events", n.path("events").asLong());
        return m;
    }

    // ── ClickHouse HTTP (reactive, best-effort) ────────────────────────
    private Mono<String> exec(String sql) {
        return ch.post().uri("/")
                .contentType(MediaType.TEXT_PLAIN)
                .bodyValue(sql)
                .retrieve()
                .bodyToMono(String.class);
    }

    private Mono<List<JsonNode>> chJson(String sql) {
        // fromCallable wraps JsonProcessingException as onError automatically; .map→.flatMap
        return exec(sql + " FORMAT JSON").flatMap(body -> Mono.fromCallable(() -> {
            JsonNode root = json.readTree(body);
            List<JsonNode> out = new ArrayList<>();
            root.path("data").forEach(out::add);
            return out;
        }));
    }

    private Mono<Long> chScalar(String sql) {
        return chJson(sql).map(rows -> rows.isEmpty() ? 0L : rows.get(0).path("n").asLong());
    }

    private String toJson(UsageEvent e) {
        try {
            return json.writeValueAsString(e);
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    private static String esc(Object s) {
        return String.valueOf(s).replace("'", "\\'");
    }
}
