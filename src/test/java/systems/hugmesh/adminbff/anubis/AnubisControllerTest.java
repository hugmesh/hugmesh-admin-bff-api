package systems.hugmesh.adminbff.anubis;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

class AnubisControllerTest {

    // ── parsePrometheus ───────────────────────────────────────────────────

    @Test
    void parsePrometheus_emptyInput_returnsEmptyList() {
        assertThat(AnubisController.parsePrometheus("")).isEmpty();
        assertThat(AnubisController.parsePrometheus(null)).isEmpty();
    }

    @Test
    void parsePrometheus_skipsCommentsAndBlanks() {
        String text = """
                # HELP anubis_requests_total Total requests
                # TYPE anubis_requests_total counter

                anubis_requests_total 42
                """;
        List<Map<String, Object>> rows = AnubisController.parsePrometheus(text);
        assertThat(rows).hasSize(1);
        assertThat(rows.get(0).get("name")).isEqualTo("anubis_requests_total");
        assertThat(rows.get(0).get("value")).isEqualTo(42.0);
    }

    @Test
    void parsePrometheus_handlesLabels() {
        String text = "anubis_requests_total{action=\"challenge\"} 15\n";
        List<Map<String, Object>> rows = AnubisController.parsePrometheus(text);
        assertThat(rows).hasSize(1);
        assertThat(rows.get(0).get("name")).isEqualTo("anubis_requests_total");
        assertThat(rows.get(0).get("labels")).isEqualTo("action=\"challenge\"");
        assertThat(rows.get(0).get("value")).isEqualTo(15.0);
    }

    @Test
    void parsePrometheus_skipsNonNumericValues() {
        String text = "bad_metric NaN\ngood_metric 1.0\n";
        List<Map<String, Object>> rows = AnubisController.parsePrometheus(text);
        // NaN parses fine with Double.parseDouble — only truly non-numeric is skipped
        assertThat(rows).hasSize(2);
        assertThat(rows.get(1).get("name")).isEqualTo("good_metric");
    }

    @Test
    void parsePrometheus_handlesTimestampColumn() {
        // Prometheus text with optional timestamp: "name value timestamp"
        String text = "anubis_up 1 1718000000000\n";
        List<Map<String, Object>> rows = AnubisController.parsePrometheus(text);
        assertThat(rows).hasSize(1);
        assertThat(rows.get(0).get("value")).isEqualTo(1.0);
    }

    // ── status endpoint ───────────────────────────────────────────────────

    @Test
    void status_whenDisabled_returnsNotEnabledWithoutCallingClient() {
        AnubisClient client = mock(AnubisClient.class);
        AnubisController ctrl = controller(client, false);

        StepVerifier.create(ctrl.status())
                .assertNext(r -> {
                    assertThat(r.get("enabled")).isEqualTo(false);
                    assertThat(r.get("reachable")).isEqualTo(false);
                    assertThat(r.get("health")).isEqualTo("not-enabled");
                })
                .verifyComplete();

        verifyNoInteractions(client);
    }

    @Test
    void status_whenEnabledAndReachable_proxiesHealth() {
        AnubisClient client = mock(AnubisClient.class);
        when(client.health()).thenReturn(Mono.just("ok"));
        AnubisController ctrl = controller(client, true);

        StepVerifier.create(ctrl.status())
                .assertNext(r -> {
                    assertThat(r.get("enabled")).isEqualTo(true);
                    assertThat(r.get("reachable")).isEqualTo(true);
                    assertThat(r.get("health")).isEqualTo("ok");
                    assertThat(r.get("difficulty")).isEqualTo(5);
                })
                .verifyComplete();
    }

    @Test
    void status_whenEnabledButUnreachable_reachableIsFalse() {
        AnubisClient client = mock(AnubisClient.class);
        when(client.health()).thenReturn(Mono.just("unreachable"));
        AnubisController ctrl = controller(client, true);

        StepVerifier.create(ctrl.status())
                .assertNext(r -> assertThat(r.get("reachable")).isEqualTo(false))
                .verifyComplete();
    }

    // ── metrics endpoint ──────────────────────────────────────────────────

    @Test
    void metrics_whenDisabled_returnsEmptyWithoutCallingClient() {
        AnubisClient client = mock(AnubisClient.class);
        AnubisController ctrl = controller(client, false);

        StepVerifier.create(ctrl.metrics())
                .assertNext(r -> {
                    assertThat(r.get("enabled")).isEqualTo(false);
                    assertThat(r.get("raw")).isEqualTo("");
                    assertThat(r.get("metrics")).isEqualTo(List.of());
                })
                .verifyComplete();

        verifyNoInteractions(client);
    }

    @Test
    void metrics_whenEnabled_parsesPrometheusText() {
        AnubisClient client = mock(AnubisClient.class);
        when(client.metrics()).thenReturn(Mono.just("anubis_requests_total 99\n"));
        AnubisController ctrl = controller(client, true);

        StepVerifier.create(ctrl.metrics())
                .assertNext(r -> {
                    assertThat(r.get("enabled")).isEqualTo(true);
                    @SuppressWarnings("unchecked")
                    List<Map<String, Object>> metrics = (List<Map<String, Object>>) r.get("metrics");
                    assertThat(metrics).hasSize(1);
                    assertThat(metrics.get(0).get("name")).isEqualTo("anubis_requests_total");
                    assertThat(metrics.get(0).get("value")).isEqualTo(99.0);
                })
                .verifyComplete();
    }

    // ── helpers ───────────────────────────────────────────────────────────

    private static AnubisController controller(AnubisClient client, boolean enabled) {
        AnubisController ctrl = new AnubisController(client);
        try {
            var f = AnubisController.class.getDeclaredField("enabled");
            f.setAccessible(true);
            f.set(ctrl, enabled);
            var mu = AnubisController.class.getDeclaredField("managementUrl");
            mu.setAccessible(true);
            mu.set(ctrl, "http://localhost:9090");
            var d = AnubisController.class.getDeclaredField("difficulty");
            d.setAccessible(true);
            d.set(ctrl, 5);
        } catch (ReflectiveOperationException e) {
            throw new RuntimeException(e);
        }
        return ctrl;
    }
}
