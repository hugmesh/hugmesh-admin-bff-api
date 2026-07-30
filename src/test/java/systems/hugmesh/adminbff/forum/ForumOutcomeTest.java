package systems.hugmesh.adminbff.forum;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** The forum-console outcome record (mirrors AkkomaOutcome / HomeserverOutcome). */
class ForumOutcomeTest {

    @Test
    void stubbed_isStubbed_emptyPayload_markedInEnvelope() {
        ForumOutcome o = ForumOutcome.stubbed();
        assertThat(o.isStubbed()).isTrue();
        assertThat(o.isOk()).isFalse();
        assertThat(o.payload()).isEmpty();
        assertThat(o.asResponse()).containsExactly(Map.entry("result", "stubbed"));
    }

    @Test
    void ok_withPayload_mergesResultMarker() {
        ForumOutcome o = ForumOutcome.ok(Map.of("topics", 7, "posts", 42));
        assertThat(o.isOk()).isTrue();
        assertThat(o.isStubbed()).isFalse();
        assertThat(o.asResponse())
                .containsEntry("result", "ok")
                .containsEntry("topics", 7)
                .containsEntry("posts", 42);
    }

    @Test
    void ok_noBody_okWithEmptyPayload() {
        ForumOutcome o = ForumOutcome.ok();
        assertThat(o.isOk()).isTrue();
        assertThat(o.payload()).isEmpty();
        assertThat(o.asResponse()).containsEntry("result", "ok");
    }

    @Test
    void ok_nullPayload_isTolerated() {
        ForumOutcome o = ForumOutcome.ok(null);
        assertThat(o.isOk()).isTrue();
        assertThat(o.payload()).isEmpty();
    }

    @Test
    void degraded_carriesReason_neverOkNeverStubbed() {
        ForumOutcome o = ForumOutcome.degraded("circuit open");
        assertThat(o.isOk()).isFalse();
        assertThat(o.isStubbed()).isFalse();
        assertThat(o.result()).isEqualTo("degraded:circuit open");
        assertThat(o.asResponse()).containsEntry("result", "degraded:circuit open");
    }
}
