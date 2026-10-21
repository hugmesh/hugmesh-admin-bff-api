package net.hugmesh.adminbff.notification;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The account-restriction outbox payload builder. The load-bearing property is the
 * IDENTITY RULE: the builder takes no actor argument and the JSON it produces can never
 * contain the acting mod/admin identity — the {@code @system} sender is neutral.
 */
class AccountRestrictionPayloadTest {

    private static final ObjectMapper M = new ObjectMapper();

    @Test
    void build_carriesTargetRoleTtlReason_asValidJson() throws Exception {
        String json = AccountRestrictionPayload.build("alice", "PROFILE", 3600L, "abuse");
        JsonNode n = M.readTree(json);
        assertThat(n.get("target").asText()).isEqualTo("alice");
        assertThat(n.get("role").asText()).isEqualTo("PROFILE");
        assertThat(n.get("ttl_seconds").asLong()).isEqualTo(3600L);
        assertThat(n.get("permanent").asBoolean()).isFalse();
        assertThat(n.get("reason").asText()).isEqualTo("abuse");
    }

    @Test
    void build_nullTtl_marksPermanent() throws Exception {
        String json = AccountRestrictionPayload.build("bob", "PROFILE", null, null);
        JsonNode n = M.readTree(json);
        assertThat(n.get("permanent").asBoolean()).isTrue();
        assertThat(n.get("ttl_seconds").isNull()).isTrue();
        // No reason key when reason is null/blank.
        assertThat(n.has("reason")).isFalse();
    }

    @Test
    void build_neverContainsActorIdentity_byAnyFieldName() {
        // Even if a caller fat-fingers an actor-looking string into another slot, the
        // builder has NO actor parameter — there is no path for it into the payload.
        String json = AccountRestrictionPayload.build("victim", "ROLE_MATRIX", 60L, "spam");
        assertThat(json).doesNotContain("set_by");
        assertThat(json).doesNotContain("actor");
        assertThat(json).doesNotContain("mod");
        assertThat(json).doesNotContain("admin");
    }

    // ── notify_channels directive (issue #93) ──────────────────────────────

    @Test
    void build_absentOrEmptyDirective_isByteForByteTheFourArgForm() {
        String legacy = AccountRestrictionPayload.build("alice", "PROFILE", 3600L, "abuse");
        assertThat(AccountRestrictionPayload.build("alice", "PROFILE", 3600L, "abuse", null)).isEqualTo(legacy);
        assertThat(AccountRestrictionPayload.build("alice", "PROFILE", 3600L, "abuse", List.of())).isEqualTo(legacy);
        assertThat(legacy).doesNotContain("notify_channels");
    }

    @Test
    void build_directive_isWrittenAsCanonicalDedupedArray() throws Exception {
        // mastodon is mod-bff's name for the akkoma channel; case/whitespace/dupes collapse.
        String json = AccountRestrictionPayload.build("alice", "PROFILE", null, null,
                List.of("Email", " mastodon ", "email", "in-app"));
        JsonNode n = M.readTree(json);
        assertThat(n.get("notify_channels").isArray()).isTrue();
        assertThat(M.convertValue(n.get("notify_channels"), List.class))
                .containsExactly("email", "akkoma", "in-app");
        // the rest of the payload is untouched
        assertThat(n.get("target").asText()).isEqualTo("alice");
        assertThat(n.get("permanent").asBoolean()).isTrue();
    }

    @Test
    void build_unknownChannelNames_areIgnored_notRejected() throws Exception {
        String mixed = AccountRestrictionPayload.build("alice", "PROFILE", null, null,
                List.of("carrier-pigeon", "matrix"));
        assertThat(M.convertValue(M.readTree(mixed).get("notify_channels"), List.class))
                .containsExactly("matrix");
        // all-unknown leaves nothing: identical to no directive at all.
        assertThat(AccountRestrictionPayload.build("alice", "PROFILE", null, null, List.of("carrier-pigeon")))
                .isEqualTo(AccountRestrictionPayload.build("alice", "PROFILE", null, null));
    }

    @Test
    void build_directive_stillNeverContainsActorIdentity() {
        String json = AccountRestrictionPayload.build("victim", "ROLE_MATRIX", 60L, "spam", List.of("email"));
        assertThat(json).doesNotContain("set_by").doesNotContain("actor");
    }
}
