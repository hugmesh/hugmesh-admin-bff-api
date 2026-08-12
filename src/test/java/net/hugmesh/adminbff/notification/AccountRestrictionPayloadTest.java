package net.hugmesh.adminbff.notification;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

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
}
