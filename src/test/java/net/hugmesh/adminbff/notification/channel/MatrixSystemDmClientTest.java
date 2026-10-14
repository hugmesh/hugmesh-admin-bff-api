package net.hugmesh.adminbff.notification.channel;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.web.reactive.function.client.WebClient;
import net.hugmesh.adminbff.notification.SystemChannelTokens;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Contract tests for the real Matrix {@code @system} DM transport against
 * {@link FakeMatrixHomeserver} — a real HTTP server whose semantics were measured on a
 * tuwunel v1.7.0 container. The fake is the contract; {@code MatrixSystemDmClientLiveIT}
 * re-checks the same contract against a real homeserver when one is supplied.
 */
class MatrixSystemDmClientTest {

    private FakeMatrixHomeserver hs;

    @BeforeEach
    void up() throws Exception {
        hs = new FakeMatrixHomeserver();
    }

    @AfterEach
    void down() {
        hs.close();
    }

    private MatrixSystemDmClient client(String token) {
        return new MatrixSystemDmClient(WebClient.builder().baseUrl(hs.baseUrl()).build(),
                new SystemChannelTokens(token, "", "", ""), Duration.ofSeconds(5));
    }

    private MatrixSystemDmClient client() {
        return client(FakeMatrixHomeserver.SYSTEM_TOKEN);
    }

    // ── happy path: the exact wire sequence ──────────────────────────────────
    @Test
    void firstDm_whoami_profile_createDirectRoom_recordsMDirect_sendsMText() {
        ChannelOutcome out = client().sendDirectMessage("alice", "Title\n\nBody", "row-1").block();

        assertThat(out).isEqualTo(ChannelOutcome.SENT);
        assertThat(hs.requests).extracting(r -> r.method() + " " + r.path()).containsExactly(
                "GET /_matrix/client/v3/account/whoami",
                "GET /_matrix/client/v3/profile/@alice:probe.test",
                "GET /_matrix/client/v3/user/@system:probe.test/account_data/m.direct",
                "POST /_matrix/client/v3/createRoom",
                "PUT /_matrix/client/v3/user/@system:probe.test/account_data/m.direct",
                "PUT /_matrix/client/v3/rooms/!room1:probe.test/send/m.room.message/hm-row-1");
        // every call carries the @system bearer, and only that
        assertThat(hs.requests).allSatisfy(r -> assertThat(r.bearer()).isEqualTo(FakeMatrixHomeserver.SYSTEM_TOKEN));
        // createRoom is a private DM invite to exactly the recipient
        JsonNode create = hs.requests.get(3).body();
        assertThat(create.get("is_direct").asBoolean()).isTrue();
        assertThat(create.get("preset").asText()).isEqualTo("trusted_private_chat");
        assertThat(create.get("invite")).hasSize(1);
        assertThat(create.get("invite").get(0).asText()).isEqualTo("@alice:probe.test");
        // m.direct now maps the recipient to the room
        assertThat(hs.accountData.get("m.direct").get("@alice:probe.test").get(0).asText())
                .isEqualTo("!room1:probe.test");
        // m.text (NOT m.notice: clients suppress push for notices) carrying title + body
        assertThat(hs.events).hasSize(1);
        assertThat(hs.events.get(0).msgtype()).isEqualTo("m.text");
        assertThat(hs.events.get(0).body()).isEqualTo("Title\n\nBody");
    }

    // ── one DM room per recipient, across sends AND across a restart ─────────
    @Test
    void secondDm_reusesTheRoom_inMemory() {
        MatrixSystemDmClient c = client();
        assertThat(c.sendDirectMessage("alice", "one", "r1").block()).isEqualTo(ChannelOutcome.SENT);
        assertThat(c.sendDirectMessage("alice", "two", "r2").block()).isEqualTo(ChannelOutcome.SENT);

        assertThat(hs.createdRooms()).hasSize(1);
        assertThat(hs.events).extracting(FakeMatrixHomeserver.Event::room).containsOnly("!room1:probe.test");
        // identity is resolved once, not per send
        assertThat(hs.count("GET", "account/whoami")).isEqualTo(1);
    }

    @Test
    void afterRestart_reusesTheRoomFromMDirect_insteadOfCreatingAnother() {
        client().sendDirectMessage("alice", "one", "r1").block();
        // a brand-new client = a restarted pod: empty in-memory cache, same homeserver
        ChannelOutcome out = client().sendDirectMessage("alice", "two", "r2").block();

        assertThat(out).isEqualTo(ChannelOutcome.SENT);
        assertThat(hs.createdRooms()).hasSize(1);
        assertThat(hs.events).hasSize(2);
    }

    @Test
    void differentRecipients_getTheirOwnRooms() {
        MatrixSystemDmClient c = client();
        c.sendDirectMessage("alice", "a", "r1").block();
        c.sendDirectMessage("bob", "b", "r2").block();

        assertThat(hs.createdRooms()).hasSize(2);
        assertThat(hs.accountData.get("m.direct").get("@alice:probe.test")).hasSize(1);
        assertThat(hs.accountData.get("m.direct").get("@bob:probe.test")).hasSize(1);
    }

    // ── no Matrix account: terminal SKIP, and nothing is created ─────────────
    @Test
    void recipientWithoutAnAccount_isSkipped_andNoRoomOrMessageIsCreated() {
        // Measured on tuwunel: createRoom would have ACCEPTED an invite to this user (200),
        // so without the profile probe this would be recorded "sent" into a dead room.
        ChannelOutcome out = client().sendDirectMessage("ghost", "hello", "r1").block();

        assertThat(out).isEqualTo(ChannelOutcome.SKIPPED);
        assertThat(hs.count("POST", "createRoom")).isZero();
        assertThat(hs.count("PUT", "send")).isZero();
        assertThat(hs.events).isEmpty();
    }

    @Test
    void invalidLocalpart_isSkipped_withoutAnyRequest() {
        MatrixSystemDmClient c = client();
        for (String bad : new String[] {null, "", "  ", "al ice", "../etc", "ali?ce", "a/../b#", "A".repeat(300),
                "alice:evil.test", "@alice"}) {
            assertThat(c.sendDirectMessage(bad, "x", "r").block()).as("localpart=%s", bad)
                    .isEqualTo(ChannelOutcome.SKIPPED);
        }
        assertThat(hs.requests).isEmpty();
    }

    // ── idempotent retry: a lost reply must not duplicate the notification ───
    @Test
    void replyLostAfterCommit_retryWithSameKey_postsExactlyOneEvent() {
        MatrixSystemDmClient c = client();
        hs.dropNextSendReply = true;

        ChannelOutcome first = c.sendDirectMessage("alice", "hello", "outbox-42").block();
        assertThat(first).isEqualTo(ChannelOutcome.FAILED);          // reconciler will retry
        assertThat(hs.events).hasSize(1);                             // ...but it did commit

        ChannelOutcome retry = c.sendDirectMessage("alice", "hello", "outbox-42").block();
        assertThat(retry).isEqualTo(ChannelOutcome.SENT);
        assertThat(hs.events).as("same txn id => the homeserver dedupes").hasSize(1);
        assertThat(hs.events.get(0).txn()).isEqualTo("hm-outbox-42");
    }

    @Test
    void differentKeys_areDifferentEvents_evenWithIdenticalText() {
        MatrixSystemDmClient c = client();
        c.sendDirectMessage("alice", "same words", "k1").block();
        c.sendDirectMessage("alice", "same words", "k2").block();
        assertThat(hs.events).hasSize(2);
    }

    @Test
    void keyWithUnsafeCharacters_isSanitisedIntoAValidTxnId() {
        client().sendDirectMessage("alice", "x", "a/b c?d#e").block();
        assertThat(hs.events.get(0).txn()).isEqualTo("hm-a_b_c_d_e");
    }

    // ── failure mapping: always FAILED (retry), never SENT, never an exception ─
    @Test
    void wrongToken_isFailed_andStopsAtWhoami() {
        ChannelOutcome out = client("not-the-token").sendDirectMessage("alice", "x", "r").block();
        assertThat(out).isEqualTo(ChannelOutcome.FAILED);
        assertThat(hs.requests).hasSize(1);
        assertThat(hs.events).isEmpty();
    }

    @Test
    void absentToken_isFailed_withoutAnyRequest() {
        assertThat(client("").sendDirectMessage("alice", "x", "r").block()).isEqualTo(ChannelOutcome.FAILED);
        assertThat(hs.requests).isEmpty();
    }

    @Test
    void rateLimited_orServerError_onSend_isFailed() {
        hs.forcedStatus.put("PUT /send/m.room.message/hm-r1", 429);
        assertThat(client().sendDirectMessage("alice", "x", "r1").block()).isEqualTo(ChannelOutcome.FAILED);
        hs.forcedStatus.clear();
        hs.forcedStatus.put("PUT /send/m.room.message/hm-r2", 500);
        assertThat(client().sendDirectMessage("alice", "x", "r2").block()).isEqualTo(ChannelOutcome.FAILED);
        assertThat(hs.events).isEmpty();
    }

    @Test
    void profileProbeServerError_isFailed_notSkipped() {
        // A 5xx on the probe is "unknown", not "no account": retry, never a terminal skip.
        hs.forcedStatus.put("GET /profile/@alice:probe.test", 500);
        assertThat(client().sendDirectMessage("alice", "x", "r").block()).isEqualTo(ChannelOutcome.FAILED);
        assertThat(hs.count("POST", "createRoom")).isZero();
    }

    @Test
    void createRoomFailure_isFailed() {
        hs.forcedStatus.put("POST /createRoom", 500);
        assertThat(client().sendDirectMessage("alice", "x", "r").block()).isEqualTo(ChannelOutcome.FAILED);
        assertThat(hs.events).isEmpty();
    }

    @Test
    void mDirectWriteFailure_stillDelivers_andDoesNotCreateASecondRoomNextTime() {
        hs.forcedStatus.put("PUT /account_data/m.direct", 500);
        MatrixSystemDmClient c = client();
        assertThat(c.sendDirectMessage("alice", "one", "r1").block()).isEqualTo(ChannelOutcome.SENT);
        assertThat(c.sendDirectMessage("alice", "two", "r2").block()).isEqualTo(ChannelOutcome.SENT);
        assertThat(hs.createdRooms()).hasSize(1);
        assertThat(c.cachedRooms()).containsEntry("@alice:probe.test", "!room1:probe.test");
    }

    @Test
    void homeserverDown_isFailed_neverThrows() {
        MatrixSystemDmClient c = client();
        hs.close();
        assertThat(c.sendDirectMessage("alice", "x", "r").block()).isEqualTo(ChannelOutcome.FAILED);
    }

    // ── self-heal: the stored DM room is gone ────────────────────────────────
    @Test
    void roomWeCanNoLongerPostIn_isReplacedWithAFreshDm() {
        MatrixSystemDmClient c = client();
        c.sendDirectMessage("alice", "one", "r1").block();
        hs.deadRooms.add("!room1:probe.test");

        ChannelOutcome out = c.sendDirectMessage("alice", "two", "r2").block();

        assertThat(out).isEqualTo(ChannelOutcome.SENT);
        assertThat(hs.createdRooms()).hasSize(2);
        assertThat(hs.events.get(hs.events.size() - 1).room()).isEqualTo("!room2:probe.test");
        // the newest room is the one a restarted client will pick from m.direct
        JsonNode list = hs.accountData.get("m.direct").get("@alice:probe.test");
        assertThat(list.get(list.size() - 1).asText()).isEqualTo("!room2:probe.test");
    }

    @Test
    void afterRestart_withAReplacedRoomInMDirect_usesTheNewestOne() {
        MatrixSystemDmClient c = client();
        c.sendDirectMessage("alice", "one", "r1").block();
        hs.deadRooms.add("!room1:probe.test");
        c.sendDirectMessage("alice", "two", "r2").block();          // replaces room1 with room2
        assertThat(hs.createdRooms()).hasSize(2);

        // restarted pod: m.direct lists [room1 (dead), room2]; it must pick room2, not trip on room1
        ChannelOutcome out = client().sendDirectMessage("alice", "three", "r3").block();

        assertThat(out).isEqualTo(ChannelOutcome.SENT);
        assertThat(hs.createdRooms()).as("no third room").hasSize(2);
        assertThat(hs.events.get(hs.events.size() - 1).room()).isEqualTo("!room2:probe.test");
    }

    // ── identity cache is dropped when the token is rejected ─────────────────
    @Test
    void identityIsRefetched_afterA401() {
        MatrixSystemDmClient c = client();
        c.sendDirectMessage("alice", "one", "r1").block();
        hs.forcedStatus.put("GET /profile/@bob:probe.test", 401);
        assertThat(c.sendDirectMessage("bob", "x", "r2").block()).isEqualTo(ChannelOutcome.FAILED);
        hs.forcedStatus.clear();

        assertThat(c.sendDirectMessage("bob", "x", "r3").block()).isEqualTo(ChannelOutcome.SENT);
        assertThat(hs.count("GET", "account/whoami")).isEqualTo(2);
    }

    @Test
    void serverOf_keepsAPortInTheServerName() {
        assertThat(MatrixSystemDmClient.serverOf("@system:example.org:8448")).isEqualTo("example.org:8448");
        assertThat(MatrixSystemDmClient.serverOf("@system:probe.test")).isEqualTo("probe.test");
    }
}
