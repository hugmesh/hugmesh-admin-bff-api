package net.hugmesh.adminbff.matrixadmin;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;

/**
 * The ported admin-room transport, against a stub tuwunel (no socket). Pins the wire shape the
 * mod-bff-api MatrixAdminClient used — directory lookup, then a PUT of
 * {@code !admin users deactivate <mxid>} into the resolved room — and every degrade path.
 */
class MatrixAdminDeactivateClientTest {

    private static final String TOKEN = "vault-injected-admin-token";

    private static MatrixAdminDeactivateClient client(TuwunelStub stub, boolean enabled, String token) {
        return new MatrixAdminDeactivateClient(stub.webClient(), enabled, token, "hugmesh.net",
                "#admins:hugmesh.net", Duration.ofSeconds(2));
    }

    @Test
    void enabled_resolvesTheAdminRoom_thenPostsTheDeactivateCommandIntoIt() {
        TuwunelStub stub = new TuwunelStub();

        MatrixAdminOutcome outcome = client(stub, true, TOKEN).deactivate("@alice:hugmesh.net").block();

        assertThat(outcome).isEqualTo(MatrixAdminOutcome.posted("$evt-1"));
        assertThat(outcome.isPosted()).isTrue();
        assertThat(stub.seen).hasSize(2);

        TuwunelStub.Seen lookup = stub.seen.get(0);
        assertThat(lookup.method()).isEqualTo(HttpMethod.GET);
        assertThat(lookup.path()).isEqualTo("/_matrix/client/v3/directory/room/#admins:hugmesh.net");
        assertThat(lookup.authorization()).isEqualTo("Bearer " + TOKEN);

        TuwunelStub.Seen send = stub.seen.get(1);
        assertThat(send.method()).isEqualTo(HttpMethod.PUT);
        // The room id resolved above, and a fresh adminbff- transaction id.
        assertThat(send.path()).startsWith("/_matrix/client/v3/rooms/!adminroom:hugmesh.net/send/m.room.message/adminbff-");
        assertThat(send.authorization()).isEqualTo("Bearer " + TOKEN);
        assertThat(send.body())
                .contains("\"msgtype\":\"m.text\"")
                .contains("\"body\":\"!admin users deactivate @alice:hugmesh.net\"");
    }

    @Test
    void bareLocalpart_isQualifiedToTheConfiguredServerName() {
        TuwunelStub stub = new TuwunelStub();

        client(stub, true, TOKEN).deactivate("bob").block();

        assertThat(stub.sends()).singleElement()
                .satisfies(s -> assertThat(s.body()).contains("!admin users deactivate @bob:hugmesh.net\""));
    }

    @Test
    void theAdminRoomIsResolvedOnce_andReused() {
        TuwunelStub stub = new TuwunelStub();
        MatrixAdminDeactivateClient c = client(stub, true, TOKEN);

        c.deactivate("@a:hugmesh.net").block();
        c.deactivate("@b:hugmesh.net").block();

        assertThat(stub.lookups()).hasSize(1);
        assertThat(stub.sends()).hasSize(2);
        // Two distinct transaction ids (a repeated txnId would be de-duplicated by the server).
        assertThat(stub.sends().get(0).path()).isNotEqualTo(stub.sends().get(1).path());
    }

    @Test
    void disabled_isStubbed_andIssuesNoHttp() {
        TuwunelStub stub = new TuwunelStub();

        MatrixAdminOutcome outcome = client(stub, false, TOKEN).deactivate("@alice:hugmesh.net").block();

        assertThat(outcome).isEqualTo(MatrixAdminOutcome.STUBBED);
        assertThat(stub.seen).isEmpty();
    }

    @Test
    void enabledWithoutAnAdminToken_degrades_andNeverPostsUnauthenticated() {
        TuwunelStub stub = new TuwunelStub();

        MatrixAdminOutcome outcome = client(stub, true, "  ").deactivate("@alice:hugmesh.net").block();

        assertThat(outcome).isEqualTo(MatrixAdminOutcome.degraded("no-admin-token"));
        assertThat(stub.seen).isEmpty();
    }

    @Test
    void aTargetThatIsNotAPlainMxid_isNeverInterpolatedIntoTheCommand() {
        TuwunelStub stub = new TuwunelStub();
        MatrixAdminDeactivateClient c = client(stub, true, TOKEN);

        // Argument injection, a second command line, and shell-ish characters.
        for (String evil : new String[] {"alice --no-leave-rooms", "@alice:hugmesh.net\n!admin server shutdown",
                "@alice:hugmesh.net --force", "@al ice:hugmesh.net", "@alice:hugmesh.net;rm", ""}) {
            assertThat(c.deactivate(evil).block()).as(evil).isEqualTo(MatrixAdminOutcome.degraded("bad-target"));
        }
        assertThat(stub.seen).isEmpty();
    }

    @Test
    void aDirectoryReplyWithoutARoomId_degradesNoAdminRoom_andSendsNothing() {
        TuwunelStub stub = new TuwunelStub();
        stub.directoryBody = "{\"servers\":[\"hugmesh.net\"]}";

        assertThat(client(stub, true, TOKEN).deactivate("@alice:hugmesh.net").block())
                .isEqualTo(MatrixAdminOutcome.degraded("no-admin-room"));
        assertThat(stub.sends()).isEmpty();
    }

    @Test
    void aNon2xxSend_degradesWithTheStatus_andDropsTheCachedRoom() {
        TuwunelStub stub = new TuwunelStub();
        MatrixAdminDeactivateClient c = client(stub, true, TOKEN);
        stub.sendStatus = HttpStatus.FORBIDDEN;

        assertThat(c.deactivate("@alice:hugmesh.net").block()).isEqualTo(MatrixAdminOutcome.degraded("http-403"));

        stub.sendStatus = HttpStatus.OK;
        c.deactivate("@alice:hugmesh.net").block();
        // The failure cleared the cache, so the second call re-resolved the room.
        assertThat(stub.lookups()).hasSize(2);
    }

    @Test
    void aDirectoryFailure_degradesWithTheStatus() {
        TuwunelStub stub = new TuwunelStub();
        stub.directoryStatus = HttpStatus.NOT_FOUND;

        assertThat(client(stub, true, TOKEN).deactivate("@alice:hugmesh.net").block())
                .isEqualTo(MatrixAdminOutcome.degraded("http-404"));
        assertThat(stub.sends()).isEmpty();
    }

    @Test
    void a2xxSendWithoutAnEventId_isNotReportedAsPosted() {
        TuwunelStub stub = new TuwunelStub();
        stub.sendBody = "{}";

        assertThat(client(stub, true, TOKEN).deactivate("@alice:hugmesh.net").block())
                .isEqualTo(MatrixAdminOutcome.degraded("no-event-id"));
    }

    @Test
    void aHungHomeserver_degradesOnTheTimeout_ratherThanHangingTheConfirm() {
        TuwunelStub stub = new TuwunelStub();
        stub.hang = true;
        MatrixAdminDeactivateClient c = new MatrixAdminDeactivateClient(stub.webClient(), true, TOKEN,
                "hugmesh.net", "#admins:hugmesh.net", Duration.ofMillis(200));

        assertThat(c.deactivate("@alice:hugmesh.net").block(Duration.ofSeconds(5)))
                .isEqualTo(MatrixAdminOutcome.degraded("timeout"));
    }

    @Test
    void mxidNormalisation() {
        MatrixAdminDeactivateClient c = client(new TuwunelStub(), true, TOKEN);
        assertThat(c.mxid("@alice:hugmesh.net")).isEqualTo("@alice:hugmesh.net");
        assertThat(c.mxid("alice:hugmesh.net")).isEqualTo("@alice:hugmesh.net");
        assertThat(c.mxid(" alice ")).isEqualTo("@alice:hugmesh.net");
        assertThat(c.mxid("@alice:matrix.example.org:8448")).isEqualTo("@alice:matrix.example.org:8448");
        assertThat(c.mxid("alice bob")).isNull();
        assertThat(c.mxid(null)).isNull();
        MatrixAdminDeactivateClient noServer = new MatrixAdminDeactivateClient(new TuwunelStub().webClient(),
                true, TOKEN, "", "#admins:hugmesh.net", Duration.ofSeconds(1));
        assertThat(noServer.mxid("alice")).isNull();
    }
}
