package systems.hugmesh.adminbff.phone;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The Azure Intune (Graph) lock leg, proven against the client-credentials → remoteLock shape
 * with a recording {@link ExchangeFunction} (no live Graph — the same seam the
 * {@code HeadscalePolicyClientTest} uses):
 * <ul>
 *   <li>token-then-remoteLock happy path &rarr; APPLIED, and the two calls hit the Entra token
 *       endpoint then the Graph {@code managedDevices/{id}/remoteLock} path;</li>
 *   <li>a 500 on remoteLock &rarr; FAILED (channel actively rejected);</li>
 *   <li>a transport timeout &rarr; UNREACHABLE (best-effort degrade);</li>
 *   <li>it NEVER throws;</li>
 *   <li>the client SECRET never appears in any request URL/query, nor in any log line;</li>
 *   <li>{@code appliesTo} matches ONLY an azure-intune device;</li>
 *   <li>unlock is the documented no-op (DISABLED, no Graph call) — the control plane clears its
 *       own lock, the handset is not force-unlocked.</li>
 * </ul>
 */
class AzureIntuneLockClientTest {

    private static final String SECRET = "s3cr3t-confidential-client-value";

    private static final PhoneDevice AZURE_DEVICE = device("azure-intune", "intune-managed-id-42");
    private static final PhoneDevice HEADWIND_DEVICE = device("headwind", null);

    private static PhoneDevice device(String provider, String intuneId) {
        return new PhoneDevice("pd", "phone-x", "phone", null, "oriole", null, null, null, null,
                null, null, "phone-host", null, null, false, null, null, false, null, null,
                null, null, null, null, null, null, null, Instant.now(), Instant.now(), 1L,
                "mesh_owned", "locked", "pending", 5L, "r", "sa", Instant.now(), null, null,
                provider, intuneId);
    }

    /** Records outgoing requests and returns canned Entra-token / Graph-remoteLock responses. */
    static class Recorder implements ExchangeFunction {
        final List<ClientRequest> requests = new ArrayList<>();
        HttpStatus tokenStatus = HttpStatus.OK;
        HttpStatus lockStatus = HttpStatus.OK;
        String accessToken = "eyJ-fake-access-token";
        Duration delay = Duration.ZERO;

        @Override
        public Mono<ClientResponse> exchange(ClientRequest request) {
            requests.add(request);
            Mono<ClientResponse> resp;
            if (request.url().getPath().endsWith("/token")) {
                resp = Mono.just(ClientResponse.create(tokenStatus)
                        .header("Content-Type", "application/json")
                        .body(tokenStatus.is2xxSuccessful()
                                ? "{\"token_type\":\"Bearer\",\"expires_in\":3599,"
                                  + "\"access_token\":\"" + accessToken + "\"}"
                                : "{\"error\":\"invalid_client\"}")
                        .build());
            } else {
                resp = Mono.just(ClientResponse.create(lockStatus)
                        .header("Content-Type", "application/json")
                        .body(lockStatus.is2xxSuccessful() ? "" : "{\"error\":{\"code\":\"denied\"}}")
                        .build());
            }
            return delay.isZero() ? resp : Mono.delay(delay).then(resp);
        }
    }

    private static AzureIntuneLockClient client(Recorder rec, long timeoutMs) {
        WebClient web = WebClient.builder().exchangeFunction(rec).build();
        return new AzureIntuneLockClient(web, "tenant-abc", "client-abc", SECRET,
                "https://graph.example.test/v1.0", "https://login.example.test", timeoutMs);
    }

    // ── log capture (the secret must never be logged) ────────────────────────────
    private Logger rootLogger;
    private ListAppender<ILoggingEvent> appender;

    @BeforeEach
    void attachAppender() {
        rootLogger = (Logger) LoggerFactory.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
        appender = new ListAppender<>();
        appender.list = new java.util.concurrent.CopyOnWriteArrayList<>();
        appender.start();
        rootLogger.addAppender(appender);
        rootLogger.setLevel(Level.TRACE);
    }

    @AfterEach
    void detachAppender() {
        rootLogger.detachAppender(appender);
    }

    private void assertNoSecretAnywhere(Recorder rec) {
        // Never in a URL or its query string.
        for (ClientRequest req : rec.requests) {
            assertThat(req.url().toString()).doesNotContain(SECRET);
            assertThat(req.url().getQuery() == null ? "" : req.url().getQuery())
                    .doesNotContain(SECRET);
        }
        // Never in any log line.
        for (ILoggingEvent ev : appender.list) {
            assertThat(ev.getFormattedMessage()).doesNotContain(SECRET);
        }
    }

    @Test
    void happyPath_tokenThenRemoteLock_applied() {
        Recorder rec = new Recorder();
        PhoneLockLeg.LegOutcome o = client(rec, 8000).lock(AZURE_DEVICE).block();

        assertThat(o).isNotNull();
        assertThat(o.isApplied()).isTrue();
        // Two calls: the Entra token endpoint, then the Graph remoteLock.
        assertThat(rec.requests).hasSize(2);
        ClientRequest token = rec.requests.get(0);
        assertThat(token.method().name()).isEqualTo("POST");
        assertThat(token.url().getPath()).isEqualTo("/tenant-abc/oauth2/v2.0/token");
        ClientRequest lock = rec.requests.get(1);
        assertThat(lock.method().name()).isEqualTo("POST");
        assertThat(lock.url().getPath())
                .isEqualTo("/v1.0/deviceManagement/managedDevices/intune-managed-id-42/remoteLock");
        assertThat(lock.headers().getFirst("Authorization"))
                .isEqualTo("Bearer " + rec.accessToken);
        assertNoSecretAnywhere(rec);
    }

    @Test
    void remoteLock500_failed() {
        Recorder rec = new Recorder();
        rec.lockStatus = HttpStatus.INTERNAL_SERVER_ERROR;   // Graph rejects the command
        PhoneLockLeg.LegOutcome o = client(rec, 8000).lock(AZURE_DEVICE).block();

        assertThat(o).isNotNull();
        assertThat(o.isFailed()).isTrue();                    // 5xx = hard reject
        assertThat(o.detail()).contains("500");
        assertNoSecretAnywhere(rec);
    }

    @Test
    void tokenEndpoint401_failed() {
        Recorder rec = new Recorder();
        rec.tokenStatus = HttpStatus.UNAUTHORIZED;            // bad client credentials
        PhoneLockLeg.LegOutcome o = client(rec, 8000).lock(AZURE_DEVICE).block();

        assertThat(o).isNotNull();
        assertThat(o.isFailed()).isTrue();
        assertThat(o.detail()).contains("401");
        // The remoteLock is never attempted once the token 4xx-rejects.
        assertThat(rec.requests).hasSize(1);
        assertNoSecretAnywhere(rec);
    }

    @Test
    void transportTimeout_unreachable() {
        Recorder rec = new Recorder();
        rec.delay = Duration.ofMillis(400);                   // slower than the client timeout
        PhoneLockLeg.LegOutcome o = client(rec, 50).lock(AZURE_DEVICE).block();

        assertThat(o).isNotNull();
        assertThat(o.isUnreachable()).isTrue();               // timeout degrades, never fails hard
        assertNoSecretAnywhere(rec);
    }

    @Test
    void noIntuneDeviceId_unreachable_neverCalls() {
        Recorder rec = new Recorder();
        PhoneDevice noId = device("azure-intune", null);
        PhoneLockLeg.LegOutcome o = client(rec, 8000).lock(noId).block();

        assertThat(o).isNotNull();
        assertThat(o.isUnreachable()).isTrue();
        assertThat(rec.requests).isEmpty();                   // no Graph id to target
    }

    @Test
    void appliesTo_onlyAzureDevice() {
        Recorder rec = new Recorder();
        AzureIntuneLockClient c = client(rec, 8000);
        assertThat(c.appliesTo(AZURE_DEVICE)).isTrue();
        assertThat(c.appliesTo(HEADWIND_DEVICE)).isFalse();
    }

    @Test
    void unlock_isDocumentedNoOp_disabled_noGraphCall() {
        Recorder rec = new Recorder();
        PhoneLockLeg.LegOutcome o = client(rec, 8000).unlock(AZURE_DEVICE).block();

        assertThat(o).isNotNull();
        assertThat(o.isDisabled()).isTrue();                  // Intune has no native unlock
        assertThat(rec.requests).isEmpty();                   // NO Graph call issued
    }

    @Test
    void neverThrows_evenOnBlankToken() {
        Recorder rec = new Recorder();
        rec.accessToken = "";                                 // 2xx token but no token value
        PhoneLockLeg.LegOutcome o = client(rec, 8000).lock(AZURE_DEVICE).block();

        assertThat(o).isNotNull();
        assertThat(o.isFailed()).isTrue();                    // missing access_token = hard fail
        assertThat(rec.requests).hasSize(1);                  // never reached remoteLock
        assertNoSecretAnywhere(rec);
    }
}
