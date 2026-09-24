package net.hugmesh.adminbff.suspension;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.homeserver.HomeserverAdminClient;
import net.hugmesh.adminbff.homeserver.HomeserverAdminConfig;
import net.hugmesh.adminbff.homeserver.HomeserverOutcome;
import net.hugmesh.adminbff.lease.AlwaysLeader;
import net.hugmesh.adminbff.matrixadmin.MatrixAdminConfig;
import net.hugmesh.adminbff.matrixadmin.MatrixAdminDeactivateClient;
import net.hugmesh.adminbff.matrixadmin.MatrixDeactivateProposalRepository;
import net.hugmesh.authcore.provision.GatewayRevocationClient;

/**
 * THE LOAD-BEARING SEPARATION of decision 83b (hugmesh-mod-bff-api#23): the access-suspension
 * reconciler must NEVER reach the one-way {@code !admin users deactivate}.
 *
 * <p>{@link MatrixAccessSyncAction#suspendHomeserver} calls
 * {@link HomeserverAdminClient#deactivateMatrix} for EVERY active ROLE_MATRIX suspension —
 * moderator bans included — and expects {@link HomeserverAdminClient#activateMatrix} to undo it
 * later. tuwunel has no activate verb, so if the ADMIN deactivate transport
 * ({@link MatrixAdminDeactivateClient}) were ever wired into that seam, every Matrix suspension
 * would become permanent. The existing {@code HomeserverAdminClientTest} cannot see that
 * mistake: it only watches the homeserver client's OWN tuwunel WebClient, and the new client
 * has its own.
 *
 * <p>Two independent witnesses:
 * <ol>
 *   <li>STRUCTURE — no compiled production class outside {@code net.hugmesh.adminbff.matrixadmin}
 *       refers to that package at all (constant-pool scan of {@code target/classes}), so there is
 *       no static path from the suspension code, the homeserver client or its config to the
 *       one-way verb.</li>
 *   <li>BEHAVIOUR — with BOTH gates armed ({@code homeserver.admin.enabled} and
 *       {@code matrix-admin.enabled}, admin token present) and BOTH WebClients routed to ONE
 *       recording stub, the reconciler's suspend and activate legs post nothing to tuwunel.</li>
 * </ol>
 */
@SpringBootTest(
        classes = {HomeserverAdminConfig.class, MatrixAdminConfig.class,
                MatrixSuspensionNeverDeactivatesTest.StubHttp.class},
        webEnvironment = SpringBootTest.WebEnvironment.NONE,
        properties = {
                "homeserver.admin.enabled=true",
                "homeserver.admin.tuwunel-url=http://tuwunel.invalid:8008",
                "homeserver.admin.akkoma-url=http://akkoma.invalid:4000",
                "matrix-admin.enabled=true",
                "matrix-admin.admin-token=armed-admin-token",
                "matrix-admin.base-url=http://tuwunel.invalid:8008"
        })
class MatrixSuspensionNeverDeactivatesTest {

    private static final String ONE_WAY_PACKAGE = "net/hugmesh/adminbff/matrixadmin/";

    /** Every outbound request from EITHER client lands here. */
    static final List<ClientRequest> SEEN = new CopyOnWriteArrayList<>();

    @Configuration(proxyBeanMethods = false)
    static class StubHttp {
        @Bean
        WebClient.Builder webClientBuilder() {
            return WebClient.builder().exchangeFunction(req -> {
                SEEN.add(req);
                return Mono.just(ClientResponse.create(HttpStatus.OK)
                        .header("Content-Type", "application/json")
                        .body("{\"room_id\":\"!adminroom:hugmesh.net\",\"event_id\":\"$evt\"}").build());
            });
        }
    }

    @MockitoBean MatrixDeactivateProposalRepository proposals;

    @Autowired HomeserverAdminClient homeserver;
    @Autowired MatrixAdminDeactivateClient oneWay;

    // ── witness 2: behaviour ──────────────────────────────────────────────────────

    @Test
    void armedSuspensionAndActivation_postNothingToTuwunel_evenWithTheOneWayVerbArmed() {
        // Positive control: the stub DOES capture the one-way client's traffic, so an empty
        // capture below is a real "nothing was sent", not a blind recorder.
        SEEN.clear();
        oneWay.deactivate("@control:hugmesh.net").block();
        assertThat(SEEN).as("positive control — the armed one-way client reaches the stub").isNotEmpty();
        SEEN.clear();

        MatrixAccessSyncAction reconciler = new MatrixAccessSyncAction(null, homeserver, null,
                new AlwaysLeader(), new GatewayRevocationClient(false, "http://localhost"));

        HomeserverOutcome suspended = reconciler.suspendHomeserver("banned-user").block();
        HomeserverOutcome restored = reconciler.activateHomeserver("banned-user").block();

        assertThat(SEEN).as("the reversible suspension seam must never post an admin-room command")
                .isEmpty();
        // And it stays a pending (re-appliable) suspension, never an applied one-way deactivate.
        assertThat(suspended.isOk()).isFalse();
        assertThat(restored.isOk()).isFalse();
    }

    // ── witness 1: structure ──────────────────────────────────────────────────────

    @Test
    void noProductionClassOutsideTheOneWayPackage_refersToIt() throws Exception {
        Path classes = classesRoot();
        List<String> offenders = new ArrayList<>();
        int scanned = 0;
        boolean sawHomeserverClient = false;
        boolean sawReconciler = false;
        boolean positiveControl = false;
        try (Stream<Path> files = Files.walk(classes)) {
            for (Path f : (Iterable<Path>) files.filter(p -> p.toString().endsWith(".class"))::iterator) {
                String rel = classes.relativize(f).toString().replace('\\', '/');
                // Class files are binary: decode as ISO-8859-1 so every byte survives, then look
                // for the package's internal name (constant pool) and its dotted form (reflection).
                String bytes = new String(Files.readAllBytes(f), StandardCharsets.ISO_8859_1);
                boolean refers = bytes.contains(ONE_WAY_PACKAGE)
                        || bytes.contains(ONE_WAY_PACKAGE.replace('/', '.'));
                if (rel.startsWith(ONE_WAY_PACKAGE)) {
                    positiveControl |= refers;
                    continue;
                }
                scanned++;
                sawHomeserverClient |= rel.equals("net/hugmesh/adminbff/homeserver/HomeserverAdminClient.class");
                sawReconciler |= rel.equals("net/hugmesh/adminbff/suspension/MatrixAccessSyncAction.class");
                if (refers) {
                    offenders.add(rel);
                }
            }
        }
        // The scan must be looking at the real tree, or an empty result proves nothing.
        assertThat(scanned).as("production classes scanned under %s", classes).isGreaterThan(200);
        assertThat(sawHomeserverClient).as("scan covered HomeserverAdminClient").isTrue();
        assertThat(sawReconciler).as("scan covered MatrixAccessSyncAction").isTrue();
        assertThat(positiveControl).as("the detector recognises a reference when one exists").isTrue();

        assertThat(offenders)
                .as("the one-way Matrix deactivate (%s) must be reachable ONLY from its own package; "
                        + "wiring it into the suspension seam makes every Matrix ban permanent",
                        ONE_WAY_PACKAGE)
                .isEmpty();
    }

    private static Path classesRoot() throws URISyntaxException, IOException {
        Path root = Path.of(HomeserverAdminClient.class.getProtectionDomain().getCodeSource()
                .getLocation().toURI());
        assertThat(Files.isDirectory(root)).as("main classes directory %s", root).isTrue();
        return root;
    }
}
