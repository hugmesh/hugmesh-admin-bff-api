package net.hugmesh.adminbff.servicecatalog;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import net.hugmesh.adminbff.web.FieldValidationException;

import java.time.Instant;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * {@link AppProfileService} validates {@code profileJson} against the committed schema BEFORE the
 * write, on POST and on PUT (issue #55). Un-parked by operator decision 37 (2026-09-17).
 *
 * <p>The behaviours that matter are as much about what does NOT happen:
 * <ul>
 *   <li>a refusal NEVER touches the repository — no partial write, no row created and rolled back;</li>
 *   <li>a valid body is stored VERBATIM — the service is a gate, not a formatter;</li>
 *   <li>reads NEVER validate, so a row written before the schema existed stays readable and
 *       editable (it is reported, never rewritten).</li>
 * </ul>
 */
class AppProfileServiceSchemaValidationTest {

    private AppProfileRepository repo;
    private AppProfileService service;

    private static final String VALID = "{\"resources\":{\"cpu\":\"500m\",\"memory\":\"512Mi\"}}";
    /** The known pre-schema shape: the flat cpu/memory pair the editor defaulted before #13. */
    private static final String LEGACY = "{\"cpu\":\"500m\",\"memory\":\"512Mi\"}";

    private static AppProfile row(String profileJson) {
        return new AppProfile("ap-1", "small-postgres", profileJson, "superadmin-subject-9",
                Instant.now(), Instant.now());
    }

    @BeforeEach
    void setUp() {
        repo = mock(AppProfileRepository.class);
        service = new AppProfileService(repo);
    }

    // ── create (POST) ───────────────────────────────────────────────────────────

    @Test
    void create_withAValidProfile_storesTheTextVerbatim() {
        when(repo.findByName("small-postgres")).thenReturn(Mono.empty());
        when(repo.insert(eq("small-postgres"), eq(VALID), eq("sub"))).thenReturn(Mono.just(row(VALID)));

        StepVerifier.create(service.create("small-postgres", VALID, "sub"))
                .assertNext(p -> assertThat(p.profileJson()).isEqualTo(VALID))
                .verifyComplete();

        verify(repo).insert("small-postgres", VALID, "sub");
    }

    @Test
    void create_withABodyTheConsoleWouldRefuse_is400WithEveryPathNamed_andNeverWrites() {
        StepVerifier.create(service.create("small-postgres",
                        "{\"resources\":{\"cpu\":\"lots\"},\"roles\":[\"admin\"],\"bogus\":1}", "sub"))
                .consumeErrorWith(e -> {
                    assertThat(e).isInstanceOf(FieldValidationException.class);
                    Map<String, String> fields = ((FieldValidationException) e).fields();
                    assertThat(fields).containsOnlyKeys("resources.cpu", "roles[0]", "bogus");
                    assertThat(fields.get("bogus"))
                            .isEqualTo("unknown field (allowed here: resources, roles, certs, exposure)");
                })
                .verify();

        verify(repo, never()).insert(anyString(), any(), anyString());
        verify(repo, never()).findByName(anyString());
    }

    @Test
    void create_withTheLegacyFlatBody_isRefused() {
        StepVerifier.create(service.create("small-postgres", LEGACY, "sub"))
                .expectError(FieldValidationException.class)
                .verify();
        verify(repo, never()).insert(anyString(), any(), anyString());
    }

    @Test
    void create_withADuplicateKey_isRefused_theOneClassTheConsoleCannotCatch() {
        StepVerifier.create(service.create("small-postgres",
                        "{\"resources\":{\"cpu\":\"500m\",\"cpu\":\"2\"}}", "sub"))
                .consumeErrorWith(e -> assertThat(((FieldValidationException) e).fields())
                        .containsOnlyKeys("$"))
                .verify();
        verify(repo, never()).insert(anyString(), any(), anyString());
    }

    @Test
    void create_withTheTrailingNewlineTheFindTrapWouldAccept_isRefused() {
        StepVerifier.create(service.create("small-postgres", "{\"resources\":{\"cpu\":\"500m\\n\"}}", "sub"))
                .consumeErrorWith(e -> assertThat(((FieldValidationException) e).fields())
                        .containsOnlyKeys("resources.cpu"))
                .verify();
        verify(repo, never()).insert(anyString(), any(), anyString());
    }

    @Test
    void create_withNullOrBlankProfileJson_isTheMinimalProfileAndStillStoresWhatWasSent() {
        when(repo.findByName(anyString())).thenReturn(Mono.empty());
        when(repo.insert(anyString(), any(), anyString())).thenReturn(Mono.just(row(null)));

        StepVerifier.create(service.create("a", null, "sub")).expectNextCount(1).verifyComplete();
        StepVerifier.create(service.create("b", "   ", "sub")).expectNextCount(1).verifyComplete();

        // Stored as sent — the service validates, it does not normalise.
        verify(repo).insert("a", null, "sub");
        verify(repo).insert("b", "   ", "sub");
    }

    @Test
    void create_stillChecksTheNameFirst() {
        // A blank name with an invalid body reports the NAME problem: the cheap, unambiguous
        // refusal the endpoint already had keeps its place at the front.
        StepVerifier.create(service.create("  ", "{\"bogus\":1}", "sub"))
                .consumeErrorWith(e -> assertThat(e).isNotInstanceOf(FieldValidationException.class))
                .verify();
    }

    // ── update (PUT) ────────────────────────────────────────────────────────────

    @Test
    void update_withAValidProfile_writes() {
        when(repo.findByName("small-postgres")).thenReturn(Mono.just(row(LEGACY)));
        when(repo.updateJson("small-postgres", VALID)).thenReturn(Mono.just(row(VALID)));

        StepVerifier.create(service.update("small-postgres", VALID))
                .assertNext(p -> assertThat(p.profileJson()).isEqualTo(VALID))
                .verifyComplete();
    }

    @Test
    void update_withAnInvalidProfile_is400_andNeverLooksTheRowUp() {
        StepVerifier.create(service.update("small-postgres", "{\"exposure\":{\"ports\":[0,70000]}}"))
                .consumeErrorWith(e -> assertThat(((FieldValidationException) e).fields())
                        .containsOnlyKeys("exposure.ports[0]", "exposure.ports[1]"))
                .verify();

        verify(repo, never()).findByName(anyString());
        verify(repo, never()).updateJson(anyString(), any());
    }

    @Test
    void update_cannotMoveARowFromAValidBodyToAnInvalidOne() {
        StepVerifier.create(service.update("small-postgres", LEGACY))
                .expectError(FieldValidationException.class)
                .verify();
        verify(repo, never()).updateJson(anyString(), any());
    }

    // ── reads: report, never rewrite, never refuse ──────────────────────────────

    @Test
    void list_returnsAPreSchemaRowUNCHANGED() {
        when(repo.findAll()).thenReturn(Flux.just(row(LEGACY)));

        StepVerifier.create(service.list())
                .assertNext(p -> assertThat(p.profileJson()).isEqualTo(LEGACY))
                .verifyComplete();
    }

    @Test
    void get_returnsAPreSchemaRowUNCHANGED_soItCanBeFixedInTheConsole() {
        when(repo.findByName("small-postgres")).thenReturn(Mono.just(row(LEGACY)));

        StepVerifier.create(service.get("small-postgres"))
                .assertNext(p -> assertThat(p.profileJson()).isEqualTo(LEGACY))
                .verifyComplete();
    }

    @Test
    void get_stillA404WhenTheRowIsAbsent() {
        when(repo.findByName("nope")).thenReturn(Mono.empty());
        StepVerifier.create(service.get("nope")).expectError().verify();
    }
}
