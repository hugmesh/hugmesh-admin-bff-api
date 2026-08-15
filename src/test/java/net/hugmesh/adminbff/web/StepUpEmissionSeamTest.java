package net.hugmesh.adminbff.web;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * STRUCTURAL guard: every step-up rejection in {@code src/main} must be minted by
 * {@link StepUpRequiredException}, never hand-built as a bare {@code ApiException.forbidden(...)}.
 *
 * <h2>Why a scanner and not per-site tests</h2>
 * There are 18 step-up gate call sites and only 6 of them are covered by a controller test that
 * asserts the {@value StepUpRequiredException#SIGNAL_HEADER} header is present. That was measured,
 * not guessed: reverting golive-record, image-build, dial-activation and backing-service-mode to
 * {@code ApiException.forbidden} with byte-identical message text left the whole suite GREEN
 * (246 tests, 0 failures). A bare {@code ApiException} renders with NO signal header, so those
 * endpoints would silently stop offering the inline MFA dialog in the browser while every test
 * still passed — the exact class of silent breakage the structured signal was introduced to end.
 *
 * <p>A per-site enumeration would not fix that: it would pass a 19th, unenumerated site. This scans
 * the source instead, so a NEW gate that skips the seam fails the build the day it is written, and
 * a NEW flavour forces both halves of the contract to be updated together
 * ({@link #theGateFlavourVocabularyIsExactlyTheEightPinnedValues()}).
 *
 * <h2>The structural anchor: the retry-header VALUE SHAPE, not any name</h2>
 * Seam membership is derived from what code DOES, not what it is called. The anchor is the
 * retry-header value shape {@code X-<flavour>-StepUp} ({@link #FLAVOUR_VALUE}), because that shape
 * is frozen on BOTH wire ends: {@code StepUpRequiredException}'s constructor tripwire
 * ({@code SAFE_HEADER_NAME}) throws for any other shape, and admin-ui's {@code SAFE_RETRY_HEADER}
 * ({@code src/app/mfa/step-up-error.ts}) IGNORES any signal value outside it. A gate that avoids
 * the shape cannot interoperate with the step-up contract at all; a gate that uses it is
 * discovered here BY VALUE — the scanner indexes every string constant whose VALUE matches the
 * shape (whatever the constant is named, one alias hop included) and treats every such identifier
 * as a step-up marker. That is why this guard cannot be renamed away: an author may call their
 * constant {@code RETRY_HEADER} (or anything else) and reword their message freely, and the gate
 * is still found through the one thing it cannot change — the retry-header value the client must
 * present the token in. Pinned by
 * {@link #aGateWithARenamedConstantAndARewordedMessage_isStillCaught()}.
 *
 * <p>Two complementary rules ride on the same index:
 * <ol>
 *   <li><b>No bare emission</b>: an {@code ApiException} construction whose arguments carry a
 *       step-up marker (the legacy phrase, {@code LEGACY_PHRASE}, an {@code X-<flavour>-StepUp}
 *       literal, or ANY identifier that resolves by value to a retry header) is an offender
 *       ({@link #noStepUpRejectionIsEmittedThroughABareApiException()}).</li>
 *   <li><b>Seam coverage</b>: every discovered flavour VALUE must be emitted through
 *       {@code StepUpRequiredException} somewhere in {@code src/main}
 *       ({@link #everyDiscoveredFlavourIsEmittedThroughTheSeam()}). This closes the deny-and-
 *       mention-nothing hole: to CHECK a token a gate must read its retry header, which puts the
 *       flavour value in the index, and an indexed flavour with no seam emission is RED — so a
 *       new gate cannot ship its deny path without the signal even if its rejection message
 *       mentions neither the phrase nor the header.</li>
 * </ol>
 *
 * <p><b>Documented limits</b> — the scanner reads source text, so:
 * <ul>
 *   <li>a deliberately obfuscated value ({@code "X-Foo-" + "StepUp"} split across a
 *       concatenation) is invisible — string composition never yields the shape in any single
 *       literal;</li>
 *   <li>a flavour arriving in a literal is indexed even when EMBEDDED (a Spring placeholder
 *       default {@code "${prop:X-Foo-StepUp}"}, message prose) — but one arriving at runtime
 *       from OUTSIDE source text entirely (an environment value with no in-source default, a
 *       config file) is not;</li>
 *   <li>a discovered constant whose NAME is a dictionary word ({@code TOKEN}) makes
 *       {@link #markersFor(Collection)} flag every innocent use of that word in offender
 *       arguments — fail-closed noise that misattributes blame in the failure list, not an
 *       escape.</li>
 * </ul>
 * The guard defends against honest renames, rewords, placeholder defaults and
 * alternate deny constructors ({@code ResponseStatusException} included) — the regression
 * classes that actually shipped or were demonstrated — not against an adversarial author, who
 * is code review's problem.
 *
 * <h2>What counts as a step-up rejection</h2>
 * The markers built by {@link #markersFor(Collection)}: the emitted legacy phrase
 * {@value StepUpRequiredException#LEGACY_PHRASE}, a reference to
 * {@code StepUpRequiredException.LEGACY_PHRASE}, an {@code X-<flavour>-StepUp} literal, or any
 * identifier the flavour index resolves to a retry-header value. Any of those inside an
 * {@code ApiException} construction means "this is a step-up rejection that will ship without the
 * signal header".
 *
 * <p>Step-up <em>MINT</em> denials are deliberately NOT matched and must stay bare 403s:
 * {@code WorkloadErrors.map} and {@code DesktopStepUpController.mint} relay a
 * {@code StepUpDeniedException} ("step-up denied: operator holds no active SSH license", "step-up
 * can only be minted by the Lease leader") — those are ordinary authz failures, and stamping a
 * signal on them would pop an MFA prompt for an operator who simply lacks a licence. The scanner is
 * pinned against that confusion in {@link #theScannerIgnoresAStepUpMintDenial()}.
 *
 * <p>The workload console's {@code X-Workload-StepUp} predates the signal and is the ONE value
 * outside the vocabulary: its deny is a body-less {@code WebFilter} response that never reaches
 * {@code ApiExceptionHandler}, emitted no phrase before the signal existed, and the console UI
 * drives its own step-up flow. It is carried as a pinned exclusion CONFINED to
 * {@code WorkloadAuthorizationFilter} ({@link #theWorkloadLegacyExclusionStaysConfinedToItsFilter()})
 * so the exemption cannot silently spread.
 *
 * <p>Comments are stripped before scanning, because the invariant is about EMITTED strings, not
 * prose: four main sources (five occurrences) legitimately discuss the phrase in a comment. That,
 * too, is pinned ({@link #theScannerIgnoresTheSamePhraseInAComment()}).
 *
 * @see StepUpSignalContractTest the wire contract this seam feeds
 */
class StepUpEmissionSeamTest {

    private static final Path MAIN = Path.of("src", "main", "java");

    /** The ONE main source allowed to hold the emitted phrase: it defines the constant. */
    private static final String SEAM = "StepUpRequiredException.java";

    /**
     * The frozen retry-header value shape — the structural anchor (see the class javadoc for why
     * it cannot be renamed away). Kept in lockstep with {@code SAFE_HEADER_NAME} in
     * {@link StepUpRequiredException} and {@code SAFE_RETRY_HEADER} in admin-ui.
     */
    private static final Pattern FLAVOUR_VALUE = Pattern.compile("X-[A-Za-z0-9-]{1,60}-StepUp");

    /**
     * {@link #FLAVOUR_VALUE} with boundary guards, for finding the shape EMBEDDED inside a longer
     * literal (a Spring {@code @Value} placeholder default, message prose). The lookbehind stops a
     * mid-token start; the lookahead refuses {@code X-Foo-StepUpToken} / {@code X-Foo-StepUp-2}.
     */
    private static final Pattern EMBEDDED_FLAVOUR_VALUE =
            Pattern.compile("(?<![A-Za-z0-9-])X-[A-Za-z0-9-]{1,60}-StepUp(?![A-Za-z0-9-])");

    /** {@code <ident> = "X-<flavour>-StepUp"} — a retry-header constant, WHATEVER its name. */
    private static final Pattern FLAVOUR_CONSTANT_DECLARATION = Pattern.compile(
            "([A-Za-z_$][A-Za-z0-9_$]*)\\s*=\\s*\"(X-[A-Za-z0-9-]{1,60}-StepUp)\"");

    /** {@code <ident> = <Class>.<ident>;} — one alias hop (DeviceTerminalStepUpGate's shape). */
    private static final Pattern ALIAS_DECLARATION = Pattern.compile(
            "([A-Za-z_$][A-Za-z0-9_$]*)\\s*=\\s*([A-Za-z_$][A-Za-z0-9_$]*)"
                    + "\\s*\\.\\s*([A-Za-z_$][A-Za-z0-9_$]*)\\s*;");

    /** A qualified constant reference, {@code <Class>.<IDENT>}. */
    private static final Pattern QUALIFIED_REF = Pattern.compile(
            "([A-Za-z_$][A-Za-z0-9_$]*)\\s*\\.\\s*([A-Za-z_$][A-Za-z0-9_$]*)");

    /**
     * {@code ApiException.forbidden(} / {@code new ApiException(}, incl. the qualified form —
     * plus {@code new ResponseStatusException(}: an RSE deny carrying a step-up marker is the
     * same bare-emission defect through a different constructor (and it additionally breaks the
     * frozen {@code {"error": ...}} body shape), so it must not escape the offender rule just by
     * not being an ApiException.
     */
    private static final Pattern API_EXCEPTION_CTOR =
            Pattern.compile("(?:new\\s+ApiException|ApiException\\s*\\.\\s*[A-Za-z][A-Za-z0-9_]*"
                    + "|new\\s+ResponseStatusException)\\s*\\(");

    /** An emission through the shared seam helper. */
    private static final Pattern SEAM_EMISSION = Pattern.compile(
            "StepUpRequiredException\\s*\\.\\s*(?:forRetryHeader|withMessage)\\s*\\(");

    /**
     * The closed vocabulary, byte-identical to the {@code FLAVOURS} list in admin-ui
     * {@code src/app/mfa/step-up-error.spec.ts}. Adding a gate must break BOTH lists on purpose.
     */
    private static final Set<String> PINNED_FLAVOURS = new TreeSet<>(Set.of(
            "X-BackingServices-StepUp",
            "X-Backup-StepUp",
            "X-Device-Terminal-StepUp",
            "X-GoLive-StepUp",
            "X-ImageGen-StepUp",
            "X-PhoneLock-StepUp",
            "X-ServiceStore-StepUp",
            "X-SshKeyIssue-StepUp"));

    /**
     * Value-shaped strings that are deliberately OUTSIDE the signal vocabulary, each confined to
     * the single file allowed to hold it (see the class javadoc).
     */
    private static final Map<String, String> LEGACY_EXCLUSIONS =
            Map.of("X-Workload-StepUp", "WorkloadAuthorizationFilter.java");

    // ── the repo-wide invariants ───────────────────────────────────────────────────────

    @Test
    void noStepUpRejectionIsEmittedThroughABareApiException() {
        List<LabeledSource> sources = mainSources();
        Pattern markers = markersFor(FlavourIndex.of(sources).constantNames());
        List<String> offenders = new ArrayList<>();
        for (LabeledSource s : sources) {
            if (!s.label().endsWith(SEAM)) {
                offenders.addAll(bareApiExceptionOffenders(s.label(), s.code(), markers));
            }
        }

        assertThat(offenders)
                .as("""
                    every step-up rejection must be minted by StepUpRequiredException \
                    (forRetryHeader/withMessage) — a bare ApiException renders with NO \
                    %s response header, so the browser silently stops offering the inline MFA \
                    dialog for that endpoint while every test still passes""",
                        StepUpRequiredException.SIGNAL_HEADER)
                .isEmpty();
    }

    @Test
    void everyDiscoveredFlavourIsEmittedThroughTheSeam() {
        List<LabeledSource> sources = mainSources();
        Map<String, List<String>> uncovered = uncoveredFlavours(sources);

        assertThat(uncovered)
                .as("""
                    every retry-header value discovered in src/main (any string constant whose \
                    VALUE matches X-<flavour>-StepUp, however it is named) must be emitted through \
                    StepUpRequiredException.forRetryHeader/withMessage somewhere in src/main. A \
                    flavour with NO seam emission means a gate's deny path ships without the \
                    %s signal — even if its rejection message mentions neither the header nor the \
                    legacy phrase. Fix the listed class to reject via the shared helper. \
                    Uncovered flavour -> where its value was sighted: %s""",
                        StepUpRequiredException.SIGNAL_HEADER, uncovered)
                .isEmpty();
    }

    @Test
    void theEmittedLegacyPhraseLivesInExactlyOneMainSource() {
        // This is the invariant StepUpRequiredException's javadoc claims: the phrase is EMITTED
        // from one place. (Comments elsewhere may name it; the scanner strips comments.)
        List<String> offenders = new ArrayList<>();
        int[] seamOccurrences = {-1};
        for (LabeledSource s : mainSources()) {
            if (s.label().endsWith(SEAM)) {
                seamOccurrences[0] = countOccurrences(s.code(), StepUpRequiredException.LEGACY_PHRASE);
            } else {
                offenders.addAll(hits(s.label(), s.code(),
                        Pattern.compile(Pattern.quote(StepUpRequiredException.LEGACY_PHRASE),
                                Pattern.CASE_INSENSITIVE)));
            }
        }

        assertThat(offenders)
                .as("compose the phrase from StepUpRequiredException.LEGACY_PHRASE instead of "
                        + "repeating the literal — an OLD admin-ui bundle greps for it, so a reword "
                        + "in one controller must not be able to break the fallback")
                .isEmpty();
        assertThat(seamOccurrences[0])
                .as("the seam %s must hold the phrase literal exactly once (the constant)", SEAM)
                .isEqualTo(1);
    }

    @Test
    void theGateFlavourVocabularyIsExactlyTheEightPinnedValues() {
        FlavourIndex index = FlavourIndex.of(mainSources());
        Set<String> discovered = new TreeSet<>(index.values());
        discovered.removeAll(LEGACY_EXCLUSIONS.keySet());

        assertThat(discovered)
                .as("""
                    the step-up retry-header vocabulary is a CROSS-REPO CONTRACT closed at exactly \
                    these 8 values, and it is discovered BY VALUE (any string of shape \
                    X-<flavour>-StepUp anywhere in src/main, however the constant holding it is \
                    named). Adding or renaming a flavour is a DELIBERATE cross-repo act: in the \
                    SAME change you must update (1) this PINNED_FLAVOURS set, (2) the literals in \
                    StepUpSignalContractTest, and (3) the admin-ui mirror specs — \
                    src/app/bff.service.step-up-signal.spec.ts and the FLAVOURS list in \
                    src/app/mfa/step-up-error.spec.ts — because the browser pins the SAME closed \
                    set and deploys independently of this BFF (a one-sided change degrades the \
                    inline MFA dialog silently). Where each value was sighted: %s""",
                        index.describeSightings())
                .isEqualTo(PINNED_FLAVOURS);
    }

    @Test
    void theWorkloadLegacyExclusionStaysConfinedToItsFilter() {
        // X-Workload-StepUp predates the signal: its deny is a body-less WebFilter response that
        // never reaches ApiExceptionHandler (and emitted no phrase before the signal existed), so
        // it is deliberately NOT in the 8-value vocabulary. Confining it keeps the exemption from
        // silently spreading to new files.
        FlavourIndex index = FlavourIndex.of(mainSources());
        for (Map.Entry<String, String> exclusion : LEGACY_EXCLUSIONS.entrySet()) {
            List<String> sightings = index.sightingsOf(exclusion.getKey());
            assertThat(sightings)
                    .as("the pinned exclusion %s must still exist (drop it from LEGACY_EXCLUSIONS "
                            + "when the workload console adopts the signal)", exclusion.getKey())
                    .isNotEmpty();
            assertThat(sightings)
                    .as("%s is a pinned LEGACY exclusion allowed ONLY in %s — a new use must "
                            + "instead join the signal vocabulary (see "
                            + "theGateFlavourVocabularyIsExactlyTheEightPinnedValues)",
                            exclusion.getKey(), exclusion.getValue())
                    .allSatisfy(at -> assertThat(at).contains(exclusion.getValue()));
        }
    }

    @Test
    void theFlavourIndexResolvesTheRealAliasChain() {
        // DeviceTerminalStepUpGate.STEP_UP_HEADER = DeviceSshTerminalWebSocketHandler.STEP_UP_HEADER
        // — the literal lives in the WS handler. If the index lost alias resolution, the
        // device-terminal flavour would drop out of the qualified map and seam coverage would rot.
        FlavourIndex index = FlavourIndex.of(mainSources());
        assertThat(index.valueOfQualified("DeviceTerminalStepUpGate", "STEP_UP_HEADER"))
                .isEqualTo("X-Device-Terminal-StepUp");
        assertThat(index.valueOfQualified("ImageGenStepUpGate", "STEP_UP_HEADER"))
                .isEqualTo("X-ImageGen-StepUp");
    }

    // ── the scanner is not vacuous: it flags the real regression, and only that ────────

    @Test
    void theScannerFlagsAGateSiteRevertedToABareApiException() {
        // VERBATIM the shape a revert produces (multi-line, byte-identical message text) — the
        // mutation that left the whole suite green before this guard existed.
        String reverted = """
                package net.hugmesh.adminbff.imagegen;
                class ImageBuildService {
                    Mono<Void> build() {
                        return Mono.error(ApiException.forbidden(
                                "image build requires step-up re-authentication (present "
                                        + ImageGenStepUpGate.STEP_UP_HEADER + ")"));
                    }
                }
                """;

        assertThat(inSourceOffenders("ImageBuildService.java", reverted))
                .as("the guard must catch a gate site reverted to a bare ApiException")
                .isNotEmpty();
        assertThat(hits("ImageBuildService.java", stripCommentsPreservingLines(reverted),
                Pattern.compile(Pattern.quote(StepUpRequiredException.LEGACY_PHRASE))))
                .as("...and the phrase-locality guard must catch it independently")
                .isNotEmpty();
    }

    @Test
    void theScannerFlagsARevertThatKeepsOnlyTheFlavourAndDropsThePhrase() {
        // A reword-and-revert: no legacy phrase at all, so the phrase guard cannot see it. The
        // flavour marker still does, which matters because this variant breaks BOTH client paths.
        String reworded = """
                class GoLiveController {
                    Mono<Void> record() {
                        return Mono.error(ApiException.forbidden(
                                "recording a go-live intent needs a second factor (present "
                                        + GoLiveStepUpGate.STEP_UP_HEADER + ")"));
                    }
                }
                """;

        assertThat(inSourceOffenders("GoLiveController.java", reworded)).isNotEmpty();
    }

    @Test
    void aGateWithARenamedConstantAndARewordedMessage_isStillCaught() {
        // THE structural case (rv2 M-D): the author names their constant RETRY_HEADER (not
        // STEP_UP_HEADER) and words their message without "requires step-up". The pre-structural
        // scanner shipped GREEN on exactly this shape. The constant's VALUE is still forced to be
        // X-<flavour>-StepUp by both wire ends, so the index resolves RETRY_HEADER by value and
        // the bare deny is an offender.
        String renamed = """
                class ToyQuotaGateController {
                    static final String RETRY_HEADER = "X-ToyQuota-StepUp";
                    Mono<Void> frob(String subject, String token) {
                        if (token == null || token.isBlank()) {
                            return Mono.error(ApiException.forbidden(
                                    "frobbing the toy quota needs re-verification (present "
                                            + RETRY_HEADER + ")"));
                        }
                        return Mono.empty();
                    }
                }
                """;

        assertThat(inSourceOffenders("ToyQuotaGateController.java", renamed))
                .as("a renamed constant + reworded message must still be caught BY VALUE")
                .isNotEmpty();
    }

    @Test
    void aNewFlavourWithoutASeamEmission_isCaught() {
        // The deny-and-mention-nothing gate: its rejection references neither the phrase nor the
        // header, so no marker can see the DENY itself — but reading the token puts the flavour
        // value in the index, and an indexed flavour with no seam emission is RED.
        String rogue = """
                class RogueGate {
                    static final String TOKEN_HEADER = "X-Rogue-StepUp";
                    Mono<Void> deny() {
                        return Mono.error(ApiException.forbidden("rogue op needs re-verification"));
                    }
                }
                """;
        String emitting = """
                class RogueController {
                    Mono<Void> deny() {
                        return Mono.error(StepUpRequiredException.forRetryHeader(
                                RogueGate.TOKEN_HEADER, "rogue op"));
                    }
                }
                """;

        assertThat(uncoveredFlavours(List.of(
                new LabeledSource("RogueGate.java", stripCommentsPreservingLines(rogue)))))
                .as("a flavour with no seam emission anywhere must be flagged")
                .containsOnlyKeys("X-Rogue-StepUp");
        assertThat(uncoveredFlavours(List.of(
                new LabeledSource("RogueGate.java", stripCommentsPreservingLines(rogue)),
                new LabeledSource("RogueController.java", stripCommentsPreservingLines(emitting)))))
                .as("...and a qualified seam emission of the same flavour satisfies it")
                .isEmpty();
    }

    @Test
    void theScannerIgnoresTheShippedSeamCall() {
        String shipped = """
                class GoLiveController {
                    Mono<Void> record() {
                        return Mono.error(StepUpRequiredException.forRetryHeader(
                                GoLiveStepUpGate.STEP_UP_HEADER, "recording a go-live intent"));
                    }
                }
                """;

        assertThat(inSourceOffenders("GoLiveController.java", shipped)).isEmpty();
    }

    @Test
    void theScannerIgnoresAStepUpMintDenial() {
        // WorkloadErrors.map / DesktopStepUpController.mint. These MUST stay bare 403s: an
        // operator without an SSH licence is not being asked to re-authenticate.
        String mintDenial = """
                class WorkloadErrors {
                    static RuntimeException map(Throwable t) {
                        if (t instanceof WorkloadStepUpService.StepUpDeniedException) {
                            return ApiException.forbidden(t.getMessage());
                        }
                        return ApiException.serviceUnavailable(
                                "desktop step-up ships dark (app.device-terminal.enabled=false)");
                    }
                }
                """;

        assertThat(inSourceOffenders("WorkloadErrors.java", mintDenial)).isEmpty();
    }

    @Test
    void theScannerIgnoresTheSamePhraseInAComment() {
        // Four main sources legitimately DISCUSS the phrase in prose (five occurrences). The
        // invariant is about emitted strings, so comment text must never trip either guard.
        String prose = """
                class BackupAdminController {
                    // ── restore (PRIVILEGED: requires step-up) ──
                    /** A missing token is a clean 403 carrying the "requires step-up" contract. */
                    Mono<Void> restore() {
                        return Mono.error(ApiException.notFound("no such backup set"));
                    }
                }
                """;

        assertThat(inSourceOffenders("BackupAdminController.java", prose)).isEmpty();
        assertThat(hits("BackupAdminController.java", stripCommentsPreservingLines(prose),
                Pattern.compile(Pattern.quote(StepUpRequiredException.LEGACY_PHRASE))))
                .isEmpty();
    }

    @Test
    void theCommentStripperLeavesStringsAndTextBlocksIntact() {
        // 116 main sources hold SQL text blocks, and `"http://x"` must not read as a comment.
        // If the stripper mangled either, the guards above would silently scan garbage.
        String source = """
                class R {
                    static final String SQL = ""\"
                            SELECT a -- not a comment, it is inside a text block
                            FROM t /* nor this */
                            ""\";
                    String url = "http://example.test/a"; // a real comment
                    char slash = '/';
                }
                """;

        String code = stripCommentsPreservingLines(source);

        assertThat(code).contains("-- not a comment, it is inside a text block");
        assertThat(code).contains("/* nor this */");
        assertThat(code).contains("\"http://example.test/a\"");
        assertThat(code).doesNotContain("a real comment");
        assertThat(code.lines().count())
                .as("line numbers in a finding must stay usable")
                .isEqualTo(source.lines().count());
    }

    // ── the flavour index: retry-header constants resolved BY VALUE ────────────────────

    /** A comment-stripped main source. */
    private record LabeledSource(String label, String code) {

        /** The top-level class name the label implies (the qualifier used in real references). */
        String className() {
            String file = label.substring(Math.max(label.lastIndexOf('/'),
                    label.lastIndexOf(java.io.File.separatorChar)) + 1);
            return file.endsWith(".java") ? file.substring(0, file.length() - 5) : file;
        }
    }

    /**
     * Every retry-header constant in a set of sources, keyed by VALUE — the piece that makes the
     * scanner structural. Collects (a) every string constant whose value matches
     * {@link #FLAVOUR_VALUE} whatever its name, (b) alias declarations that copy such a constant
     * (to a fixpoint, so {@code DeviceTerminalStepUpGate.STEP_UP_HEADER =
     * DeviceSshTerminalWebSocketHandler.STEP_UP_HEADER} resolves), and (c) every whole string
     * literal of the shape (a header name used as a value, e.g. an inline {@code getFirst(...)}).
     */
    private static final class FlavourIndex {

        /** {@code "Class.IDENT" -> value} for every resolved constant (aliases included). */
        private final Map<String, String> qualified = new TreeMap<>();
        /** {@code label -> (IDENT -> value)} for same-file (unqualified) resolution. */
        private final Map<String, Map<String, String>> byFile = new TreeMap<>();
        /** {@code value -> [label:line, ...]} — every whole-literal sighting of a value. */
        private final Map<String, List<String>> sightings = new TreeMap<>();

        static FlavourIndex of(List<LabeledSource> sources) {
            FlavourIndex index = new FlavourIndex();
            for (LabeledSource s : sources) {
                // (a) named constants, discovered by VALUE.
                Matcher decl = FLAVOUR_CONSTANT_DECLARATION.matcher(s.code());
                while (decl.find()) {
                    index.add(s, decl.group(1), decl.group(2));
                }
                // (c) every occurrence of the shape EMBEDDED in any string literal, boundary-
                // guarded — not only whole literals. A flavour smuggled in through a Spring
                // placeholder default ("${prop:X-HostCfg-StepUp}") or mentioned in message prose
                // is a real flavour the wire will carry, and the whole-literal form let exactly
                // that placeholder shape ship with zero red anywhere (found by the round-4
                // re-verifier). The lookarounds stop a prefix match inside a longer token
                // ("X-Foo-StepUpToken", "X-Foo-StepUp-2" index nothing).
                for (int[] literal : simpleStringLiterals(s.code())) {
                    String content = s.code().substring(literal[0] + 1, literal[1]);
                    Matcher embedded = EMBEDDED_FLAVOUR_VALUE.matcher(content);
                    while (embedded.find()) {
                        index.sightings.computeIfAbsent(embedded.group(), k -> new ArrayList<>())
                                .add(s.label() + ":" + lineOf(s.code(), literal[0]));
                    }
                }
            }
            // (b) alias hops, to a fixpoint (bounded: each pass must add a constant to continue).
            boolean grew = true;
            while (grew) {
                grew = false;
                for (LabeledSource s : sources) {
                    Matcher alias = ALIAS_DECLARATION.matcher(s.code());
                    while (alias.find()) {
                        String value = index.qualified.get(alias.group(2) + "." + alias.group(3));
                        if (value != null) {
                            grew |= index.add(s, alias.group(1), value);
                        }
                    }
                }
            }
            return index;
        }

        private boolean add(LabeledSource s, String ident, String value) {
            String previous = qualified.put(s.className() + "." + ident, value);
            byFile.computeIfAbsent(s.label(), k -> new TreeMap<>()).put(ident, value);
            return !value.equals(previous);
        }

        Set<String> constantNames() {
            Set<String> names = new TreeSet<>();
            for (Map<String, String> perFile : byFile.values()) {
                names.addAll(perFile.keySet());
            }
            return names;
        }

        Set<String> values() {
            Set<String> values = new TreeSet<>(sightings.keySet());
            values.addAll(qualified.values());
            return values;
        }

        List<String> sightingsOf(String value) {
            return sightings.getOrDefault(value, List.of());
        }

        String valueOfQualified(String className, String ident) {
            return qualified.get(className + "." + ident);
        }

        Map<String, String> inFile(String label) {
            return byFile.getOrDefault(label, Map.of());
        }

        String describeSightings() {
            Map<String, List<String>> all = new TreeMap<>(sightings);
            return all.toString();
        }
    }

    /**
     * Flavour values with NO {@code StepUpRequiredException} emission across {@code sources},
     * mapped to where each value was sighted (pinned legacy exclusions skipped).
     */
    private static Map<String, List<String>> uncoveredFlavours(List<LabeledSource> sources) {
        FlavourIndex index = FlavourIndex.of(sources);
        Set<String> covered = new TreeSet<>();
        for (LabeledSource s : sources) {
            Matcher emission = SEAM_EMISSION.matcher(s.code());
            while (emission.find()) {
                String args = balancedArguments(s.code(), emission.end() - 1);
                Matcher literal = FLAVOUR_VALUE.matcher(args);
                while (literal.find()) {
                    covered.add(literal.group());
                }
                Matcher ref = QUALIFIED_REF.matcher(args);
                while (ref.find()) {
                    String value = index.valueOfQualified(ref.group(1), ref.group(2));
                    if (value != null) {
                        covered.add(value);
                    }
                }
                for (Map.Entry<String, String> local : index.inFile(s.label()).entrySet()) {
                    if (Pattern.compile("\\b" + Pattern.quote(local.getKey()) + "\\b")
                            .matcher(args).find()) {
                        covered.add(local.getValue());
                    }
                }
            }
        }
        Map<String, List<String>> uncovered = new LinkedHashMap<>();
        for (String value : index.values()) {
            if (!covered.contains(value) && !LEGACY_EXCLUSIONS.containsKey(value)) {
                List<String> where = index.sightingsOf(value);
                uncovered.put(value, where.isEmpty() ? List.of("(aliased constant)") : where);
            }
        }
        return uncovered;
    }

    /**
     * The step-up markers: the legacy phrase, {@code LEGACY_PHRASE}, {@code STEP_UP_HEADER} (the
     * canonical constant name, kept as a belt), an {@code X-<flavour>-StepUp} literal, or ANY of
     * {@code constantNames} — identifiers the flavour index resolved to a retry-header VALUE, so
     * a renamed constant is still a marker.
     */
    private static Pattern markersFor(Collection<String> constantNames) {
        StringBuilder pattern = new StringBuilder(
                Pattern.quote(StepUpRequiredException.LEGACY_PHRASE)
                        + "|LEGACY_PHRASE"
                        + "|STEP_UP_HEADER"
                        + "|X-[A-Za-z0-9-]{1,60}-StepUp");
        for (String name : new TreeSet<>(constantNames)) {
            pattern.append("|\\b").append(Pattern.quote(name)).append("\\b");
        }
        return Pattern.compile(pattern.toString(), Pattern.CASE_INSENSITIVE);
    }

    // ── the scanning machinery ─────────────────────────────────────────────────────────

    /** Every {@code src/main} java source, comment-stripped, with a vacuity guard. */
    private static List<LabeledSource> mainSources() {
        assertThat(Files.isDirectory(MAIN)).as("source root %s must exist", MAIN).isTrue();
        List<LabeledSource> sources = new ArrayList<>();
        boolean sawSeam = false;
        try (Stream<Path> files = Files.walk(MAIN)) {
            for (Path file : files.filter(p -> p.toString().endsWith(".java")).toList()) {
                String label = MAIN.relativize(file).toString();
                sawSeam |= label.endsWith(SEAM);
                sources.add(new LabeledSource(label,
                        stripCommentsPreservingLines(readString(file))));
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        // A scanner that walked nothing, or lost the seam, would pass vacuously.
        assertThat(sources.size()).as("expected to scan the real main sources under %s", MAIN)
                .isGreaterThan(100);
        assertThat(sawSeam).as("%s must be among the scanned sources", SEAM).isTrue();
        return sources;
    }

    /**
     * Every {@code ApiException} construction in {@code code} whose ARGUMENTS carry a step-up
     * marker, i.e. every step-up rejection that would ship with no signal header.
     */
    private static List<String> bareApiExceptionOffenders(String label, String code,
                                                          Pattern markers) {
        List<String> offenders = new ArrayList<>();
        Matcher m = API_EXCEPTION_CTOR.matcher(code);
        while (m.find()) {
            String args = balancedArguments(code, m.end() - 1);
            if (markers.matcher(args).find()) {
                offenders.add(label + ":" + lineOf(code, m.start()) + "  "
                        + collapse(code.substring(m.start(), m.end()) + args));
            }
        }
        return offenders;
    }

    /**
     * Offenders in a single in-memory probe source, resolving constants declared IN that source
     * (the real scan resolves across all of {@code src/main} the same way).
     */
    private static List<String> inSourceOffenders(String label, String source) {
        String code = stripCommentsPreservingLines(source);
        FlavourIndex index = FlavourIndex.of(List.of(new LabeledSource(label, code)));
        return bareApiExceptionOffenders(label, code, markersFor(index.constantNames()));
    }

    /** {@code label:line  text} for every line of {@code code} matching {@code pattern}. */
    private static List<String> hits(String label, String code, Pattern pattern) {
        List<String> found = new ArrayList<>();
        String[] lines = code.split("\n", -1);
        for (int i = 0; i < lines.length; i++) {
            if (pattern.matcher(lines[i]).find()) {
                found.add(label + ":" + (i + 1) + "  " + lines[i].strip());
            }
        }
        return found;
    }

    /**
     * The argument text of the call whose opening {@code (} is at {@code open}, up to the matching
     * close paren. Parens inside string and char literals do not count.
     */
    private static String balancedArguments(String code, int open) {
        int depth = 0;
        for (int i = open; i < code.length(); i++) {
            char c = code.charAt(i);
            if (c == '"' || c == '\'') {
                i = endOfLiteral(code, i);
                continue;
            }
            if (c == '(') {
                depth++;
            } else if (c == ')' && --depth == 0) {
                return code.substring(open + 1, i);
            }
        }
        return code.substring(open + 1);
    }

    /**
     * Start/end quote indexes of every SIMPLE (non-text-block) string literal in {@code code} —
     * {@code [openQuote, closeQuote]} pairs, so content is {@code code.substring(open+1, close)}.
     */
    private static List<int[]> simpleStringLiterals(String code) {
        List<int[]> literals = new ArrayList<>();
        int i = 0;
        while (i < code.length()) {
            char c = code.charAt(i);
            if (c == '"' || c == '\'') {
                int end = endOfLiteral(code, i);
                if (c == '"' && !code.startsWith("\"\"\"", i) && end < code.length()
                        && code.charAt(end) == '"') {
                    literals.add(new int[] {i, end});
                }
                i = end + 1;
            } else {
                i++;
            }
        }
        return literals;
    }

    /**
     * Replaces every comment with spaces, keeping the source's exact length and newlines so line
     * numbers stay meaningful. String literals, char literals and text blocks are left untouched —
     * without that, {@code "http://x"} would swallow the rest of the line and the SQL text blocks
     * in 116 main sources would be mangled.
     */
    private static String stripCommentsPreservingLines(String source) {
        StringBuilder out = new StringBuilder(source.length());
        int i = 0;
        while (i < source.length()) {
            char c = source.charAt(i);
            if (c == '"' || c == '\'') {
                int end = endOfLiteral(source, i);
                out.append(source, i, Math.min(end + 1, source.length()));
                i = end + 1;
            } else if (c == '/' && i + 1 < source.length() && source.charAt(i + 1) == '/') {
                while (i < source.length() && source.charAt(i) != '\n') {
                    out.append(' ');
                    i++;
                }
            } else if (c == '/' && i + 1 < source.length() && source.charAt(i + 1) == '*') {
                int end = source.indexOf("*/", i + 2);
                end = end < 0 ? source.length() : end + 2;
                for (; i < end; i++) {
                    out.append(source.charAt(i) == '\n' ? '\n' : ' ');
                }
            } else {
                out.append(c);
                i++;
            }
        }
        return out.toString();
    }

    /** Index of the closing quote of the literal starting at {@code start}. */
    private static int endOfLiteral(String source, int start) {
        char quote = source.charAt(start);
        boolean textBlock = quote == '"' && source.startsWith("\"\"\"", start);
        String terminator = textBlock ? "\"\"\"" : String.valueOf(quote);
        int i = start + terminator.length();
        while (i < source.length()) {
            char c = source.charAt(i);
            if (c == '\\') {
                i += 2;
                continue;
            }
            if (source.startsWith(terminator, i)) {
                return i + terminator.length() - 1;
            }
            // An unterminated non-text-block literal cannot cross a line in valid Java; stopping
            // here keeps a malformed source from consuming the whole file.
            if (!textBlock && c == '\n') {
                return i - 1;
            }
            i++;
        }
        return source.length() - 1;
    }

    private static int lineOf(String code, int offset) {
        return (int) code.substring(0, offset).chars().filter(ch -> ch == '\n').count() + 1;
    }

    private static int countOccurrences(String haystack, String needle) {
        int count = 0;
        for (int i = haystack.indexOf(needle); i >= 0; i = haystack.indexOf(needle, i + 1)) {
            count++;
        }
        return count;
    }

    private static String collapse(String text) {
        String flat = text.replaceAll("\\s+", " ").strip();
        return flat.length() <= 160 ? flat : flat.substring(0, 160) + "…";
    }

    private static String readString(Path file) {
        try {
            return Files.readString(file);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
