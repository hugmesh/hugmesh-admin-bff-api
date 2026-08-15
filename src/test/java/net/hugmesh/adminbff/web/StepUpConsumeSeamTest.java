package net.hugmesh.adminbff.web;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * STRUCTURAL guard: a privileged operation authorised by the Casdoor-MFA leg must CONSUME the
 * freshness stamp, so a second privileged mutation needs a fresh challenge.
 *
 * <h2>The invariant, and what breaks without it</h2>
 * {@code MfaStepUpService.consume()} clears {@code bff_session.mfa_satisfied}. Its whole purpose
 * is single use: the stamp is valid for the freshness window (10 min by default), so a gate site
 * that satisfies on {@code mfaFresh} and then forgets to consume silently converts step-up from
 * <em>one challenge per privileged operation</em> into <em>one challenge per ten minutes</em>.
 * Every mutation in that window — go-live, image build, SSH key issuance, phone lockout, backup
 * restore — would ride on a single challenge. Nothing about that is visible in a response body,
 * a log line, or any existing test; the endpoint keeps returning 200.
 *
 * <h2>Why a scanner, and why this one is not the emission scanner</h2>
 * {@link StepUpEmissionSeamTest} guards the other half of the contract — that a rejection is
 * MINTED through {@code StepUpRequiredException} so the client gets a signal header. It says
 * nothing about what happens on the ACCEPT path. These are complementary: emission covers the
 * 403, this covers the 200. At the time of writing all 19 three-arg gate call sites do consume
 * correctly; this exists so the TWENTIETH cannot quietly not.
 *
 * <h2>The two shapes, both legitimate</h2>
 * <ol>
 *   <li><b>Inline</b> (18 of 19 sites): the consume sits in the same method as the gate check,
 *       normally {@code Mono<Void> consume = mfaFresh ? mfaStepUp.consume(sessionToken) :
 *       Mono.empty();} composed into the returned chain.</li>
 *   <li><b>Deferred</b> ({@code DeviceSshTerminalWebSocketHandler}): {@code mfaFresh} is threaded
 *       as a parameter through {@code handleStepUpAndAuthorize -> afterAuthorized ->
 *       openTransport}, and the consume happens at the real transport open. That is deliberate
 *       and arguably better — it consumes only when the operation actually commits, so a denial
 *       further down does not burn the operator's challenge. The first draft of this scanner was
 *       method-scoped and flagged it; the code was right and the rule was wrong.</li>
 * </ol>
 * Rule 4 exists so accepting the deferred shape does not degrade into "any consume anywhere in
 * the file counts": a deferred site must demonstrably pass {@code mfaFresh} onward.
 *
 * <h2>The lazy-Mono trap (rule 2)</h2>
 * {@code Mono<Void> consume = mfaStepUp.consume(token);} does NOTHING on its own — a Mono that is
 * never subscribed never runs. A site could hold a perfectly correct-looking assignment, forget to
 * compose it into the returned chain, and never clear the stamp. Rule 2 requires the local to be
 * used again (composed or returned).
 */
class StepUpConsumeSeamTest {

    private static final Path MAIN = Path.of("src", "main", "java");

    /** The gate classes define {@code isSatisfied}; they are not call SITES of it. */
    private static final String GATE_SUFFIX = "StepUpGate.java";

    /** A file we must always see, so a scan that silently walked nothing cannot pass. */
    private static final String SENTINEL = "GoLiveController.java";

    /** The observed number of three-arg gate call sites; a floor, not a pin. */
    private static final int SITE_FLOOR = 19;

    private static final Pattern SATISFY = Pattern.compile("\\bisSatisfied\\s*\\(");
    private static final Pattern MFA_CONSUME = Pattern.compile("\\bmfaStepUp\\s*\\.\\s*consume\\s*\\(");
    private static final Pattern CONSUME_ASSIGN =
            Pattern.compile("Mono<Void>\\s+(\\w+)\\s*=\\s*[^;]*consume\\s*\\(");
    /** A call passing {@code mfaFresh} onward as an argument (the deferred-consume evidence). */
    private static final Pattern THREADS_MFAFRESH =
            Pattern.compile("\\w+\\s*\\([^;]*\\bmfaFresh\\b[^;]*\\)");
    /** A method signature immediately before a body brace (never a lambda arrow). */
    private static final Pattern METHOD_HEAD =
            Pattern.compile("\\)\\s*(?:throws\\s+[\\w.,\\s<>]+?)?\\s*$");

    record LabeledSource(String label, String code) { }

    // ── the assertions ────────────────────────────────────────────────────────────────

    @Test
    void everyGateSiteThatCanSatisfyOnMfaFreshness_consumesTheStamp() {
        List<LabeledSource> sources = mainSources();
        assertThat(offenders(sources))
                .as("every three-arg step-up gate site must consume the MFA freshness stamp; "
                        + "an unconsumed stamp authorises EVERY privileged mutation for the rest "
                        + "of the freshness window")
                .isEmpty();
    }

    @Test
    void theScanFindsTheKnownGateSites_soAGreenRunIsNotVacuous() {
        assertThat(countSites(mainSources()))
                .as("expected at least %d three-arg gate call sites; a lower count means the "
                        + "scanner stopped recognising them and every rule below went vacuous",
                        SITE_FLOOR)
                .isGreaterThanOrEqualTo(SITE_FLOOR);
    }

    // ── negative controls: each plants one defect and asserts THIS analyser catches it ──

    @Test
    void aGateSiteThatNeverConsumes_isCaught() {
        String src = """
                class NewFeatureController {
                    Mono<Object> doPrivilegedThing(String actor, String tok, boolean mfaFresh) {
                        if (!stepUp.isSatisfied(actor, tok, mfaFresh)) {
                            throw StepUpRequiredException.forRetryHeader(H, "do the thing");
                        }
                        return service.mutate(actor);
                    }
                }
                """;
        assertThat(offenders(List.of(new LabeledSource("NewFeatureController.java", src))))
                .as("a new gate site that never consumes must be caught")
                .anySatisfy(o -> assertThat(o).contains("NEVER consumes"));
    }

    @Test
    void aConsumeMonoAssignedButNeverSubscribed_isCaught() {
        // The lazy-Mono trap: this LOOKS correct and clears nothing.
        String src = """
                class ForgetfulController {
                    Mono<Object> doPrivilegedThing(String actor, String tok, boolean mfaFresh, String sess) {
                        if (!stepUp.isSatisfied(actor, tok, mfaFresh)) {
                            throw StepUpRequiredException.forRetryHeader(H, "do the thing");
                        }
                        Mono<Void> consume = mfaFresh ? mfaStepUp.consume(sess) : Mono.empty();
                        return service.mutate(actor);
                    }
                }
                """;
        assertThat(offenders(List.of(new LabeledSource("ForgetfulController.java", src))))
                .as("a consume Mono that is assigned but never subscribed clears nothing")
                .anySatisfy(o -> assertThat(o).contains("never subscribed"));
    }

    @Test
    void aDeferredConsumeThatDoesNotThreadMfaFresh_isCaught() {
        // An unrelated consume elsewhere in the file must NOT vacuously satisfy the rule.
        String src = """
                class CoincidentalController {
                    Mono<Object> doPrivilegedThing(String actor, String tok, boolean mfaFresh) {
                        if (!stepUp.isSatisfied(actor, tok, mfaFresh)) {
                            throw StepUpRequiredException.forRetryHeader(H, "do the thing");
                        }
                        return service.mutate(actor);
                    }
                    Mono<Void> someOtherEndpoint(String sess) {
                        return mfaStepUp.consume(sess);
                    }
                }
                """;
        assertThat(offenders(List.of(new LabeledSource("CoincidentalController.java", src))))
                .as("a consume in an unrelated method must not count as this site's consume")
                .anySatisfy(o -> assertThat(o).contains("coincidental"));
    }

    @Test
    void theDeliberateDeferredConsumeShape_isAccepted() {
        // POSITIVE control: the DeviceSshTerminalWebSocketHandler shape must NOT be flagged.
        // The first draft of this scanner was method-scoped and produced exactly this false
        // positive — the code was right and the rule was wrong.
        String src = """
                class TerminalHandler {
                    Mono<Void> handleStepUpAndAuthorize(String op, String tok, String sess, boolean mfaFresh) {
                        if (!stepUpGate.isSatisfied(op, tok, mfaFresh)) {
                            return close(session, "missing/invalid step-up");
                        }
                        return authz.authorize(op).then(Mono.defer(() -> afterAuthorized(op, sess, mfaFresh)));
                    }
                    Mono<Void> afterAuthorized(String op, String sess, boolean mfaFresh) {
                        return devices.find(op).flatMap(d -> openTransport(op, d, sess, mfaFresh));
                    }
                    Mono<Void> openTransport(String op, Object d, String sess, boolean mfaFresh) {
                        stepUp.consume(op);
                        if (mfaFresh) {
                            mfaStepUp.consume(sess).subscribe();
                        }
                        return transport.open(op);
                    }
                }
                """;
        assertThat(offenders(List.of(new LabeledSource("TerminalHandler.java", src))))
                .as("the deliberate deferred-consume shape (mfaFresh threaded to the commit point) "
                        + "is correct and must not be flagged")
                .isEmpty();
    }

    @Test
    void theRealSourcesExerciseBothShapes_soNeitherBranchIsUntested() {
        List<LabeledSource> sources = mainSources();
        assertThat(countInlineConsume(sources))
                .as("expected the inline-consume shape to be exercised by the real sources")
                .isGreaterThan(0);
        assertThat(countDeferredConsume(sources))
                .as("expected the deferred-consume shape to be exercised by the real sources; "
                        + "if this drops to 0 the rule-4 branch is no longer covered by anything "
                        + "but its synthetic control")
                .isGreaterThan(0);
    }

    // ── the analyser ──────────────────────────────────────────────────────────────────

    /** Every rule violation across {@code sources}. Empty means the invariant holds. */
    private static List<String> offenders(List<LabeledSource> sources) {
        List<String> out = new ArrayList<>();
        for (LabeledSource s : sources) {
            if (s.label().endsWith(GATE_SUFFIX)) continue;
            Matcher m = SATISFY.matcher(s.code());
            while (m.find()) {
                if (countTopLevelArgs(s.code(), m.end() - 1) != 3) continue;
                String at = s.label() + ":" + lineOf(s.code(), m.start());
                String body = enclosingMethod(s.code(), m.start());
                if (body == null) {
                    out.add(at + "  no enclosing method found (scanner cannot verify this site)");
                    continue;
                }
                // R1 — the file must consume the MFA stamp at all.
                if (!MFA_CONSUME.matcher(s.code()).find()) {
                    out.add(at + "  satisfies on mfaFresh but the file NEVER consumes the stamp "
                            + "(the challenge would authorise every privileged mutation for the "
                            + "rest of the freshness window)");
                    continue;
                }
                if (MFA_CONSUME.matcher(body).find()) {
                    // R2 — a consume Mono must actually be subscribed.
                    Matcher a = CONSUME_ASSIGN.matcher(body);
                    while (a.find()) {
                        String name = a.group(1);
                        String rest = body.substring(a.end());
                        boolean used = Pattern.compile("\\b" + Pattern.quote(name) + "\\s*\\.").matcher(rest).find()
                                || Pattern.compile("return\\s+" + Pattern.quote(name) + "\\b").matcher(rest).find();
                        if (!used) {
                            out.add(at + "  Mono '" + name + "' assigned from consume() but never "
                                    + "subscribed - an unsubscribed Mono clears nothing");
                        }
                    }
                    // R3 — the consume must be conditioned on the MFA leg.
                    if (!body.contains("mfaFresh")) {
                        out.add(at + "  consume present but not conditioned on mfaFresh");
                    }
                } else {
                    // R4 — deferred consume is fine, but only with evidence of threading.
                    // The gate call itself passes mfaFresh, so it must be blanked first or every
                    // site trivially "threads" it and rule 4 can never fire. (Its own negative
                    // control caught exactly that.)
                    if (!THREADS_MFAFRESH.matcher(withoutGateCalls(body)).find()) {
                        out.add(at + "  no consume in this method AND mfaFresh is not threaded "
                                + "onward — the file-level consume is coincidental, not this "
                                + "site's");
                    }
                }
            }
        }
        return out;
    }

    /**
     * {@code body} with every {@code isSatisfied(…)} call blanked out. Rule 4 asks whether the
     * method hands {@code mfaFresh} to something else; the gate check itself is not "something
     * else", and leaving it in makes the rule unfalsifiable.
     */
    private static String withoutGateCalls(String body) {
        StringBuilder out = new StringBuilder(body);
        Matcher m = SATISFY.matcher(body);
        while (m.find()) {
            int open = m.end() - 1;
            int depth = 0;
            for (int i = open; i < body.length(); i++) {
                char c = body.charAt(i);
                if (c == '(') depth++;
                else if (c == ')') {
                    depth--;
                    if (depth == 0) {
                        for (int k = m.start(); k <= i; k++) {
                            if (out.charAt(k) != '\n') out.setCharAt(k, ' ');
                        }
                        break;
                    }
                }
            }
        }
        return out.toString();
    }

    private static int countSites(List<LabeledSource> sources) {
        int n = 0;
        for (LabeledSource s : sources) {
            if (s.label().endsWith(GATE_SUFFIX)) continue;
            Matcher m = SATISFY.matcher(s.code());
            while (m.find()) if (countTopLevelArgs(s.code(), m.end() - 1) == 3) n++;
        }
        return n;
    }

    private static int countInlineConsume(List<LabeledSource> sources) {
        return countByShape(sources, true);
    }

    private static int countDeferredConsume(List<LabeledSource> sources) {
        return countByShape(sources, false);
    }

    private static int countByShape(List<LabeledSource> sources, boolean inline) {
        int n = 0;
        for (LabeledSource s : sources) {
            if (s.label().endsWith(GATE_SUFFIX)) continue;
            Matcher m = SATISFY.matcher(s.code());
            while (m.find()) {
                if (countTopLevelArgs(s.code(), m.end() - 1) != 3) continue;
                String body = enclosingMethod(s.code(), m.start());
                if (body == null) continue;
                if (MFA_CONSUME.matcher(body).find() == inline) n++;
            }
        }
        return n;
    }

    // ── scanning machinery ────────────────────────────────────────────────────────────

    /** Every {@code src/main} java source, comment-stripped, with vacuity guards. */
    private static List<LabeledSource> mainSources() {
        assertThat(Files.isDirectory(MAIN)).as("source root %s must exist", MAIN).isTrue();
        List<LabeledSource> sources = new ArrayList<>();
        boolean sawSentinel = false;
        try (Stream<Path> files = Files.walk(MAIN)) {
            for (Path file : files.filter(p -> p.toString().endsWith(".java")).toList()) {
                String label = MAIN.relativize(file).toString();
                sawSentinel |= label.endsWith(SENTINEL);
                sources.add(new LabeledSource(label, stripComments(readString(file))));
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        assertThat(sources.size()).as("expected to scan the real main sources under %s", MAIN)
                .isGreaterThan(100);
        assertThat(sawSentinel).as("%s must be among the scanned sources", SENTINEL).isTrue();
        return sources;
    }

    /**
     * The smallest enclosing {@code { … }} whose opening brace is preceded by a METHOD signature
     * (never a lambda arrow), so a gate check inside a lambda resolves to its method, not the
     * lambda.
     */
    private static String enclosingMethod(String code, int idx) {
        List<int[]> enclosing = new ArrayList<>();
        List<Integer> stack = new ArrayList<>();
        for (int i = 0; i < code.length(); i++) {
            char c = code.charAt(i);
            if (c == '{') {
                stack.add(i);
            } else if (c == '}' && !stack.isEmpty()) {
                int open = stack.remove(stack.size() - 1);
                if (open < idx && idx < i) enclosing.add(new int[]{open, i});
            }
        }
        enclosing.sort((x, y) -> (x[1] - x[0]) - (y[1] - y[0]));
        for (int[] span : enclosing) {
            int open = span[0];
            String head = code.substring(Math.max(0, open - 400), open);
            boolean lambda = open >= 2 && code.startsWith("->", findArrow(code, open));
            if (!lambda && METHOD_HEAD.matcher(head).find()) {
                return code.substring(open, span[1] + 1);
            }
        }
        return null;
    }

    /** Index of the last non-space run of 2 chars before {@code open} (to spot {@code ->}). */
    private static int findArrow(String code, int open) {
        int i = open - 1;
        while (i > 0 && Character.isWhitespace(code.charAt(i))) i--;
        return Math.max(0, i - 1);
    }

    /** Top-level (comma-separated, bracket-aware) argument count for the call at {@code open}. */
    private static int countTopLevelArgs(String code, int open) {
        int depth = 0, args = 0;
        boolean any = false;
        for (int i = open; i < code.length(); i++) {
            char c = code.charAt(i);
            if (c == '(' || c == '[' || c == '<') depth++;
            else if (c == ')' || c == ']' || c == '>') {
                depth--;
                if (depth == 0) return any ? args + 1 : 0;
            } else if (c == ',' && depth == 1) args++;
            else if (!Character.isWhitespace(c) && depth == 1) any = true;
        }
        return -1;
    }

    /** Blank out comments while preserving line numbering and string literals. */
    private static String stripComments(String s) {
        StringBuilder out = new StringBuilder(s.length());
        int i = 0;
        while (i < s.length()) {
            char c = s.charAt(i);
            if (c == '"') {
                int j = i + 1;
                while (j < s.length() && s.charAt(j) != '"') j += s.charAt(j) == '\\' ? 2 : 1;
                out.append(s, i, Math.min(j + 1, s.length()));
                i = j + 1;
            } else if (s.startsWith("//", i)) {
                int j = s.indexOf('\n', i);
                if (j < 0) j = s.length();
                out.append(" ".repeat(j - i));
                i = j;
            } else if (s.startsWith("/*", i)) {
                int j = s.indexOf("*/", i);
                j = j < 0 ? s.length() : j + 2;
                for (int k = i; k < j; k++) out.append(s.charAt(k) == '\n' ? '\n' : ' ');
                i = j;
            } else {
                out.append(c);
                i++;
            }
        }
        return out.toString();
    }

    private static int lineOf(String code, int idx) {
        int line = 1;
        for (int i = 0; i < idx; i++) if (code.charAt(i) == '\n') line++;
        return line;
    }

    private static String readString(Path p) {
        try {
            return new String(Files.readAllBytes(p), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
