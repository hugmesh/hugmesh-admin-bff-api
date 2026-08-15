package net.hugmesh.adminbff.web;

import org.springframework.http.HttpStatus;
import net.hugmesh.commons.web.ApiException;

/**
 * The ONE place that mints a "step-up required" rejection, and the ONE place that owns the
 * structured signal telling a client <em>which</em> step-up flavour to satisfy.
 *
 * <h2>Why this exists</h2>
 * Before this type, the browser's only way to recognise a step-up gate was a case-insensitive
 * substring match on the server's free-text error message (admin-ui
 * {@code src/app/mfa/step-up-error.ts}: {@code /requires step-up/i}) — its own doc admitted
 * "the free-text phrase IS the contract". Any reword of any gate message therefore silently
 * disabled the inline step-up dialog fleet-wide and the retry flow died with a bare error.
 * The 10 step-up gates ({@code BackingServiceStepUpGate}, {@code BackupStepUpGate},
 * {@code DeviceTerminalStepUpGate}, {@code GoLiveStepUpGate}, {@code ImageGenStepUpGate},
 * {@code PhoneLockStepUpGate}, {@code ServiceStoreStepUpGate}, {@code SshKeyIssueStepUpGate},
 * {@code WorkloadStepUpService}, {@code DesktopStepUpController}) share NO supertype, so this
 * exception — rendered by the single {@link ApiExceptionHandler} — is the centralising seam.
 *
 * <h2>The wire contract</h2>
 * <ul>
 *   <li><b>Status stays 403.</b> Deliberately NOT 428: every existing client (admin-ui,
 *       login-ui, the CLI, the generator's ncurses/GUI callers) already branches on 403, and a
 *       status change would be a breaking, non-rolling-deployable change.</li>
 *   <li><b>Body is byte-identical to before</b> — {@code {"error": "<message>"}}, exactly what
 *       {@link ApiExceptionHandler} has always emitted for EVERY {@link ApiException}. Nothing
 *       is added to the shared JSON error body, so no unrelated error's wire shape moves and
 *       the {@code {error}} shape the UIs (and the mock-bff reference impl) pin stays exact.</li>
 *   <li><b>The signal is a response header</b>, {@value #SIGNAL_HEADER}, whose value is the
 *       NAME OF THE RETRY HEADER the caller must present the step-up token in — e.g.
 *       {@code X-Step-Up-Required: X-ImageGen-StepUp}. Self-describing: a client sets
 *       {@code response.headers.get('X-Step-Up-Required')} as the request header name on retry,
 *       so a NEW gate needs zero client change. Absent on every non-step-up response.</li>
 * </ul>
 *
 * <h2>Backward compatibility in BOTH directions (rolling deploy)</h2>
 * <ul>
 *   <li><b>old client + new server:</b> the legacy free-text phrase {@value #LEGACY_PHRASE} is
 *       RETAINED verbatim in every message. {@link #LEGACY_PHRASE} is the single place main
 *       sources EMIT that literal — four other main sources name it in a comment, which reaches
 *       no client — so it cannot drift out from under an old client. Enforced, comment-aware, by
 *       {@code StepUpEmissionSeamTest}.</li>
 *   <li><b>new client + old server:</b> the client keeps the substring sniff as a FALLBACK when
 *       {@value #SIGNAL_HEADER} is absent (see admin-ui {@code step-up-error.ts}).</li>
 * </ul>
 *
 * @see ApiExceptionHandler
 */
public final class StepUpRequiredException extends ApiException {

    /**
     * The structured signal: a response header present on (and ONLY on) a step-up rejection.
     * Its value is the request-header name the retry must carry the step-up token in — one of
     * the 8 gate {@code STEP_UP_HEADER} constants.
     */
    public static final String SIGNAL_HEADER = "X-Step-Up-Required";

    /**
     * The legacy free-text phrase an OLD client greps for. This constant is the only place in main
     * sources where the phrase is <b>emitted</b>: every gate message is composed from it, so the
     * pre-signal contract cannot be reworded away by editing one controller. Four OTHER main
     * sources mention the phrase in a COMMENT ({@code BackingServiceStepUpGate},
     * {@code BackupStepUpGate}, {@code ImageGenStepUpGate}, and {@code BackupAdminController}
     * twice) — prose that reaches no client, which is why the invariant is about EMISSION, not
     * about the literal's absence. It is enforced, comment-aware, by
     * {@code StepUpEmissionSeamTest.theEmittedLegacyPhraseLivesInExactlyOneMainSource}.
     */
    public static final String LEGACY_PHRASE = "requires step-up";

    /**
     * A retry-header name is only ever a compile-time gate constant, so this is a tripwire for
     * a future programming error, not a runtime input filter. It also makes header-value
     * injection (CR/LF) structurally impossible: a bad value throws at construction and so can
     * never be written to the wire.
     */
    private static final java.util.regex.Pattern SAFE_HEADER_NAME =
            java.util.regex.Pattern.compile("^X-[A-Za-z0-9-]{1,60}-StepUp$");

    private final String retryHeader;

    private StepUpRequiredException(String retryHeader, String message) {
        super(HttpStatus.FORBIDDEN, withLegacyPhrase(message, retryHeader));
        if (retryHeader == null || !SAFE_HEADER_NAME.matcher(retryHeader).matches()) {
            throw new IllegalArgumentException(
                    "step-up retry header must be an X-<flavour>-StepUp gate constant, got: "
                            + retryHeader);
        }
        this.retryHeader = retryHeader;
    }

    /**
     * SOURCE-enforced old-client contract: this type is INCAPABLE of minting a rejection whose
     * message lacks {@link #LEGACY_PHRASE} — the constructor composes rather than trusting
     * callers. A message that already carries the phrase (case-insensitively, mirroring the old
     * admin-ui sniff {@code /requires step-up/i}) passes through VERBATIM, so every shipped
     * message — all {@link #forRetryHeader} output and the one {@link #withMessage} caller —
     * is byte-identical to before. Only a message that would break an old client is amended,
     * by appending the canonical hint (which also re-states the retry header for clients that
     * cannot read the signal). A null/blank message becomes the canonical-template wording
     * rather than NPE-ing the renderer's {@code Map.of("error", ...)}.
     */
    private static String withLegacyPhrase(String message, String retryHeader) {
        if (message != null
                && message.toLowerCase(java.util.Locale.ROOT).contains(LEGACY_PHRASE)) {
            return message;
        }
        if (message == null || message.isBlank()) {
            return "this operation " + LEGACY_PHRASE + " re-authentication (present "
                    + retryHeader + ")";
        }
        return message + " (" + LEGACY_PHRASE + " re-authentication: present " + retryHeader + ")";
    }

    /** The request-header name the caller must present a step-up token in on retry. */
    public String retryHeader() {
        return retryHeader;
    }

    /**
     * The canonical rejection: {@code "<verb> requires step-up re-authentication (present
     * <retryHeader>)"}. This reproduces, byte for byte, the message the 17 uniform gate call
     * sites hand-built before centralisation — so an old substring-sniffing client sees no
     * change at all.
     *
     * @param retryHeader a gate's {@code STEP_UP_HEADER} constant
     * @param verb        the operation as it reads in the message, e.g. {@code "issue"}
     */
    public static StepUpRequiredException forRetryHeader(String retryHeader, String verb) {
        return new StepUpRequiredException(retryHeader,
                verb + " " + LEGACY_PHRASE + " re-authentication (present " + retryHeader + ")");
    }

    /**
     * Escape hatch for the one gate whose wording predates the canonical template
     * (cloud-backup restore). The caller passes its message VERBATIM so no operator-visible
     * text is reworded — but this is NOT trusted with the wire contract: the constructor
     * appends {@link #LEGACY_PHRASE} whenever the given message lacks it (see
     * {@link #withLegacyPhrase}), so no caller wording can strip the old-client signal. To
     * keep the wording truly verbatim, compose the phrase from {@link #LEGACY_PHRASE} (the
     * emitted-once invariant in {@code StepUpEmissionSeamTest} bans repeating the literal
     * anyway).
     */
    public static StepUpRequiredException withMessage(String retryHeader, String message) {
        return new StepUpRequiredException(retryHeader, message);
    }
}
