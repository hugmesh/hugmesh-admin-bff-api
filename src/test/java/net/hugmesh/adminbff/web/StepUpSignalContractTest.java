package net.hugmesh.adminbff.web;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import net.hugmesh.adminbff.backingservices.BackingServiceStepUpGate;
import net.hugmesh.adminbff.cloudbackup.BackupStepUpGate;
import net.hugmesh.adminbff.desktop.terminal.DeviceTerminalStepUpGate;
import net.hugmesh.adminbff.golive.GoLiveStepUpGate;
import net.hugmesh.adminbff.imagegen.ImageGenStepUpGate;
import net.hugmesh.adminbff.phone.PhoneLockStepUpGate;
import net.hugmesh.adminbff.servicecatalog.ServiceStoreStepUpGate;
import net.hugmesh.adminbff.sshissue.SshKeyIssueStepUpGate;
import net.hugmesh.commons.web.ApiException;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * THE wire contract for the structured step-up signal. This is the acceptance bar for the
 * problem it fixes: before it, the browser's ONLY way to know "this action needs step-up" was a
 * case-insensitive substring match on a server error STRING, so any reword of any gate message
 * silently killed the inline MFA dialog and the retry flow fleet-wide.
 *
 * <p>Pinned here:
 * <ol>
 *   <li>the signal header is PRESENT and names the right flavour on a step-up rejection;</li>
 *   <li>the signal header is ABSENT on an ordinary, non-step-up error — the important negative,
 *       because a routine authz DENY must never pop an MFA prompt;</li>
 *   <li>the legacy free-text phrase is STILL in the message, byte for byte, so an OLD UI
 *       deployed against a NEW BFF keeps working (rolling deploy, both directions);</li>
 *   <li>the JSON body stays byte-identical to the pre-signal shape for EVERY error;</li>
 *   <li>status stays 403 — deliberately NOT 428.</li>
 * </ol>
 *
 * <p>The real end-to-end wire proof through actual gates lives in the controller tests
 * ({@code AdminSshKeyIssuanceControllerTest}, {@code BackupAdminControllerTest},
 * {@code PhoneManagementSuperadminControllerTest}); this class pins the renderer + exception
 * invariants directly so a regression cannot hide behind a mocked gate. That every OTHER gate site
 * also routes through this seam is guarded structurally by {@link StepUpEmissionSeamTest}.
 *
 * <h2>These literals are a CROSS-REPO contract — both halves must move together</h2>
 * The browser pins the SAME strings, and a mismatch is silent and total: a case-different header
 * name simply never matches, so the inline MFA dialog stops appearing with no error anywhere.
 * The client side lives in <b>hugmesh-admin-ui</b>:
 * <ul>
 *   <li>{@code src/app/mfa/step-up-error.ts} — {@code STEP_UP_SIGNAL_HEADER},
 *       {@code LEGACY_STEP_UP_PATTERN}, {@code SAFE_RETRY_HEADER};</li>
 *   <li>{@code src/app/mfa/step-up-error.spec.ts} — pins {@code 'X-Step-Up-Required'} and the same
 *       8-value {@code FLAVOURS} list ("pins the header name and the legacy phrase the two halves
 *       agree on").</li>
 * </ul>
 * If you change a literal here, change it there in the SAME change, and remember the two halves
 * deploy independently: a rolling deploy runs old-UI/new-BFF and new-UI/old-BFF simultaneously.
 */
class StepUpSignalContractTest {

    private final ApiExceptionHandler handler = new ApiExceptionHandler();

    /** The closed value vocabulary: every gate's retry-header constant. */
    private static final String[] VOCABULARY = {
            BackingServiceStepUpGate.STEP_UP_HEADER,
            BackupStepUpGate.STEP_UP_HEADER,
            DeviceTerminalStepUpGate.STEP_UP_HEADER,
            GoLiveStepUpGate.STEP_UP_HEADER,
            ImageGenStepUpGate.STEP_UP_HEADER,
            PhoneLockStepUpGate.STEP_UP_HEADER,
            ServiceStoreStepUpGate.STEP_UP_HEADER,
            SshKeyIssueStepUpGate.STEP_UP_HEADER,
    };

    // ── (1) the signal is present and names the flavour ────────────────────────────────

    @Test
    void stepUpRejection_carriesTheSignalHeader_namingTheRetryHeader() {
        ResponseEntity<Map<String, Object>> r = handler.handle(
                StepUpRequiredException.forRetryHeader(ImageGenStepUpGate.STEP_UP_HEADER,
                        "image build"));

        assertThat(r.getHeaders().getFirst(StepUpRequiredException.SIGNAL_HEADER))
                .isEqualTo("X-ImageGen-StepUp");
    }

    @Test
    void everyGateFlavour_roundTripsThroughTheSignalHeader() {
        // >= 3 DIFFERENT gates, and in fact all 8 — the value a client must set on retry is the
        // header NAME itself, so a NEW gate needs zero client change.
        for (String retryHeader : VOCABULARY) {
            ResponseEntity<Map<String, Object>> r = handler.handle(
                    StepUpRequiredException.forRetryHeader(retryHeader, "op"));
            assertThat(r.getHeaders().getFirst(StepUpRequiredException.SIGNAL_HEADER))
                    .as("flavour for %s", retryHeader)
                    .isEqualTo(retryHeader);
        }
    }

    @Test
    void theEightFlavours_areAllDistinct() {
        assertThat(VOCABULARY).doesNotHaveDuplicates().hasSize(8);
    }

    // ── (1a) THE LITERALS. Deliberately hard-coded, not derived from the constants ──────

    @Test
    void theSignalHeaderName_isExactlyXStepUpRequired() {
        // Hard-coded ON PURPOSE. Asserting against SIGNAL_HEADER would follow any edit to it, and
        // the UI pins the literal 'X-Step-Up-Required' (admin-ui src/app/mfa/step-up-error.spec.ts,
        // "pins the header name and the legacy phrase the two halves agree on"). Without this
        // assertion the constant can be re-cased to "X-Stepup-Required" and the BFF suite stays
        // GREEN while every browser silently stops recognising step-up — a header-name mismatch
        // produces no error, just a missing MFA dialog. Case and hyphenation are both load-bearing.
        assertThat(StepUpRequiredException.SIGNAL_HEADER).isEqualTo("X-Step-Up-Required");
    }

    @Test
    void theSignalHeaderReachesTheWireUnderThatExactName() {
        // The constant AND the rendered header, so a rename cannot slip through the renderer either.
        ResponseEntity<Map<String, Object>> r = handler.handle(
                StepUpRequiredException.forRetryHeader(BackupStepUpGate.STEP_UP_HEADER, "restore"));

        assertThat(r.getHeaders().getFirst("X-Step-Up-Required")).isEqualTo("X-Backup-StepUp");
    }

    @Test
    void theEightFlavourNames_areExactlyTheseLiterals() {
        // Byte-identical to the FLAVOURS list in admin-ui src/app/mfa/step-up-error.spec.ts. The
        // browser only trusts a value matching ^X-[A-Za-z0-9-]{1,60}-StepUp$ and IGNORES anything
        // else, falling back to the legacy phrase — so a renamed flavour degrades silently to the
        // old brittle behaviour instead of failing loudly. Which gate owns which literal is pinned
        // here; that the set has not GROWN a ninth member is pinned by
        // StepUpEmissionSeamTest.theGateFlavourVocabularyIsExactlyTheEightPinnedValues().
        assertThat(BackingServiceStepUpGate.STEP_UP_HEADER).isEqualTo("X-BackingServices-StepUp");
        assertThat(BackupStepUpGate.STEP_UP_HEADER).isEqualTo("X-Backup-StepUp");
        assertThat(DeviceTerminalStepUpGate.STEP_UP_HEADER).isEqualTo("X-Device-Terminal-StepUp");
        assertThat(GoLiveStepUpGate.STEP_UP_HEADER).isEqualTo("X-GoLive-StepUp");
        assertThat(ImageGenStepUpGate.STEP_UP_HEADER).isEqualTo("X-ImageGen-StepUp");
        assertThat(PhoneLockStepUpGate.STEP_UP_HEADER).isEqualTo("X-PhoneLock-StepUp");
        assertThat(ServiceStoreStepUpGate.STEP_UP_HEADER).isEqualTo("X-ServiceStore-StepUp");
        assertThat(SshKeyIssueStepUpGate.STEP_UP_HEADER).isEqualTo("X-SshKeyIssue-StepUp");
    }

    // ── (2) THE NEGATIVE: an ordinary error carries NO signal ──────────────────────────

    @Test
    void ordinaryForbidden_hasNoSignalHeader() {
        // A routine authz failure (own-domain DENY, no active license, role floor...) must NEVER
        // pop an MFA prompt in the browser.
        ResponseEntity<Map<String, Object>> r =
                handler.handle(ApiException.forbidden("no active SSH license for this device"));

        assertThat(r.getStatusCode().value()).isEqualTo(403);
        assertThat(r.getHeaders().containsHeader(StepUpRequiredException.SIGNAL_HEADER)).isFalse();
    }

    @ParameterizedTest
    @ValueSource(ints = {400, 401, 404, 409, 410, 422, 502, 503})
    void noOtherStatus_everCarriesTheSignalHeader(int status) {
        ResponseEntity<Map<String, Object>> r = handler.handle(
                new ApiException(HttpStatus.valueOf(status), "boom"));

        assertThat(r.getHeaders().containsHeader(StepUpRequiredException.SIGNAL_HEADER)).isFalse();
    }

    // ── (3) the legacy phrase survives — old UI + new BFF ──────────────────────────────

    @Test
    void canonicalMessage_isByteIdenticalToThePreSignalHandBuiltString() {
        // This is the EXACT string the 17 uniform call sites built before centralisation. If this
        // assertion ever fails, an OLD admin-ui's /requires step-up/i sniff has been broken.
        assertThat(StepUpRequiredException
                .forRetryHeader(ImageGenStepUpGate.STEP_UP_HEADER, "image build").getMessage())
                .isEqualTo("image build requires step-up re-authentication "
                        + "(present X-ImageGen-StepUp)");
    }

    @Test
    void everyFlavourMessage_containsTheLegacyPhrase() {
        for (String retryHeader : VOCABULARY) {
            assertThat(StepUpRequiredException.forRetryHeader(retryHeader, "op").getMessage())
                    .as("legacy fallback phrase for %s", retryHeader)
                    .contains(StepUpRequiredException.LEGACY_PHRASE);
        }
    }

    @Test
    void theLegacyPhrase_isExactlyWhatTheOldUiGreppedFor() {
        // admin-ui src/app/mfa/step-up-error.ts pinned /requires step-up/i.
        assertThat(StepUpRequiredException.LEGACY_PHRASE).isEqualTo("requires step-up");
    }

    // ── (4) the JSON body did not move ─────────────────────────────────────────────────

    @Test
    void body_staysExactlyTheSingleErrorKey_evenWithTheSignal() {
        ResponseEntity<Map<String, Object>> stepUp = handler.handle(
                StepUpRequiredException.forRetryHeader(GoLiveStepUpGate.STEP_UP_HEADER,
                        "recording a go-live intent"));
        ResponseEntity<Map<String, Object>> plain = handler.handle(ApiException.forbidden("nope"));

        assertThat(stepUp.getBody()).containsOnlyKeys("error");
        assertThat(stepUp.getBody()).containsEntry("error",
                "recording a go-live intent requires step-up re-authentication "
                        + "(present X-GoLive-StepUp)");
        assertThat(plain.getBody()).isEqualTo(Map.of("error", "nope"));
    }

    // ── (5) status stays 403, never 428 ────────────────────────────────────────────────

    @Test
    void stepUpRejection_is403_not428() {
        StepUpRequiredException ex = StepUpRequiredException.forRetryHeader(
                BackupStepUpGate.STEP_UP_HEADER, "restore");

        // Numeric, not the enum constant: HttpStatusAssertionStyleTest bans enum-identity status
        // assertions repo-wide (aliased constants share a code but are not equal), and this
        // assertion was violating that guard — the feature branch turned main's suite red.
        assertThat(ex.status().value()).isEqualTo(403);
        assertThat(handler.handle(ex).getStatusCode().value()).isEqualTo(403);
    }

    // ── the verbatim escape hatch (cloud-backup's pre-template wording) ───────────────

    @Test
    void withMessage_keepsTheCallersWordingVerbatim_andStillSignals() {
        String verbatim = "restore " + StepUpRequiredException.LEGACY_PHRASE
                + ": present a valid step-up token in the "
                + BackupStepUpGate.STEP_UP_HEADER + " header";

        ResponseEntity<Map<String, Object>> r = handler.handle(
                StepUpRequiredException.withMessage(BackupStepUpGate.STEP_UP_HEADER, verbatim));

        // byte-identical to the pre-change cloud-backup message
        assertThat(r.getBody()).containsEntry("error", "restore requires step-up: present a valid "
                + "step-up token in the X-Backup-StepUp header");
        assertThat(r.getHeaders().getFirst(StepUpRequiredException.SIGNAL_HEADER))
                .isEqualTo("X-Backup-StepUp");
    }

    @Test
    void withMessage_aHostileCallerCannotProduceAPhraselessRejection() {
        // rv2 M-G: a withMessage caller rewords its text to DROP "requires step-up" entirely.
        // Only the per-site controller message pins used to catch that — no repo-wide invariant
        // forced a composed message to keep the old-client contract. The type itself must be
        // unable to mint a rejection an old (phrase-sniffing) UI cannot recognise: when the
        // caller's wording lacks the phrase, the constructor appends it.
        ResponseEntity<Map<String, Object>> r = handler.handle(StepUpRequiredException.withMessage(
                BackupStepUpGate.STEP_UP_HEADER,
                "restore needs a second factor: present a valid token in the X-Backup-StepUp header"));

        assertThat((String) r.getBody().get("error"))
                .as("the emitted message must STILL carry the legacy phrase an old UI greps for "
                        + "(admin-ui /requires step-up/i), no matter what the caller passed")
                .containsIgnoringCase(StepUpRequiredException.LEGACY_PHRASE)
                .startsWith("restore needs a second factor");
        assertThat(r.getHeaders().getFirst(StepUpRequiredException.SIGNAL_HEADER))
                .isEqualTo("X-Backup-StepUp");
    }

    @Test
    void withMessage_aNullMessageStillCarriesThePhraseAndTheSignal() {
        // Defensive corner: a null message must not NPE the renderer (Map.of rejects null) and
        // must still honour both halves of the contract.
        ResponseEntity<Map<String, Object>> r = handler.handle(StepUpRequiredException.withMessage(
                ImageGenStepUpGate.STEP_UP_HEADER, null));

        assertThat((String) r.getBody().get("error"))
                .containsIgnoringCase(StepUpRequiredException.LEGACY_PHRASE);
        assertThat(r.getHeaders().getFirst(StepUpRequiredException.SIGNAL_HEADER))
                .isEqualTo("X-ImageGen-StepUp");
    }

    @Test
    void withMessage_aMessageAlreadyCarryingThePhrase_staysVerbatim() {
        // The old client's sniff is /requires step-up/i, so a cased variant already satisfies
        // the contract and must NOT be reworded — withMessage's whole point is verbatim wording.
        String cased = "restore Requires Step-Up right now";

        assertThat(StepUpRequiredException.withMessage(BackupStepUpGate.STEP_UP_HEADER, cased)
                .getMessage()).isEqualTo(cased);
    }

    // ── header-injection tripwire: a bad value can never reach the wire ───────────────

    @ParameterizedTest
    @ValueSource(strings = {
            "X-Evil-StepUp\r\nSet-Cookie: a=b",   // CRLF response splitting
            "Authorization",                       // not a gate constant
            "x-imagegen-stepup",                   // wrong shape (lower-case prefix)
            "",
    })
    void aRetryHeaderThatIsNotAGateConstant_throwsAtConstruction(String bogus) {
        assertThatThrownBy(() -> StepUpRequiredException.forRetryHeader(bogus, "op"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("X-<flavour>-StepUp");
    }

    @Test
    void aNullRetryHeader_throwsAtConstruction() {
        assertThatThrownBy(() -> StepUpRequiredException.forRetryHeader(null, "op"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void everyRealGateConstant_passesTheTripwire() {
        for (String retryHeader : VOCABULARY) {
            assertThat(StepUpRequiredException.forRetryHeader(retryHeader, "op").retryHeader())
                    .isEqualTo(retryHeader);
        }
    }
}
