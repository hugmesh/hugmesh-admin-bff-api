package net.hugmesh.adminbff.announcement;

import org.junit.jupiter.api.Test;

import java.text.Normalizer;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.SoftAssertions.assertSoftly;

/**
 * The text rules of the {@code @system} notice ({@link AkkomaNoticeText}): the recipient's
 * mention is the only at-sign, nothing can open a tag, the recipient name is one every
 * mention grammar reads whole, and the status is capped. These are checked on the string
 * itself, with no model of any server's parser; the two transport tests show the same
 * rules on the wire.
 */
class AkkomaNoticeTextTest {

    // ── at-signs ─────────────────────────────────────────────────────────────

    @Test
    void everyCodePointThatIsOrFoldsToAnAtSign_isWrittenAsText() {
        List<Integer> atSigns = new ArrayList<>();
        for (int cp = 0; cp <= Character.MAX_CODE_POINT; cp++) {
            if (FediverseAddressing.isAtSignClass(cp)) {
                atSigns.add(cp);
            }
        }
        // The sweep is not vacuous: it finds the plain sign and the two compatibility forms.
        assertThat(atSigns).contains((int) '@', 0xFE6B, 0xFF20);
        for (int cp : atSigns) {
            String out = AkkomaNoticeText.neutralise("a" + new String(Character.toChars(cp)) + "carol");
            assertThat(out).as("U+%04X", cp).isEqualTo("a(at)carol");
        }
    }

    @Test
    void everyCodePointThatIsOrFoldsToALessThanSign_isWrittenAsAGlyphThatOpensNoTag() {
        List<Integer> lessThans = new ArrayList<>();
        for (int cp = 0; cp <= Character.MAX_CODE_POINT; cp++) {
            if (FediverseAddressing.isLessThanClass(cp)) {
                lessThans.add(cp);
            }
        }
        assertThat(lessThans).contains((int) '<', 0x226E, 0xFE64, 0xFF1C);
        for (int cp : lessThans) {
            String out = AkkomaNoticeText.neutralise("x:" + new String(Character.toChars(cp)) + "a/href=y>");
            assertThat(out).as("U+%04X", cp).isEqualTo("x:\u2039a/href=y>");
        }
    }

    @Test
    void theStandIns_surviveEveryNormalisationFormWithoutBecomingASign() {
        // Whatever a server normalises the text to, the stand-ins must not turn back into
        // the signs they replace.
        String neutral = AkkomaNoticeText.neutralise("@carol \uFF20bob \uFE6Bdan <a> \uFF1Cb \uFE64c \u226E");
        for (Normalizer.Form form : Normalizer.Form.values()) {
            String normalised = Normalizer.normalize(neutral, form);
            assertThat(normalised).as("%s", form).doesNotContain("@").doesNotContain("<");
        }
    }

    @Test
    void aStatusBuiltFromAHostileReason_hasOneAtSignAtTheStart_inEveryNormalisationForm() {
        assertSoftly(soft -> {
            List<String> reasons = new ArrayList<>(FediverseAddressing.REASONS_NAMING_SOMEONE_ELSE);
            reasons.addAll(FediverseAddressing.REASONS_CARRYING_A_TAG);
            for (String reason : reasons) {
                String status = AkkomaNoticeText.status("alice", "Title\n\nReason: " + reason + ".");
                for (Normalizer.Form form : Normalizer.Form.values()) {
                    String normalised = Normalizer.normalize(status, form);
                    soft.assertThat(normalised).as("%s of [%s]", form, status).startsWith("@alice Title");
                    soft.assertThat(normalised.indexOf('@', 1)).as("second at-sign in %s of [%s]", form, status)
                            .isEqualTo(-1);
                    soft.assertThat(normalised.indexOf('<')).as("less-than in %s of [%s]", form, status)
                            .isEqualTo(-1);
                }
            }
        });
    }

    // ── what is left as typed ────────────────────────────────────────────────

    @Test
    void textWithNeitherSign_isReturnedUnchanged() {
        String plain = "Your account access changed.\n\nReason: spam \uD83D\uDE00 > quoted, 5 > 3 & \"x\".";
        assertThat(AkkomaNoticeText.neutralise(plain)).isSameAs(plain);
        assertThat(AkkomaNoticeText.neutralise("")).isEmpty();
        assertThat(AkkomaNoticeText.neutralise(null)).isEmpty();
    }

    @Test
    void hashtagsLinksAndEmojiShortcodes_areLeftAsTyped() {
        // Deliberate: the server renders these (a tag link, an anchor showing its own
        // target, an image) but none of them changes who receives or can see the notice.
        String typed = "rule #3, #nsfw, see https://example.org/rules and example.org :blobcat:";
        assertThat(AkkomaNoticeText.neutralise(typed)).isEqualTo(typed);
        assertThat(AkkomaNoticeText.status("alice", typed)).isEqualTo("@alice " + typed);
    }

    @Test
    void anEmailAddressOrProfileLink_losesItsAtSignToo() {
        // The price of having no context rules: neither is a mention on the two servers
        // measured, and both are rewritten anyway.
        assertThat(AkkomaNoticeText.neutralise("write to help@example.org or see https://remote.social/@carol"))
                .isEqualTo("write to help(at)example.org or see https://remote.social/(at)carol");
    }

    @Test
    void neutralisingTwice_changesNothingMore() {
        String once = AkkomaNoticeText.neutralise("@carol <b> \uFF20x");
        assertThat(AkkomaNoticeText.neutralise(once)).isSameAs(once);
    }

    // ── the status ───────────────────────────────────────────────────────────

    @Test
    void status_isTheMentionASpaceAndTheNeutralisedText() {
        assertThat(AkkomaNoticeText.status("alice", "Title\n\nReason: reported by @carol."))
                .isEqualTo("@alice Title\n\nReason: reported by (at)carol.");
        assertThat(AkkomaNoticeText.status("alice", null)).isEqualTo("@alice ");
    }

    @Test
    void status_refusesARecipientNameThatIsNotAddressable() {
        for (String bad : new String[] {null, "", "bob.", "alice @carol", "Alice"}) {
            assertThatThrownBy(() -> AkkomaNoticeText.status(bad, "x")).as("localpart=[%s]", bad)
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Test
    void status_isCappedWithAnEllipsis() {
        String status = AkkomaNoticeText.status("alice", "y".repeat(9000));
        assertThat(status).hasSize(AkkomaNoticeText.MAX_STATUS_CHARS).startsWith("@alice yyy").endsWith("\u2026");
        // exactly at the cap: untouched
        String fits = AkkomaNoticeText.status("alice", "y".repeat(AkkomaNoticeText.MAX_STATUS_CHARS - 7));
        assertThat(fits).hasSize(AkkomaNoticeText.MAX_STATUS_CHARS).endsWith("y");
    }

    @Test
    void theCap_neverCutsASurrogatePairInHalf() {
        // "@alice " is 7 chars; pad so that an emoji's two chars straddle the cut point.
        String emoji = "\uD83D\uDE00";
        for (int pad = 0; pad < 4; pad++) {
            String status = AkkomaNoticeText.status("alice", "y".repeat(pad) + emoji.repeat(3000));
            assertThat(status.length()).as("pad=%d", pad).isLessThanOrEqualTo(AkkomaNoticeText.MAX_STATUS_CHARS);
            assertThat(status).as("pad=%d", pad).endsWith("\u2026");
            String body = status.substring(0, status.length() - 1);
            assertThat(Character.isHighSurrogate(body.charAt(body.length() - 1))).as("pad=%d", pad).isFalse();
            assertThat(body.codePoints().filter(cp -> cp >= Character.MIN_SURROGATE && cp <= Character.MAX_SURROGATE)
                    .count()).as("lone surrogates, pad=%d", pad).isZero();
        }
    }

    @Test
    void theCap_isAppliedAfterNeutralising() {
        // 2000 at-signs grow to 8000 chars; the result is still capped and still has one at-sign.
        String status = AkkomaNoticeText.status("alice", "@".repeat(2000));
        assertThat(status.length()).isLessThanOrEqualTo(AkkomaNoticeText.MAX_STATUS_CHARS);
        assertThat(FediverseAddressing.atSigns(status)).isEqualTo(1);
    }

    // ── the recipient name ───────────────────────────────────────────────────

    @Test
    void addressable_isLowerCaseLettersDigitsAndUnderscores_upToSixtyFour() {
        for (String ok : new String[] {"alice", "a", "0", "_", "a_b", "_alice", "alice_", "a__b", "user_42",
            "a".repeat(AkkomaNoticeText.MAX_LOCALPART_CHARS)}) {
            assertThat(AkkomaNoticeText.addressable(ok)).as("[%s]", ok).isTrue();
        }
    }

    @Test
    void addressable_refusesANameAParserWouldShortenSplitOrNotReadAtAll() {
        for (String bad : new String[] {null, "", " ", "Alice", "alice ", " alice", "al ice",
            // trailing punctuation is dropped by both servers: "@bob." reaches "bob"
            "bob.", "bob..", "bob,", "bob!", "bob?", "bob:", "bob;",
            // Mastodon stops before a trailing hyphen: "@bob-" reaches "bob"
            "bob-", "-bob", ".bob",
            // separators inside: never an account the broker creates
            "bob.smith", "b-ob", "a..b",
            // anything that could start or carry another mention or a tag
            "alice@evil.test", "alice @bob", "alice\n@bob", "a@b", "bob)", "bob/", "bob's", "bob<", "b>ob",
            "bob\tx", "bob\u200B", "b\u00F6b", "\uFF42ob", "a&b=c",
            "a".repeat(AkkomaNoticeText.MAX_LOCALPART_CHARS + 1)}) {
            assertThat(AkkomaNoticeText.addressable(bad)).as("[%s]", bad).isFalse();
        }
    }
}
