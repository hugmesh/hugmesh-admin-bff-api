package net.hugmesh.adminbff.announcement;

import java.text.Normalizer;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.TreeSet;

/**
 * Test-side model of who a Mastodon-API server delivers a {@code direct} status to when it
 * derives the recipients from the status TEXT, shared by the two {@code @system} notice
 * client tests.
 *
 * <p>A {@code direct} status goes to every account its text mentions. The two servers this
 * code has been pointed at read mentions differently. Both were run offline over the inputs
 * below: Akkoma 3.20.1's own formatter and link parser, and the {@code MENTION_RE} of
 * Mastodon 4.3.1.
 * <ul>
 *   <li><b>Both</b> read {@code "Reason: reported by @carol."} as a mention of {@code carol},
 *       drop a trailing {@code , . ; : ? !} (so {@code "@bob."} mentions {@code bob}), and
 *       read {@code "x:<br>@carol"} as a mention although no whitespace precedes the
 *       at-sign.</li>
 *   <li><b>Mastodon only</b>: an at-sign that does not follow {@code =}, {@code /} or a word
 *       character starts a mention, so {@code "(@carol)"}, a tab or a zero-width space
 *       before the at-sign, and {@code "<b>@carol</b>"} all mention; the name also stops
 *       before a trailing {@code -}, so {@code "@bob-"} mentions {@code bob}.</li>
 *   <li><b>Neither</b> reads the fullwidth or the small at-sign.</li>
 * </ul>
 *
 * <p>{@link #addressedByText} is deliberately STRICTER than either: any at-sign, wherever it
 * stands, followed by an account's name and then by anything that cannot continue a name,
 * counts as addressing that account. It also treats the two code points that Unicode
 * compatibility normalisation folds to an at-sign as at-signs. Text that names only the
 * recipient under this rule names only the recipient under both real grammars; the reverse
 * does not hold, so this is a demonstration that a recipient can be added, never a proof
 * that one cannot. The parser-independent check is {@link #atSigns}: one at-sign, at the
 * start, leaves nothing for any mention grammar to read. {@link #lessThans} is the same
 * kind of check for markup: no less-than sign, nothing that can open a tag.
 */
public final class FediverseAddressing {

    /**
     * Free-text reasons that name an account other than the recipient. Every one of them is
     * read as a mention of {@code carol} by {@link #addressedByText}; the comments say which
     * real server does too.
     */
    public static final List<String> REASONS_NAMING_SOMEONE_ELSE = List.of(
            "reported by @carol",              // both
            "@carol",                          // both
            "see\n@carol\nthanks",             // both
            "cc @carol, @bob",                 // both, two extra recipients
            "@carol@remote.social",            // both: a remote account
            "x:<br>@carol",                    // both; on Akkoma with no whitespace before the at-sign
            "(@carol)",                        // Mastodon only
            "\t@carol",                        // Mastodon only
            "@CAROL",                          // both: the name is offered as typed, lookup ignores case
            "@carol's",                        // Mastodon only
            "<b>@carol</b>",                   // Mastodon only
            "@alice @carol",                   // both
            "\u200B@carol",                    // Mastodon only: a zero-width space is not a word character
            "\uFF20carol",                     // neither today; NFKC folds the fullwidth sign to '@'
            "\uFE6Bcarol");                    // neither today; NFKC folds the small sign to '@'

    /**
     * Free-text reasons that carry a tag. Akkoma 3.20.1 escapes HTML in plain text except
     * inside a link-like token, and its default output filter keeps anchors and images:
     * the first is served as a link showing one address and opening another, the second as
     * an image fetched from the named host (both measured offline). The last three hold no
     * {@code <} today but Unicode normalisation turns each into text that does.
     */
    public static final List<String> REASONS_CARRYING_A_TAG = List.of(
            "x:<a/href=https://evil.example>https://hugmesh.example/appeal</a>",
            "x:<img/src=https://evil.example/p.png>",
            "see:<script>alert(1)</script>",
            "plain <b>bold</b> and a < b",
            "x:\uFF1Ca/href=https://evil.example>appeal",
            "x:\uFE64a/href=https://evil.example>appeal",
            "a \u226E b");

    private FediverseAddressing() {
    }

    /** True for an at-sign and for a code point some Unicode normalisation form folds to text holding one. */
    public static boolean isAtSignClass(int codePoint) {
        return foldsTo(codePoint, '@');
    }

    /** True for a less-than sign and for a code point some normalisation form folds to text holding one. */
    public static boolean isLessThanClass(int codePoint) {
        return foldsTo(codePoint, '<');
    }

    private static boolean foldsTo(int codePoint, char sign) {
        if (codePoint == sign) {
            return true;
        }
        if (codePoint < 0x80 || (codePoint >= Character.MIN_SURROGATE && codePoint <= Character.MAX_SURROGATE)) {
            return false;
        }
        String s = new String(Character.toChars(codePoint));
        for (Normalizer.Form form : Normalizer.Form.values()) {
            if (Normalizer.normalize(s, form).indexOf(sign) >= 0) {
                return true;
            }
        }
        return false;
    }

    /** How many at-sign-class code points the text holds. */
    public static long atSigns(String text) {
        return text.codePoints().filter(FediverseAddressing::isAtSignClass).count();
    }

    /** How many less-than-class code points the text holds. */
    public static long lessThans(String text) {
        return text.codePoints().filter(FediverseAddressing::isLessThanClass).count();
    }

    /**
     * The accounts (lower-case names) the status would be delivered to under the
     * stricter-than-real rule in the class comment.
     */
    public static Set<String> addressedByText(String status, Collection<String> accounts) {
        Set<String> addressed = new TreeSet<>();
        String lower = status.toLowerCase(Locale.ROOT);
        int i = 0;
        while (i < lower.length()) {
            int cp = lower.codePointAt(i);
            i += Character.charCount(cp);
            if (isAtSignClass(cp)) {
                for (String account : accounts) {
                    if (lower.startsWith(account, i) && !continuesAName(lower, i + account.length())) {
                        addressed.add(account);
                    }
                }
            }
        }
        return addressed;
    }

    private static boolean continuesAName(String s, int at) {
        if (at >= s.length()) {
            return false;
        }
        char c = s.charAt(at);
        return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
    }
}
