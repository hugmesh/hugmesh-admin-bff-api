package net.hugmesh.adminbff.announcement;

import java.util.regex.Pattern;

/**
 * Builds the text of the {@code @system} per-user notice: a Mastodon-API {@code direct}
 * status that @-mentions its one recipient. Both transports that post such a notice
 * ({@link AnnouncementMastodonClient#postLocalUserNotice} and the notification channel's
 * {@code AkkomaSystemNoticeClient}) build the status here, so the rules below hold on
 * either path. It lives in this package because {@code notification.channel} already
 * depends on it and not the other way round.
 *
 * <h3>Why the text is rewritten</h3>
 * A {@code direct} status is delivered to every account its text mentions, and the notice
 * text carries the moderator's free-text reason verbatim. Posted as typed, a reason such as
 * {@code reported by @carol} sends the recipient's restriction notice to {@code carol} as
 * well, and {@code @carol@other.example} names an account on another server, which Akkoma
 * and Mastodon both look up over the network when they do not know it. So:
 * <ul>
 *   <li><b>The recipient's mention is the only at-sign in the status.</b> Every at-sign in
 *       the title and body is written {@value #AT_REPLACEMENT}: {@code @}, and the two code
 *       points Unicode normalisation folds to it (U+FE6B, U+FF20). The rule has no context
 *       on purpose. Where a mention may start differs per server (Akkoma reads
 *       {@code x:<br>@carol} as one, Mastodon {@code (@carol)}), so anything cleverer would
 *       have to track each server's grammar. The cost is that an e-mail address or a
 *       profile link in a reason is shown with {@value #AT_REPLACEMENT} too.</li>
 *   <li><b>The status holds no less-than sign.</b> Akkoma escapes HTML in plain text but
 *       leaves a link-like token as it is, and its default output filter keeps anchors and
 *       images. So {@code x:<a/href=https://other.example>https://this.example/appeal</a>}
 *       is served as a link that shows one address and opens another, and
 *       {@code x:<img/src=...>} as an image the reader's client fetches. Every {@code <}
 *       (and U+226E, U+FE64, U+FF1C, which normalisation turns into text holding one) is
 *       written {@value #LESS_THAN_REPLACEMENT}, so nothing in the notice can open a
 *       tag.</li>
 *   <li><b>The recipient name is one that every mention grammar reads whole.</b> Both
 *       servers drop trailing punctuation from a mention ({@code @bob.} reaches
 *       {@code bob}) and Mastodon also stops before a trailing {@code -}, so only
 *       {@code [a-z0-9_]}, 1 to {@value #MAX_LOCALPART_CHARS} characters, is
 *       {@linkplain #addressable addressable}. That is also the only shape the account
 *       broker gives a fediverse account ({@code ServiceTokenBroker.mastodonLocalpart}).</li>
 *   <li>The status is capped at {@value #MAX_STATUS_CHARS} characters, so a long reason is
 *       shortened and not rejected by the server.</li>
 * </ul>
 * The transports add a second, Akkoma-only guard on top: they name the recipient in the
 * request's {@code to} field, which makes Akkoma address exactly that nickname and ignore
 * mentions in the text.
 *
 * <h3>What is left as typed</h3>
 * Hashtags, links and {@code :emoji:} shortcodes. The server turns them into tag links,
 * anchors that show their own target, and images, which changes how the notice looks and
 * not who receives it or who can see it: neither server puts a {@code direct} status on a
 * hashtag timeline or sends it to a hashtag's followers. No content type is sent, so both
 * servers take the text as plain text and apply no Markdown or BBCode to it.
 *
 * <p><b>Verification status.</b> Which strings each server reads as a mention, and what
 * Akkoma serves for a tag inside a link-like token, were measured by running Akkoma
 * 3.20.1's own formatter and output filter and Mastodon 4.3.1's mention pattern over them
 * offline. The remote-handle lookup, the hashtag visibility rule, the plain-text default and
 * the effect of the {@code to} field are read from the two servers' sources. No notice has
 * been posted to a running Akkoma.
 */
public final class AkkomaNoticeText {

    /** Akkoma's default {@code max_toot_chars} is 5000 (Mastodon: 500); stay well inside it. */
    public static final int MAX_STATUS_CHARS = 4000;

    /** The longest recipient name that is accepted. */
    public static final int MAX_LOCALPART_CHARS = 64;

    /** What every at-sign in the notice's title and body is written as. */
    static final String AT_REPLACEMENT = "(at)";

    /** What every less-than sign is written as: U+2039, which no parser reads as markup. */
    static final String LESS_THAN_REPLACEMENT = "\u2039";

    private static final Pattern LOCALPART = Pattern.compile("[a-z0-9_]+");

    private AkkomaNoticeText() {
    }

    /**
     * Whether {@code localpart} can be the recipient of a notice: lower-case letters, digits
     * and underscores only, 1 to {@value #MAX_LOCALPART_CHARS} characters. Any other name is
     * one no broker-created account has, and one a server could read as a mention of
     * somebody else.
     */
    public static boolean addressable(String localpart) {
        return localpart != null
                && localpart.length() <= MAX_LOCALPART_CHARS
                && LOCALPART.matcher(localpart).matches();
    }

    /**
     * The status to post: the recipient's mention, a space, and {@code text}
     * {@linkplain #neutralise neutralised}, capped at {@value #MAX_STATUS_CHARS} characters.
     *
     * @throws IllegalArgumentException if {@code localpart} is not {@link #addressable}
     */
    public static String status(String localpart, String text) {
        if (!addressable(localpart)) {
            throw new IllegalArgumentException("not an addressable recipient name");
        }
        return cap("@" + localpart + " " + neutralise(text));
    }

    /**
     * {@code text} with every at-sign written {@value #AT_REPLACEMENT} and every less-than
     * sign written {@value #LESS_THAN_REPLACEMENT}; everything else is kept as it is. Null
     * is the empty string.
     */
    public static String neutralise(String text) {
        if (text == null) {
            return "";
        }
        StringBuilder out = null;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            String written = replacementFor(c);
            if (written != null) {
                if (out == null) {
                    out = new StringBuilder(text.length() + 16).append(text, 0, i);
                }
                out.append(written);
            } else if (out != null) {
                out.append(c);
            }
        }
        return out == null ? text : out.toString();
    }

    /**
     * The stand-in for a sign a server could read as markup, or null for any other char.
     * Every code point listed is in the Basic Multilingual Plane, so a per-char scan cannot
     * split one.
     */
    private static String replacementFor(char c) {
        return switch (c) {
            case '@', '\uFE6B', '\uFF20' -> AT_REPLACEMENT;
            case '<', '\u226E', '\uFE64', '\uFF1C' -> LESS_THAN_REPLACEMENT;
            default -> null;
        };
    }

    /** Shorten to the cap with an ellipsis, never cutting a surrogate pair in half. */
    private static String cap(String status) {
        if (status.length() <= MAX_STATUS_CHARS) {
            return status;
        }
        int end = MAX_STATUS_CHARS - 1;
        if (Character.isHighSurrogate(status.charAt(end - 1))) {
            end--;
        }
        return status.substring(0, end) + "\u2026";
    }
}
