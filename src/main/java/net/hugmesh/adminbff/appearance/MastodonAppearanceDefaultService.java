package net.hugmesh.adminbff.appearance;

import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.web.ApiException;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Owner-of-the-brand ADMIN-write-gated, per-domain PLATFORM-WIDE default appearance for
 * the hugmesh-mastodon-ui remote's {@code PreferencesService}. A non-customised user
 * inherits this default (ahead of the client's built-in default); an ADMIN configures it.
 *
 * <p>Field vocabulary mirrors {@code PreferencesService.AppearancePreferences} in
 * hugmesh-mastodon-ui EXACTLY (same field names, same allowed values) and the paired
 * PER-USER {@code mastodon.appearance.*} keys in hugmesh-user-bff-api's
 * {@code UserPreferencesService} — so an admin default and a user override are always
 * mutually intelligible.
 *
 * <p>{@link #get} returns ONLY the fields an admin has explicitly configured — a fresh
 * brand with no admin default returns an EMPTY map, which is the honest signal "no
 * platform-wide opinion yet, the client's built-in default applies". This is intentionally
 * the same "absence-is-meaningful" resolution as the per-user appearance keys, NOT a
 * defaults-merge (there is nothing further to merge in here — the client is the final
 * fallback).
 */
@Service
public class MastodonAppearanceDefaultService {

    public static final String THEME = "theme";
    public static final String ACCENT = "accent";
    public static final String APPEARANCE = "appearance";
    public static final String LAYOUT = "layout";
    public static final String DENSITY = "density";
    public static final String MEDIA_CORNERS = "mediaCorners";
    public static final String FONT = "font";
    public static final String TEXT_SIZE = "textSize";
    public static final String HIGH_CONTRAST = "highContrast";
    public static final String REDUCED_MOTION = "reducedMotion";

    private static final Set<String> BOOLEAN_KEYS = Set.of(HIGH_CONTRAST, REDUCED_MOTION);

    private static final Set<String> KNOWN_KEYS = Set.of(
            THEME, ACCENT, APPEARANCE, LAYOUT, DENSITY, MEDIA_CORNERS, FONT, TEXT_SIZE,
            HIGH_CONTRAST, REDUCED_MOTION);

    private static final Set<String> THEME_VALUES =
            Set.of("snap-neon", "pastel-rose", "pastel-sky", "pastel-mint", "mono");
    private static final Set<String> ACCENT_VALUES =
            Set.of("neon", "rose", "lavender", "sky", "mint", "peach");
    private static final Set<String> APPEARANCE_VALUES = Set.of("auto", "light", "dark");
    private static final Set<String> LAYOUT_VALUES = Set.of("single", "multi");
    private static final Set<String> DENSITY_VALUES = Set.of("comfortable", "compact");
    private static final Set<String> MEDIA_CORNERS_VALUES = Set.of("rounded", "square");
    private static final Set<String> FONT_VALUES = Set.of("system", "serif", "mono", "dyslexic");
    private static final Set<String> TEXT_SIZE_VALUES = Set.of("sm", "md", "lg", "xl");
    private static final Set<String> BOOLEAN_VALUES = Set.of("true", "false");

    private final MastodonAppearanceDefaultRepository repo;

    public MastodonAppearanceDefaultService(MastodonAppearanceDefaultRepository repo) {
        this.repo = repo;
    }

    /** The brand's currently-configured default (typed: booleans as real booleans, so the
     *  JSON shape matches {@code AppearancePreferences} exactly). Empty map = no admin
     *  default configured for this brand yet. */
    public Mono<Map<String, Object>> get(String domain) {
        String dom = requireDomain(domain);
        return repo.findAll(dom).map(MastodonAppearanceDefaultService::typed);
    }

    /**
     * ADMIN-only: upsert every field present in {@code prefs} (a partial or full
     * AppearancePreferences-shaped map) as the brand's new default, then return the
     * resolved (typed) view. Every key must be a known field and every value must be one
     * of that field's allowed values — a client can never persist a key/value the
     * mastodon-ui panel can't honour. An EMPTY {@code prefs} is a no-op 400 (nothing to
     * set) so a caller never silently "succeeds" at doing nothing.
     */
    public Mono<Map<String, Object>> put(Map<String, Object> prefs, String domain, String actor) {
        String dom = requireDomain(domain);
        if (prefs == null || prefs.isEmpty()) {
            return Mono.error(ApiException.badRequest("prefs must contain at least one field"));
        }
        List<Mono<Void>> upserts = new ArrayList<>();
        for (Map.Entry<String, Object> e : prefs.entrySet()) {
            String key = e.getKey() == null ? "" : e.getKey().trim();
            if (!KNOWN_KEYS.contains(key)) {
                return Mono.error(ApiException.badRequest("unknown appearance field: " + key));
            }
            String value = normalizeValue(key, e.getValue());
            upserts.add(repo.upsert(dom, key, value, actor == null ? "admin" : actor));
        }
        return Flux.merge(upserts).then(get(dom));
    }

    private static Map<String, Object> typed(Map<String, String> stored) {
        Map<String, Object> out = new LinkedHashMap<>();
        stored.forEach((k, v) -> out.put(k, BOOLEAN_KEYS.contains(k) ? Boolean.valueOf(v) : v));
        return out;
    }

    private static String normalizeValue(String key, Object rawValue) {
        if (rawValue == null) {
            throw ApiException.badRequest(key + " must not be null");
        }
        if (BOOLEAN_KEYS.contains(key)) {
            if (rawValue instanceof Boolean b) return b.toString();
            String s = rawValue.toString().trim().toLowerCase();
            if (!BOOLEAN_VALUES.contains(s)) {
                throw ApiException.badRequest(key + " must be true|false");
            }
            return s;
        }
        String v = rawValue.toString().trim();
        Set<String> allowed = allowedValuesFor(key);
        if (!allowed.contains(v)) {
            throw ApiException.badRequest(key + " must be one of: " + String.join("|", sorted(allowed)));
        }
        return v;
    }

    private static Set<String> allowedValuesFor(String key) {
        if (key.equals(THEME)) return THEME_VALUES;
        if (key.equals(ACCENT)) return ACCENT_VALUES;
        if (key.equals(APPEARANCE)) return APPEARANCE_VALUES;
        if (key.equals(LAYOUT)) return LAYOUT_VALUES;
        if (key.equals(DENSITY)) return DENSITY_VALUES;
        if (key.equals(MEDIA_CORNERS)) return MEDIA_CORNERS_VALUES;
        if (key.equals(FONT)) return FONT_VALUES;
        return TEXT_SIZE_VALUES;
    }

    private static List<String> sorted(Set<String> values) {
        List<String> list = new ArrayList<>(values);
        Collections.sort(list);
        return list;
    }

    private static String requireDomain(String domain) {
        if (domain == null || domain.isBlank()) {
            throw ApiException.unauthorized("missing resolvable tenant domain");
        }
        return domain;
    }
}
