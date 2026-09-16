package net.hugmesh.adminbff;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * STRUCTURAL guard on the legacy user-facing surface of {@link AuthController}: the set of
 * request mappings it declares is PINNED here, so retiring one is a deliberate act that has to
 * come through this file and read the evidence below first.
 *
 * <p><b>This guard does not oppose the retirement — it sequences it.</b> The operator's answer
 * on hugmesh-generator#347 decision 11 is <i>"retire them"</i>, with the caveat, in the same
 * line: <i>"If a probe shows a live consumer I will report it here rather than delete
 * quietly."</i> The probe showed live consumers on two of three lanes (below), so the paths
 * stay for now and the blockers are tracked (hugmesh-generator#366 for the two disagreeing route
 * tables). When a blocker is cleared, retiring the path means removing its mapping AND its
 * {@link #PINNED} entry in the same commit — one edit, with the evidence in front of you. If the
 * operator prefers no guard at all, delete this class; nothing at runtime depends on it.
 *
 * <h2>Why this guard exists</h2>
 * The operator's answer on hugmesh-admin-bff-api#2 is <b>"retire"</b>. That answer is on the
 * issue, so the next reader will try to carry it out — and on 2026-09-10 carrying it out would
 * have broken two of the three deployment lanes. The five paths the issue calls "shadowed" are
 * shadowed on the <b>kind/cluster lane only</b>. The measurement, in full, is in
 * {@link AuthController}'s class javadoc; the short version is:
 * <ul>
 *   <li>the cluster's DEPLOYED route table sends {@code /bff/register/**}, {@code /bff/me/**}
 *       and {@code /bff/provision/**} to user-bff, which implements none of them (so they 404
 *       there today — a generator routing defect, not a dead handler);</li>
 *   <li>the COMPOSE route table lists user-bff's paths exactly and has no {@code /bff/provision}
 *       entry at all, so all five fall through to the {@code /bff/**} admin-bff catch-all and
 *       are served by {@link AuthController};</li>
 *   <li>the DEVICE lane has no gateway: {@code tests/qemu/seed-accounts.sh} curls
 *       {@code POST /bff/register/google} straight at admin-bff on {@code 127.0.0.1:8403}.</li>
 * </ul>
 * Live callers on origin/main: login-ui's {@code bff.service.ts} POSTs both {@code /provision/*}
 * paths on every sign-in, and admin-ui's {@code bff.service.ts} fetches {@code /me/namespaces}.
 *
 * <h2>What trips it</h2>
 * Deleting a mapping trips it (the retirement this guards against) and so does ADDING one — a new
 * legacy user path deserves the same three-lane check. Either way the fix is to update
 * {@link #PINNED} <em>and</em> the audit in {@link AuthController}'s javadoc together. (Only the
 * MAPPINGS are scanned; the javadoc audit is not — so the pin catches a surface change, and the
 * failure message is what points the editor at the prose to update alongside it.)
 *
 * <h2>Documented limit</h2>
 * This reads source text, so it pins what the file DECLARES, not what the running app serves. A
 * mapping that survives here while its handler is gutted to a no-op is invisible to this test —
 * behaviour is {@code AuthControllerTest}'s job. What this guard alone can catch is the specific
 * failure mode that was one edit away: a wholesale deletion of these mappings on the strength of
 * "the cluster routes them elsewhere".
 */
class LegacyUserPathRetirementGuardTest {

    private static final Path CONTROLLER =
            Path.of("src/main/java/net/hugmesh/adminbff/AuthController.java");

    /**
     * Every mapping {@link AuthController} declares, as {@code METHOD /bff<path>}, mapped to the
     * reason it is still here. The five the issue calls "shadowed" carry their blocker; the rest
     * carry why they were never candidates.
     */
    private static final Map<String, String> PINNED = new LinkedHashMap<>();

    static {
        PINNED.put("POST /bff/register/google",
                "device lane calls it with no gateway at all: tests/qemu/seed-accounts.sh:408,464 "
                        + "curls it at http://127.0.0.1:8403 as the bootstrap fallback when a fresh "
                        + "mesh has no admin account. Unshadowed on compose too.");
        PINNED.put("POST /bff/register/discord",
                "no hand-written UI caller found (weakest case), but NOT shadowed on the compose or "
                        + "device lanes either, so unreachability is not established — only "
                        + "'uncalled by a UI'.");
        PINNED.put("POST /bff/login",
                "superseded by user-bff SsoAuthController POST /bff/login on cluster AND compose "
                        + "(both route the exact path there); still the device-lane login.");
        PINNED.put("POST /bff/login/local",
                "admin-bff only on every lane — user-bff has password RESET, not password LOGIN. "
                        + "login-ui bff.service.ts:314 fetches it directly.");
        PINNED.put("POST /bff/register/complete",
                "registration stage 2, admin-bff only, explicitly carved back out of the cluster's "
                        + "/bff/register/** route (20-gateway-fe.yaml). Deleting it stops onboarding.");
        PINNED.put("GET /bff/me",
                "superseded by user-bff GET /bff/me on the cluster; still served here on compose "
                        + "(the compose route lists /bff/me exactly) and on the device lane.");
        PINNED.put("GET /bff/me/namespaces",
                "admin-ui bff.service.ts:77 (myNamespaces()) fetches it; unshadowed on compose "
                        + "because the compose user-bff route is the EXACT path /bff/me.");
        PINNED.put("GET /bff/session",
                "superseded by user-bff GET /bff/session on cluster and compose (exact path both).");
        PINNED.put("POST /bff/sessionOut",
                "admin-bff only on every lane — user-bff's logout is DELETE /bff/session, a "
                        + "different verb and path. login-ui session.service.ts:444 (clear()) "
                        + "awaits it on every logout; admin-ui has no production caller.");
        PINNED.put("POST /bff/provision/matrix",
                "login-ui bff.service.ts provisionServiceTokens() POSTs it on every sign-in; the "
                        + "compose route table has NO /bff/provision entry, so compose serves it here.");
        PINNED.put("POST /bff/provision/mastodon",
                "same as /provision/matrix — same caller, same lane, plus "
                        + "tests/stack/seed-e2e.sh:547.");
    }

    /** {@code @GetMapping("/x")} / {@code @PostMapping("/x")} etc., capturing verb and path. */
    private static final Pattern MAPPING =
            Pattern.compile("@(Get|Post|Put|Delete|Patch)Mapping\\(\"([^\"]+)\"\\)");

    private static String source() {
        try {
            return Files.readString(CONTROLLER);
        } catch (IOException e) {
            throw new UncheckedIOException("cannot read " + CONTROLLER.toAbsolutePath(), e);
        }
    }

    private static Set<String> declaredMappings() {
        Set<String> found = new TreeSet<>();
        Matcher m = MAPPING.matcher(source());
        while (m.find()) {
            found.add(m.group(1).toUpperCase(java.util.Locale.ROOT) + " /bff" + m.group(2));
        }
        return found;
    }

    @Test
    void theLegacyUserFacingSurfaceIsExactlyThePinnedSet_soARetirementCannotLandUnnoticed() {
        Set<String> declared = declaredMappings();

        // Sanity: the scanner must actually be finding mappings. A regex that silently matched
        // nothing would make every assertion below vacuously "no unexpected additions".
        assertThat(declared)
                .as("the @(Get|Post|...)Mapping scanner found nothing in %s — the guard would be "
                        + "vacuous", CONTROLLER)
                .isNotEmpty();

        Set<String> retired = new TreeSet<>(PINNED.keySet());
        retired.removeAll(declared);
        assertThat(retired)
                .as("""
                        A legacy user path was RETIRED from AuthController. hugmesh-admin-bff-api#2 \
                        carries the operator's "retire" answer, but the 2026-09-10 audit (this \
                        class's javadoc + AuthController's) measured that these paths are shadowed \
                        on the kind/cluster lane ONLY: the COMPOSE route table routes them to the \
                        /bff/** admin-bff catch-all, and the DEVICE lane reaches admin-bff with no \
                        gateway in front of it at all. Per-path blockers: %s. If a blocker is now \
                        genuinely gone, say so on #2 with the evidence, then update PINNED and the \
                        AuthController audit in the same commit.""",
                        retired.stream().map(p -> p + " -> " + PINNED.get(p)).toList())
                .isEmpty();

        Set<String> added = new TreeSet<>(declared);
        added.removeAll(PINNED.keySet());
        assertThat(added)
                .as("""
                        A NEW mapping appeared on AuthController: %s. This class is the legacy \
                        user-facing surface that issue #2 is trying to shrink, so anything added \
                        here needs the same three-lane check (cluster route table, compose route \
                        table, device/no-gateway) before it ships. Record the answer in \
                        AuthController's javadoc and add it to PINNED.""", added)
                .isEmpty();
    }

    @Test
    void everyPinnedPathCarriesANonEmptyReason_soTheGuardCannotDecayIntoABareList() {
        assertThat(PINNED)
                .allSatisfy((path, reason) -> assertThat(reason)
                        .as("pinned path %s has no stated reason to still exist", path)
                        .isNotBlank());
    }
}
