package systems.hugmesh.adminbff.locallogin;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Per-IP AND per-(IP,username) throttle guarding {@code POST /bff/login/local} in front of the
 * {@link LocalSecretVerifier#verify} Casdoor password-grant call (PR #198 security review, MEDIUM
 * finding): unauthenticated and — before that — un-rate-limited, that endpoint runs one REAL
 * {@code grant_type=password} call against Casdoor per request for an attacker-chosen username,
 * with nothing anywhere in the path to slow a brute-force / enumeration sweep down (the existing
 * resilience4j circuit breakers in this codebase — {@code akkoma}/{@code tuwunel}/{@code casdoor}/
 * {@code edge-ai} — guard the access-suspension RECONCILE loops against a stalled downstream; none
 * of them sit in front of an inbound, caller-triggered request).
 *
 * <h3>Why (IP, username), not username alone — PR #199 security review, HIGH finding</h3>
 * The first cut of this class (this same PR, prior commit) had a per-username bucket keyed on the
 * raw, unauthenticated username string ALONE, global across every source IP. Role usernames are
 * structurally predictable ({@code <roleId>@<tenant-domain>}, e.g. {@code brandowner@acme.local}),
 * so an attacker who knows (or guesses) a role username could exhaust that ONE global budget — 5
 * attempts/60s shared by literally every caller everywhere — with 5 garbage-secret requests from a
 * single IP, then simply rotate to a new source IP for the next 5, and so on: the username budget
 * never replenished per-source because there was only ONE budget for the whole world, so this
 * indefinitely denied that role's legitimate login from ANY IP, including the real owner's.
 * {@code LocalLoginRateLimiterTest} originally proved this shape directly
 * ({@code overUsernameLimit_deniesFurtherAttempts_evenFromDifferentIps}). Scoping the tight bucket
 * to the {@code (ip, username)} PAIR instead of username alone fixes this: each source IP now gets
 * its OWN small budget against a given username, so spraying from N different IPs costs an
 * attacker on the order of N * per-ip-username-limit real Casdoor calls before anything starts
 * denying — the same order of magnitude as just attacking the per-IP bucket directly — instead of
 * a FIXED 5 total attempts no matter how many IPs are used. A genuine single attacker hammering
 * one account from one place is throttled exactly as tightly as before (same default limit/window,
 * just a narrower key), and the per-IP bucket (unchanged) still independently catches one source
 * enumerating many different usernames.
 *
 * <p><b>Two independent dimensions, BOTH must allow.</b> A request that fails EITHER bucket is
 * throttled — this stops both attack shapes a single dimension misses: an enumeration sweep of
 * many usernames from one IP (caught by the per-IP bucket) and a sustained attack against one
 * (ip,username) pair (caught by the per-(ip,username) bucket) — while, per the finding above,
 * NEITHER bucket lets a spray of one victim username across many attacker-controlled IPs add up to
 * a single shared, exhaustible budget the way the old per-username-alone bucket did. Each call
 * always consumes one slot from BOTH buckets (regardless of whether the other already denied) so
 * each bucket's count reflects every attempt against that key, not just the ones that reached
 * Casdoor.
 *
 * <h3>Numbers</h3>
 * Defaults: <b>10 attempts / 60s per IP</b>, <b>5 attempts / 60s per (IP,username) pair</b>. The
 * loopback-agent handoff this endpoint serves is a human retrying at most a couple of mistyped
 * secrets, not a scripted loop, so both windows are deliberately tight — an attacker gets at most
 * one real Casdoor call roughly every 6-12 seconds per key, which is slow enough to make an
 * exhaustive credential sweep impractical while never tripping on a genuine multi-typo retry.
 * Per-(ip,username) is tighter than per-IP because a single attacker-chosen username from a single
 * source is the actual oracle target; the IP bucket is the backstop against the same source
 * spraying many usernames. Both are configurable via {@code app.local-login.rate-limit.per-ip.*} /
 * {@code app.local-login.rate-limit.per-ip-username.*} (see {@code application.yml}) — an operator
 * who observes false positives (e.g. many legitimate users behind one NAT'd egress IP) can widen
 * {@code per-ip} without touching the tighter {@code per-ip-username} bound.
 *
 * <h3>Implementation — fixed window, not resilience4j's {@code RateLimiterRegistry}</h3>
 * A FIXED window per key (reset once {@code windowMillis} has elapsed since the key's first hit
 * in the current window), not a true sliding log — simpler, O(1) memory per key, and adequate for
 * a throttle whose job is "stop the flood" rather than "meter precisely" (the worst case, a burst
 * straddling a window boundary, still caps an attacker at roughly 2x the configured rate over any
 * rolling window). This is deliberately a small hand-rolled counter rather than resilience4j's
 * {@link io.github.resilience4j.ratelimiter.RateLimiterRegistry} (already a dependency here, used
 * for the circuit breakers above): that registry is designed for a small, FIXED set of NAMED
 * instances (exactly how the breakers above use it); keyed dynamically per-IP / per-(ip,username),
 * its internal instance map would grow WITHOUT BOUND for the process lifetime — an attacker
 * spraying distinct keys would leak memory forever. This class caps itself instead (see below).
 *
 * <p><b>Size-bounded (memory safety, not a security control).</b> Each dimension is capped at
 * {@value #MAX_TRACKED_KEYS_PER_DIMENSION} tracked keys. Once a dimension is at capacity, a
 * never-seen key is allowed through UNTRACKED rather than grow the map further — so filling the
 * cap can only ever make the limiter more permissive for brand-new keys, never falsely deny an
 * existing one. Concretely: the per-(ip,username) bucket could in theory be exhausted by an
 * attacker spraying {@value #MAX_TRACKED_KEYS_PER_DIMENSION} distinct (ip,username) pairs (trivial
 * to reach by varying either half), but the per-IP bucket is keyed on the attacker's own (much
 * smaller) address space and keeps throttling regardless, so the combined guard still holds. Each
 * entry is a handful of bytes (a {@code String} key + one small counter object), so at the cap
 * this is a few MB, not a DoS vector in itself.
 *
 * <p><b>Per-pod / single-instance</b>, exactly like the existing circuit breakers: in-memory only,
 * so a multi-replica deployment gets a per-pod budget rather than a cluster-wide one. Acceptable
 * here — the goal is bounding the per-connection oracle cost, not perfectly counting every
 * attempt cluster-wide.
 */
@Component
public class LocalLoginRateLimiter {

    /** Per-dimension cap on distinct tracked keys — see class javadoc ("Size-bounded"). */
    static final int MAX_TRACKED_KEYS_PER_DIMENSION = 20_000;

    private final int ipLimit;
    private final long ipWindowMillis;
    private final int ipUsernameLimit;
    private final long ipUsernameWindowMillis;

    private final ConcurrentHashMap<String, Window> byIp = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Window> byIpUsername = new ConcurrentHashMap<>();

    public LocalLoginRateLimiter(
            @Value("${app.local-login.rate-limit.per-ip.attempts:10}") int ipLimit,
            @Value("${app.local-login.rate-limit.per-ip.window-ms:60000}") long ipWindowMillis,
            @Value("${app.local-login.rate-limit.per-ip-username.attempts:5}") int ipUsernameLimit,
            @Value("${app.local-login.rate-limit.per-ip-username.window-ms:60000}") long ipUsernameWindowMillis) {
        this.ipLimit = ipLimit;
        this.ipWindowMillis = ipWindowMillis;
        this.ipUsernameLimit = ipUsernameLimit;
        this.ipUsernameWindowMillis = ipUsernameWindowMillis;
    }

    /**
     * {@code true} — both the per-IP and per-(IP,username) buckets had a free slot; the caller may
     * proceed to Casdoor. {@code false} — at least one bucket is exhausted; the caller MUST 429
     * without ever calling Casdoor. {@code ip}/{@code username} are normalised (trimmed,
     * lower-cased) before keying so case/whitespace variation cannot split one caller's budget
     * across multiple buckets.
     */
    public boolean tryAcquire(String ip, String username) {
        boolean ipOk = allow(byIp, normalize(ip), ipLimit, ipWindowMillis);
        boolean pairOk = allow(byIpUsername, pairKey(ip, username), ipUsernameLimit, ipUsernameWindowMillis);
        return ipOk && pairOk;
    }

    private static boolean allow(ConcurrentHashMap<String, Window> buckets, String key, int limit,
                                 long windowMillis) {
        long now = System.currentTimeMillis();
        Window w = buckets.get(key);
        if (w == null) {
            if (buckets.size() >= MAX_TRACKED_KEYS_PER_DIMENSION) {
                // At capacity: allow this never-seen key through untracked (see class javadoc).
                return true;
            }
            w = buckets.computeIfAbsent(key, k -> new Window(now));
        }
        synchronized (w) {
            if (now - w.windowStartMillis >= windowMillis) {
                w.windowStartMillis = now;
                w.count.set(0);
            }
            return w.count.incrementAndGet() <= limit;
        }
    }

    private static String normalize(String s) {
        return s == null ? "" : s.trim().toLowerCase();
    }

    /** Composite key for the per-(ip,username) bucket — see the class javadoc's "Why (IP,
     *  username)" section for the DoS this dimension closes. NUL-delimited: a normalised IP or
     *  username never legitimately contains a NUL byte, so unlike a printable delimiter (":",
     *  "@", "|"...) this cannot be ambiguous given IPv6 addresses and email-shaped usernames both
     *  already use those characters. */
    private static String pairKey(String ip, String username) {
        return normalize(ip) + '\u0000' + normalize(username);
    }

    /** One key's fixed-window counter: a mutable start-of-window stamp + attempt count, guarded
     *  by synchronizing on the instance itself in {@link #allow}. */
    private static final class Window {
        private long windowStartMillis;
        private final AtomicInteger count = new AtomicInteger(0);

        private Window(long now) {
            this.windowStartMillis = now;
        }
    }
}
