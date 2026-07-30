package systems.hugmesh.adminbff.locallogin;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Plain unit tests for {@link LocalLoginRateLimiter} — no Spring context needed, the class has a
 * simple {@code (int,long,int,long)} constructor. Covers the contract {@code AuthController}
 * relies on: under-limit passes, over-limit denies, and the two dimensions (per-IP,
 * per-(IP,username)) are scoped independently of each other so one caller/identity never burns
 * another's budget.
 *
 * <p><b>PR #199 security review, HIGH finding.</b> The FIRST cut of this test class had
 * {@code overUsernameLimit_deniesFurtherAttempts_evenFromDifferentIps}, which proved the
 * then-current per-username-ALONE bucket was global across every source IP — i.e. it proved the
 * exact DoS shape a real attacker could use: exhaust one victim role username's entire login
 * budget by spraying garbage secrets from many different IPs, since all of them shared ONE
 * budget. That test has been REPLACED below by
 * {@link #sameUsername_fromManyDifferentIps_isNotGloballyThrottled}, which proves the opposite,
 * NOW-CORRECT property for the {@code (ip, username)}-keyed bucket: the same username attempted
 * from many different IPs is NOT globally throttled, because each IP now owns its own budget
 * against that username. {@link #overIpUsernamePairLimit_deniesFurtherAttempts} proves the
 * throttle still works as intended for the actual attack that matters — one source hammering one
 * account.
 */
class LocalLoginRateLimiterTest {

    private static final String IP_A = "10.0.0.1";
    private static final String IP_B = "10.0.0.2";
    private static final String USER_A = "alice@acme.local";
    private static final String USER_B = "bob@acme.local";

    @Test
    void underLimit_allowsEveryAttempt() {
        // 3 attempts/60s on both dimensions; exactly 3 calls for the SAME key must all pass.
        LocalLoginRateLimiter limiter = new LocalLoginRateLimiter(3, 60_000, 3, 60_000);

        assertThat(limiter.tryAcquire(IP_A, USER_A)).isTrue();
        assertThat(limiter.tryAcquire(IP_A, USER_A)).isTrue();
        assertThat(limiter.tryAcquire(IP_A, USER_A)).isTrue();
    }

    /**
     * THE fix, proven directly: a role username is structurally predictable
     * ({@code roleId@tenant-domain}), so an attacker sprays it from many different source IPs. With
     * the per-(ip,username) bucket, each of those IPs gets its OWN small budget against that
     * username — spraying from more IPs buys the attacker more attempts (at the per-IP-username
     * rate each time), it does NOT exhaust one shared global budget the way the old
     * per-username-alone bucket did. The per-IP dimension is set generous here so only the
     * per-(ip,username) dimension is under test.
     */
    @Test
    void sameUsername_fromManyDifferentIps_isNotGloballyThrottled() {
        // per-ip-username budget of 1; per-ip budget generous so it never trips first.
        LocalLoginRateLimiter limiter = new LocalLoginRateLimiter(1000, 60_000, 1, 60_000);

        // 50 distinct source IPs, each making its single allotted attempt against the SAME
        // victim username: every single one succeeds — the username alone never runs out.
        for (int i = 0; i < 50; i++) {
            String ip = "203.0.113." + i;
            assertThat(limiter.tryAcquire(ip, USER_A))
                    .as("attempt #%d against %s from a fresh IP must still be allowed", i, USER_A)
                    .isTrue();
        }
    }

    /**
     * The real attack the per-(ip,username) bucket exists to stop: one source hammering one
     * account. The pair budget is exhausted exactly like the old per-username-alone bucket used
     * to be for a SINGLE source — the difference (proven above) is only that a second source no
     * longer shares that same budget.
     */
    @Test
    void overIpUsernamePairLimit_deniesFurtherAttempts() {
        // per-ip-username budget of 2; per-ip budget generous so it never trips first.
        LocalLoginRateLimiter limiter = new LocalLoginRateLimiter(1000, 60_000, 2, 60_000);

        assertThat(limiter.tryAcquire(IP_A, USER_A)).isTrue();
        assertThat(limiter.tryAcquire(IP_A, USER_A)).isTrue();
        // Third attempt: SAME (ip,username) pair, over its budget — denied.
        assertThat(limiter.tryAcquire(IP_A, USER_A)).isFalse();
    }

    /**
     * A different source IP against the SAME victim username has its OWN pair budget, unaffected
     * by IP_A having just exhausted its pair budget against that username — this is the isolation
     * property {@link #sameUsername_fromManyDifferentIps_isNotGloballyThrottled} demonstrates at
     * scale; this test pins it down as a direct before/after.
     */
    @Test
    void differentIpSameUsername_hasOwnPairBudget() {
        LocalLoginRateLimiter limiter = new LocalLoginRateLimiter(1000, 60_000, 1, 60_000);

        assertThat(limiter.tryAcquire(IP_A, USER_A)).isTrue();
        assertThat(limiter.tryAcquire(IP_A, USER_A)).isFalse();   // IP_A's pair budget against USER_A is spent
        // IP_B has never attempted USER_A before — its own (ip,username) pair is fresh.
        assertThat(limiter.tryAcquire(IP_B, USER_A)).isTrue();
    }

    @Test
    void overIpLimit_deniesFurtherAttempts_evenWithDifferentUsernames() {
        // IP budget of 2; per-ip-username budget generous so it never trips first.
        LocalLoginRateLimiter limiter = new LocalLoginRateLimiter(2, 60_000, 1000, 60_000);

        assertThat(limiter.tryAcquire(IP_A, USER_A)).isTrue();
        assertThat(limiter.tryAcquire(IP_A, USER_B)).isTrue();   // same IP, different username — still counts
        // Third attempt from the SAME ip (a THIRD username) is denied by the IP bucket alone.
        assertThat(limiter.tryAcquire(IP_A, "carol@acme.local")).isFalse();
    }

    @Test
    void differentIps_haveIndependentBudgets() {
        LocalLoginRateLimiter limiter = new LocalLoginRateLimiter(1, 60_000, 1000, 60_000);

        // IP_A exhausts its own (limit=1) budget...
        assertThat(limiter.tryAcquire(IP_A, USER_A)).isTrue();
        assertThat(limiter.tryAcquire(IP_A, USER_B)).isFalse();
        // ...but IP_B, never having been attempted, still has its full budget.
        assertThat(limiter.tryAcquire(IP_B, USER_A)).isTrue();
    }

    @Test
    void pairKeyIsCaseAndWhitespaceNormalised_soVariantsShareOneBudget() {
        LocalLoginRateLimiter limiter = new LocalLoginRateLimiter(1000, 60_000, 1, 60_000);

        assertThat(limiter.tryAcquire(IP_A, "Alice@Acme.local")).isTrue();
        // Same (ip,username) identity, different username case/whitespace — must share the SAME
        // pair budget, not evade it.
        assertThat(limiter.tryAcquire(IP_A, "  alice@acme.local  ")).isFalse();
    }

    @Test
    void windowResets_afterItElapses() throws InterruptedException {
        // A tiny 50ms window so the test can wait it out without a fake clock.
        LocalLoginRateLimiter limiter = new LocalLoginRateLimiter(1000, 60_000, 1, 50);

        assertThat(limiter.tryAcquire(IP_A, USER_A)).isTrue();
        assertThat(limiter.tryAcquire(IP_A, USER_A)).isFalse();

        Thread.sleep(80);

        assertThat(limiter.tryAcquire(IP_A, USER_A)).isTrue();
    }
}
