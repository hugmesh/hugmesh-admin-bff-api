package net.hugmesh.adminbff;

/**
 * How long a {@code subject:<user>} gateway revocation key lives, by what the key is FOR.
 *
 * <h2>What a subject key does at the gateway</h2>
 * {@code GatewayRevocationClient#revokeSubject} writes {@code subject:<casdoor username>} with a
 * Cassandra TTL. The gateway's {@code RevocationGatewayFilter} denies a request when the JWT's
 * subject (or username) is in the key set. It is plain set membership: there is no comparison
 * with the token's {@code iat}. So for as long as the key lives, EVERY token for that subject is
 * refused, including one minted after the key was written. The TTL is therefore two things at
 * once: the window in which a stale token is cut off, and the window in which the person is
 * locked out of everything behind the gateway.
 *
 * <h2>Cut-off keys: {@value #CUTOFF_PROPERTY}</h2>
 * Account-disable, role revoke and desktop-sudo revoke write a key once, to stop a token that
 * still carries the old state. The key must outlive the longest token Casdoor issues, or the
 * revoked token works again when the key lapses. The seeded Casdoor apps issue 168 h tokens
 * (hugmesh-generator {@code specs/cluster/manifests/casdoor/init-job.yaml}: every {@code app-*}
 * client and {@code hugmesh-desktop} set {@code expireInHours: 168}; only {@code app-user-bff}
 * is 4 h). These sites used to pass a 1 h literal described as "the custody JWT lifetime", so a
 * revoked token was refused for one hour and then accepted for up to ~7 more days. The default
 * is 168 h, and hugmesh-generator {@code tests/scripts/test-subject-revocation-ttl.sh} fails if
 * the cluster value drops below the largest seeded {@code expireInHours}.
 *
 * <p>The cost, stated plainly: with today's set-membership filter, a 168 h cut-off key also
 * locks the person out for 168 h, fresh login or not. That is the intent for a disabled
 * account. For a role revoke it is broader than the role. Narrowing it needs the gateway to
 * deny only tokens issued before the key ({@code iat < revoked_at}); until then the remaining
 * levers are this TTL and the seeded {@code expireInHours}, both operator decisions.
 *
 * <h2>Grant keys: {@value #GRANT_PROPERTY}</h2>
 * Role grant and desktop-sudo grant write a key so the grantee's next token carries the new
 * role. A stale token here is UNDER-privileged; nothing is cut off, and the key's lifetime is
 * pure lock-out. They keep the short 1 h default and must not share the cut-off value.
 *
 * <h2>Not covered here</h2>
 * The access-suspension reconcile re-writes its subject key on every tick while the suspension
 * is active (see {@code AbstractAccessSyncAction}), so it does not depend on the key outliving a
 * token; it keeps its own short, named TTL so lifting a suspension restores access promptly.
 *
 * <p>All of this is inert while {@code broker.gateway-revocation.enabled} is false (the shipped
 * default) and while the client has no credential the gateway accepts (hugmesh-admin-bff-api#45,
 * hugmesh-generator#347 decision 45).
 */
public final class SubjectRevocationTtl {

    public static final String CUTOFF_PROPERTY = "broker.gateway-revocation.subject-cutoff-ttl-seconds";
    public static final String GRANT_PROPERTY = "broker.gateway-revocation.subject-grant-ttl-seconds";

    /** 168 h: the longest {@code expireInHours} any seeded Casdoor app issues. */
    public static final long DEFAULT_CUTOFF_SECONDS = 604_800L;
    /** 1 h: a grant key only nudges a re-mint; anything longer is lock-out. */
    public static final long DEFAULT_GRANT_SECONDS = 3_600L;

    /** {@code @Value} expressions. The shipped {@code application.yml} binds both keys to their
     *  env names; these fallbacks only apply when the file does not. */
    public static final String CUTOFF_VALUE = "${" + CUTOFF_PROPERTY + ":" + DEFAULT_CUTOFF_SECONDS + "}";
    public static final String GRANT_VALUE = "${" + GRANT_PROPERTY + ":" + DEFAULT_GRANT_SECONDS + "}";

    private SubjectRevocationTtl() {
    }

    /**
     * Refuse a non-positive TTL at startup. The client treats {@code <= 0} as "the table default"
     * (30 days), which would turn a grant key into a month-long lock-out and hide a typo in the
     * cut-off value. Fails the bean, and with it the boot, rather than writing such a key.
     */
    public static long require(String property, long seconds) {
        if (seconds <= 0) {
            throw new IllegalStateException(property + " must be a positive number of seconds, got "
                    + seconds + " (a non-positive TTL means the gateway table's 30-day default)");
        }
        return seconds;
    }
}
