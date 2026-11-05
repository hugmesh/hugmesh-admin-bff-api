package net.hugmesh.adminbff.mfa;

import java.time.Duration;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;

/**
 * The MERGED MFA requirement across every role a principal holds in a domain — what
 * {@link RoleMfaPolicyEnforcementFilter} asks {@link RoleMfaPolicyService#requirementFor} for.
 *
 * <p>Only the policies that resolve {@code required=true} (post-floor) participate; a role whose
 * policy does not require MFA contributes nothing, so a plain {@code user} role can never relax
 * the {@code admin} policy riding alongside it. The merge is the STRICTEST of the participants:
 * <ul>
 *   <li><b>grace</b> — {@link #graceSeconds} is the smallest POSITIVE {@code graceSeconds} among
 *       the participants, or {@code 0} when none sets one. A participant whose row (or default)
 *       says {@code 0} is recorded in {@link #platformWindowApplies}: {@code 0} means "no per-role
 *       grace of its own; the platform freshness window ({@code app.casdoor.mfa.freshness},
 *       default 10m) is the re-prompt cadence". {@link #window(Duration)} takes the minimum of
 *       whichever of the two apply, so a positive grace can only ever be SHORTENED by a
 *       sibling role, never lengthened;</li>
 *   <li><b>methods</b> — the INTERSECTION of every participant's non-empty {@code methods} list
 *       (an empty list on a policy means "any" and constrains nothing). {@link #methodsConstrained}
 *       says whether at least one participant restricted the methods; a constrained requirement
 *       whose intersection is EMPTY is unsatisfiable and {@link #allowsMethod} denies every
 *       factor (fail closed: two roles that contradict each other are an operator error, not a
 *       licence to skip the check).</li>
 * </ul>
 *
 * @param required              whether MFA is required for any of the roles
 * @param graceSeconds          the strictest positive per-role grace, or {@code 0} if none
 * @param platformWindowApplies whether some participant left the grace at {@code 0}
 * @param methodsConstrained    whether some participant restricted the allowed methods
 * @param methods               the allowed methods when constrained (may be empty = unsatisfiable);
 *                              ignored when unconstrained
 */
public record MfaRequirement(
        boolean required,
        long graceSeconds,
        boolean platformWindowApplies,
        boolean methodsConstrained,
        Set<String> methods) {

    /** Nothing required: the answer for a principal none of whose roles needs MFA. */
    public static final MfaRequirement NONE = new MfaRequirement(false, 0L, false, false, Set.of());

    /**
     * The fail-closed answer for an UNKNOWN requirement (a lookup that yields nothing): MFA is
     * required, on the platform window, with any method — the strictest answer that is still
     * satisfiable by a legitimate challenge.
     */
    public static final MfaRequirement UNKNOWN = new MfaRequirement(true, 0L, true, false, Set.of());

    public MfaRequirement {
        Set<String> normalised = new LinkedHashSet<>();
        if (methods != null) {
            for (String m : methods) {
                if (m != null && !m.isBlank()) {
                    normalised.add(m.trim().toLowerCase(Locale.ROOT));
                }
            }
        }
        methods = Set.copyOf(normalised);
        if (graceSeconds < 0) {
            graceSeconds = 0L;
        }
    }

    /**
     * The freshness window an MFA stamp must fall within, given the platform window: the
     * smaller of the strictest positive per-role grace and (when some participant is on it)
     * the platform window. A requirement that names neither (only possible for {@link #NONE})
     * yields the platform window.
     */
    public Duration window(Duration platformFreshness) {
        Duration platform = platformFreshness == null || platformFreshness.isZero() || platformFreshness.isNegative()
                ? Duration.ofMinutes(10) : platformFreshness;
        if (graceSeconds <= 0) {
            return platform;
        }
        Duration grace = Duration.ofSeconds(graceSeconds);
        return platformWindowApplies && platform.compareTo(grace) < 0 ? platform : grace;
    }

    /**
     * Whether a stamp made with {@code amr} satisfies the method restriction. Unconstrained
     * accepts anything, including a stamp that recorded no method. Constrained requires a
     * non-blank method that is in the intersection (case-insensitive); a stamp that recorded
     * no method cannot prove it used an allowed factor, so it is refused.
     */
    public boolean allowsMethod(String amr) {
        if (!methodsConstrained) {
            return true;
        }
        if (amr == null || amr.isBlank()) {
            return false;
        }
        return methods.contains(amr.trim().toLowerCase(Locale.ROOT));
    }

    /** Merge the participating (required) policies into one requirement. */
    static MfaRequirement merge(Collection<RoleMfaPolicy> policies) {
        boolean required = false;
        long grace = 0L;
        boolean platform = false;
        boolean constrained = false;
        Set<String> allowed = null;
        for (RoleMfaPolicy policy : policies) {
            if (policy == null || !policy.required()) {
                continue;
            }
            required = true;
            long g = policy.graceSeconds();
            if (g > 0) {
                grace = grace == 0 ? g : Math.min(grace, g);
            } else {
                platform = true;
            }
            if (!policy.methods().isEmpty()) {
                constrained = true;
                Set<String> these = new LinkedHashSet<>();
                for (String m : policy.methods()) {
                    these.add(m.trim().toLowerCase(Locale.ROOT));
                }
                if (allowed == null) {
                    allowed = these;
                } else {
                    allowed.retainAll(these);
                }
            }
        }
        if (!required) {
            return NONE;
        }
        return new MfaRequirement(true, grace, platform, constrained, allowed == null ? Set.of() : allowed);
    }
}
