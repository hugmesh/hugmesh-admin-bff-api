package net.hugmesh.adminbff.domainregistry;

import java.util.Collection;
import java.util.HashSet;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Allocates the per-domain SELinux MCS category PAIR a {@code domain_registry} row carries
 * ({@code selinux_level} for the domain's Casdoor pod, {@code selinux_level_pg} for its
 * Postgres pod) — operator DECISION 29c, 2026-09-17: <em>"the domain_registry writer
 * allocates selinuxLevel / selinuxLevelPg at insert, under a uniqueness constraint, because
 * docs/SECURITY.md §3 requires cluster-unique MCS categories"</em>.
 *
 * <h3>Why this is not a formatting helper</h3>
 * Of the four layers that see a malformed per-domain element, three fail CLOSED and this one
 * fails OPEN: a duplicate MCS category means two workloads share a category, they stop being
 * mutually isolated by SELinux, and <b>nothing in the cluster reports it</b>. So the
 * allocation is a correctness surface with two independent guards:
 *
 * <ol>
 *   <li><b>Structural</b> — a slot {@code n} maps to the pair
 *       {@code (FLOOR + 2n, FLOOR + 2n + 1)}. {@code FLOOR} is EVEN, so {@code selinux_level}
 *       only ever holds EVEN categories and {@code selinux_level_pg} only ever ODD ones. The
 *       two columns therefore draw from disjoint halves of the range and a cross-column
 *       collision is impossible by construction — which matters because a per-column UNIQUE
 *       constraint cannot express "A.selinux_level &ne; B.selinux_level_pg".</li>
 *   <li><b>The database</b> — {@code uq_domain_registry_selinux_level} /
 *       {@code uq_domain_registry_selinux_level_pg} (changelog 012). This allocator READS the
 *       taken set and the caller then INSERTs; between those two steps a concurrent insert can
 *       take the slot, and the UNIQUE constraint — not the read — is what makes that insert
 *       lose. The caller retries on that violation. Never remove the constraint on the grounds
 *       that the allocator "already checks".</li>
 * </ol>
 *
 * <h3>The reserved range</h3>
 * {@code s0:c0} &hellip; {@code s0:c255} belong to the STATIC per-application identity matrix in
 * hugmesh-generator {@code docs/SECURITY.md} §3 (the highest statically assigned category there
 * on 2026-09-17 is {@code s0:c88}, so the floor leaves 167 free categories of headroom for new
 * fixed workloads). Dynamic per-domain allocation starts at {@link #FLOOR_CATEGORY} and runs to
 * {@link #CEILING_CATEGORY}, which is set by the node's containerd
 * ({@code specs/etc/containerd/config.toml}: {@code selinux_category_range = 1024}, i.e. valid
 * categories are {@code c0}&ndash;{@code c1023}). Two categories per domain gives
 * {@link #MAX_SLOT} + 1 = 384 own-IdP domains; asking for the 385th is refused LOUDLY by
 * {@link Exhausted} rather than wrapping around onto a live category.
 *
 * <p>Allocation picks the LOWEST FREE slot, so a registry that never deletes rows (domains are
 * soft-disabled, never hard-deleted) hands out 0, 1, 2, &hellip; in order and the assignment is
 * reproducible from the row set alone.
 *
 * <p>Pure and side-effect free: no Spring, no I/O, no clock. Everything here is unit-testable
 * without a database.
 */
public final class McsCategoryAllocator {

    /** First category available for per-domain allocation (everything below is the static matrix). */
    public static final int FLOOR_CATEGORY = 256;

    /** Highest category the node's containerd will accept ({@code selinux_category_range = 1024}). */
    public static final int CEILING_CATEGORY = 1023;

    /** Highest allocatable slot: the pair {@code (FLOOR+2n, FLOOR+2n+1)} must fit under the ceiling. */
    public static final int MAX_SLOT = (CEILING_CATEGORY - FLOOR_CATEGORY - 1) / 2;

    /** The {@code s0:cNN} spelling docs/SECURITY.md §3 and every {@code seLinuxOptions.level} uses. */
    private static final Pattern LEVEL = Pattern.compile("^s0:c(\\d{1,4})$");

    private McsCategoryAllocator() {
    }

    /** The allocated pair for one domain. */
    public record McsPair(String level, String levelPg) {
    }

    /** Refusal when every slot in the reserved range is taken. Never wraps onto a live category. */
    public static final class Exhausted extends RuntimeException {
        private static final long serialVersionUID = 1L;

        Exhausted(String message) {
            super(message);
        }
    }

    /**
     * The category pair for a 0-based slot. {@code level} takes the EVEN offset, {@code levelPg}
     * the ODD one above it — the structural half of the no-shared-category guarantee.
     *
     * @throws IllegalArgumentException for a slot outside {@code 0..}{@link #MAX_SLOT}
     */
    public static McsPair forSlot(int slot) {
        if (slot < 0 || slot > MAX_SLOT) {
            throw new IllegalArgumentException(
                    "MCS slot " + slot + " is outside the reserved range (0.." + MAX_SLOT + ")");
        }
        int base = FLOOR_CATEGORY + (2 * slot);
        return new McsPair("s0:c" + base, "s0:c" + (base + 1));
    }

    /**
     * The slot a {@code selinux_level} value came from, or empty when the value is null, blank,
     * not an {@code s0:cNN} level, below the floor, above the ceiling, or ODD (an odd category in
     * the {@code selinux_level} column is a Postgres-half value in the wrong column — not a slot).
     *
     * <p>Unparseable values are IGNORED rather than rejected on purpose: a pre-decision or
     * hand-edited row must not be able to wedge every future allocation. It costs nothing,
     * because the slot it would have occupied is then simply allocatable — and the UNIQUE
     * constraint still refuses an actual duplicate.
     */
    public static OptionalInt slotOf(String level) {
        if (level == null) {
            return OptionalInt.empty();
        }
        Matcher m = LEVEL.matcher(level.trim());
        if (!m.matches()) {
            return OptionalInt.empty();
        }
        int category;
        try {
            category = Integer.parseInt(m.group(1));
        } catch (NumberFormatException e) {
            return OptionalInt.empty();
        }
        if (category < FLOOR_CATEGORY || category > CEILING_CATEGORY) {
            return OptionalInt.empty();
        }
        int offset = category - FLOOR_CATEGORY;
        if (offset % 2 != 0) {
            return OptionalInt.empty();
        }
        return OptionalInt.of(offset / 2);
    }

    /**
     * The lowest free pair given the {@code selinux_level} values already on the table.
     *
     * @param takenLevels every non-null {@code selinux_level} currently stored (nulls and
     *                    unparseable entries are ignored — see {@link #slotOf(String)})
     * @throws Exhausted when slots {@code 0..}{@link #MAX_SLOT} are all taken
     */
    public static McsPair allocate(Collection<String> takenLevels) {
        Set<Integer> taken = new HashSet<>();
        for (String level : takenLevels) {
            slotOf(level).ifPresent(taken::add);
        }
        for (int slot = 0; slot <= MAX_SLOT; slot++) {
            if (!taken.contains(slot)) {
                return forSlot(slot);
            }
        }
        throw new Exhausted(
                "per-domain MCS category range exhausted: all " + (MAX_SLOT + 1)
                        + " slots (s0:c" + FLOOR_CATEGORY + "..s0:c" + CEILING_CATEGORY
                        + ") are allocated. Refusing to reuse a live category — "
                        + "docs/SECURITY.md §3 requires cluster-unique MCS categories.");
    }

    /**
     * Whether a category value is a well-formed {@code s0:cNN} INSIDE the reserved per-domain
     * range — the guard on an EXPLICIT pair supplied by a caller (a future reconcile/import
     * path restating an existing domain's categories) rather than allocated here.
     *
     * <p>Unlike {@link #slotOf(String)} this does NOT require the EVEN half: it is a
     * range check, deliberately, so a forced-duplicate test can still hand the database two
     * in-range values and prove a UNIQUE constraint bites. What it refuses is a category from
     * the STATIC per-application matrix — hugmesh-generator {@code docs/DOMAIN-IDP.md:56}
     * forbids the base's {@code s0:c85} / {@code s0:c86} placeholders ever going live on a
     * domain, and a static-matrix category silently co-locates a tenant's pod with a platform
     * workload. That failure is invisible in the cluster, which is why it is refused at the
     * writer rather than trusted to a reviewer.
     */
    public static boolean isInReservedRange(String level) {
        if (level == null) {
            return false;
        }
        Matcher m = LEVEL.matcher(level.trim());
        if (!m.matches()) {
            return false;
        }
        int category;
        try {
            category = Integer.parseInt(m.group(1));
        } catch (NumberFormatException e) {
            return false;
        }
        return category >= FLOOR_CATEGORY && category <= CEILING_CATEGORY;
    }

    /**
     * Whether a database error is the MCS-uniqueness violation this allocator races against
     * (as opposed to the {@code cluster_domain} / {@code ns_prefix} duplicate, which is a real
     * 409 for the caller and must NOT be retried). Matched on the constraint NAME anywhere in
     * the throwable chain, which both PostgreSQL and the H2 PG-compat store put in the message.
     */
    public static boolean isCategoryCollision(Throwable error) {
        for (Throwable t = error; t != null; t = t.getCause()) {
            String message = t.getMessage();
            if (message == null) {
                continue;
            }
            String lower = message.toLowerCase(java.util.Locale.ROOT);
            if (lower.contains("uq_domain_registry_selinux_level")) {
                return true;
            }
            if (t.getCause() == t) {
                break;
            }
        }
        return false;
    }

    /** The category pair carried by a row, when it has one (both halves present). */
    public static Optional<McsPair> pairOf(String level, String levelPg) {
        if (level == null || level.isBlank() || levelPg == null || levelPg.isBlank()) {
            return Optional.empty();
        }
        return Optional.of(new McsPair(level, levelPg));
    }
}
