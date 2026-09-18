package net.hugmesh.adminbff.domainregistry;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * {@link McsCategoryAllocator} — operator DECISION 29c (2026-09-17): <em>"the domain_registry
 * writer allocates selinuxLevel / selinuxLevelPg at insert, under a uniqueness constraint,
 * because docs/SECURITY.md §3 requires cluster-unique MCS categories"</em>.
 *
 * <p>Pure unit tests, no database. The DB half of the same guarantee (the UNIQUE constraints
 * that arbitrate a concurrent allocation) is proven in {@code DomainRegistryRepositoryTest}.
 *
 * <p>These tests go RED if the decision is reverted: dropping the reserved-range floor back
 * onto the static matrix, hashing the slug instead of allocating a free slot, dropping the
 * even/odd split that keeps the two columns disjoint, or wrapping around at exhaustion.
 */
class McsCategoryAllocatorTest {

    /**
     * The highest category statically assigned in hugmesh-generator {@code docs/SECURITY.md} §3
     * on 2026-09-17 ({@code edge-ai-analysis}, plus {@code s0:c88} in the brand-repo Casdoor
     * Postgres template). The reserved dynamic range must start clear of it with real headroom
     * — a floor that merely clears today's maximum gets overrun by the next fixed workload,
     * which is exactly how {@code s0:c49} was taken twice.
     */
    private static final int HIGHEST_STATIC_CATEGORY = 88;

    @Test
    @DisplayName("the reserved range starts clear of the static docs/SECURITY.md §3 matrix")
    void reservedRange_clearsTheStaticMatrixWithHeadroom() {
        assertThat(McsCategoryAllocator.FLOOR_CATEGORY)
                .as("""
                        Per-domain categories must not be drawn from the range the fixed \
                        workload matrix allocates by hand. Lowering this floor re-creates the \
                        s0:c49 double-allocation: a category that looks free to a manifest scan \
                        because the workload holding it has no Deployment yet.""")
                .isGreaterThan(HIGHEST_STATIC_CATEGORY + 64);

        assertThat(McsCategoryAllocator.CEILING_CATEGORY)
                .as("""
                        The node's containerd is configured selinux_category_range = 1024 \
                        (hugmesh-generator specs/etc/containerd/config.toml), so c1023 is the \
                        highest category a pod can carry. Raising this past it hands out a \
                        category the runtime will reject.""")
                .isEqualTo(1023);
    }

    @Test
    @DisplayName("slot 0 is the floor pair, and every pair is (even, odd+1)")
    void forSlot_pairsAnEvenCategoryWithTheOddOneAboveIt() {
        assertThat(McsCategoryAllocator.forSlot(0))
                .isEqualTo(new McsCategoryAllocator.McsPair("s0:c256", "s0:c257"));
        assertThat(McsCategoryAllocator.forSlot(1))
                .isEqualTo(new McsCategoryAllocator.McsPair("s0:c258", "s0:c259"));
        assertThat(McsCategoryAllocator.forSlot(McsCategoryAllocator.MAX_SLOT))
                .isEqualTo(new McsCategoryAllocator.McsPair("s0:c1022", "s0:c1023"));
    }

    @Test
    @DisplayName("no pair ever leaves the reserved range, and the two columns stay DISJOINT")
    void everySlot_staysInRangeAndKeepsTheColumnsDisjoint() {
        Set<String> levels = new HashSet<>();
        Set<String> levelsPg = new HashSet<>();
        for (int slot = 0; slot <= McsCategoryAllocator.MAX_SLOT; slot++) {
            McsCategoryAllocator.McsPair pair = McsCategoryAllocator.forSlot(slot);
            int level = category(pair.level());
            int levelPg = category(pair.levelPg());
            assertThat(level).isBetween(McsCategoryAllocator.FLOOR_CATEGORY,
                    McsCategoryAllocator.CEILING_CATEGORY);
            assertThat(levelPg).isBetween(McsCategoryAllocator.FLOOR_CATEGORY,
                    McsCategoryAllocator.CEILING_CATEGORY);
            levels.add(pair.level());
            levelsPg.add(pair.levelPg());
        }
        assertThat(levels).hasSize(McsCategoryAllocator.MAX_SLOT + 1);
        assertThat(levelsPg).hasSize(McsCategoryAllocator.MAX_SLOT + 1);
        // THE cross-column assertion. A per-column UNIQUE constraint cannot express
        // "domain A's casdoor category != domain B's postgres category"; the even/odd split
        // is what makes that impossible, so it is asserted over the WHOLE range, not a sample.
        assertThat(levels)
                .as("""
                        docs/SECURITY.md §3 forbids ANY two workloads sharing a category, and \
                        every domain is two workloads. selinux_level draws only EVEN offsets \
                        and selinux_level_pg only ODD ones, so the two sets cannot intersect. \
                        If this fails, two domains can be issued a shared category and nothing \
                        in the cluster will report it.""")
                .doesNotContainAnyElementsOf(levelsPg);
    }

    @Test
    @DisplayName("a slot outside the reserved range is refused, never wrapped")
    void forSlot_outsideTheRange_isRefused() {
        assertThatThrownBy(() -> McsCategoryAllocator.forSlot(-1))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> McsCategoryAllocator.forSlot(McsCategoryAllocator.MAX_SLOT + 1))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("allocate() hands out the LOWEST free slot and reuses a freed one")
    void allocate_picksTheLowestFreeSlot() {
        assertThat(McsCategoryAllocator.allocate(List.of()))
                .isEqualTo(McsCategoryAllocator.forSlot(0));
        assertThat(McsCategoryAllocator.allocate(List.of("s0:c256")))
                .isEqualTo(McsCategoryAllocator.forSlot(1));
        // slot 1 freed (its row was never created / was removed) -> reused before slot 3.
        assertThat(McsCategoryAllocator.allocate(List.of("s0:c256", "s0:c260")))
                .isEqualTo(McsCategoryAllocator.forSlot(1));
    }

    @Test
    @DisplayName("values that are not slots are ignored, so one bad row cannot wedge allocation")
    void allocate_ignoresUnparseableAndOutOfRangeValues() {
        List<String> junk = new ArrayList<>();
        junk.add(null);
        junk.add("");
        junk.add("   ");
        junk.add("s0:c11");        // a STATIC matrix category, below the floor
        junk.add("s0:c2000");      // above the ceiling
        junk.add("s0:c257");       // an ODD category: a Postgres-half value in the wrong column
        junk.add("c256");          // missing the sensitivity prefix
        junk.add("s0:c256:c257");  // a range, not a single category
        junk.add("not-a-level");
        assertThat(McsCategoryAllocator.allocate(junk))
                .as("""
                        None of these identify an allocated SLOT, so none may consume one. A \
                        hand-edited or pre-decision row must not be able to wedge every future \
                        allocation — and it costs nothing, because the DB UNIQUE constraint \
                        still refuses an actual duplicate.""")
                .isEqualTo(McsCategoryAllocator.forSlot(0));
    }

    @Test
    @DisplayName("slotOf round-trips forSlot, and refuses everything else")
    void slotOf_roundTripsAndRefuses() {
        for (int slot : new int[] {0, 1, 7, 100, McsCategoryAllocator.MAX_SLOT}) {
            assertThat(McsCategoryAllocator.slotOf(McsCategoryAllocator.forSlot(slot).level()))
                    .hasValue(slot);
            assertThat(McsCategoryAllocator.slotOf(McsCategoryAllocator.forSlot(slot).levelPg()))
                    .as("the Postgres half is an ODD category — not a slot in the level column")
                    .isEmpty();
        }
        assertThat(McsCategoryAllocator.slotOf(null)).isEmpty();
        assertThat(McsCategoryAllocator.slotOf("s0:c255")).as("below the floor").isEmpty();
        assertThat(McsCategoryAllocator.slotOf("s0:c1024")).as("above the ceiling").isEmpty();
    }

    @Test
    @DisplayName("an exhausted range is REFUSED, never wrapped onto a live category")
    void allocate_exhaustedRange_refuses() {
        List<String> everySlot = new ArrayList<>();
        for (int slot = 0; slot <= McsCategoryAllocator.MAX_SLOT; slot++) {
            everySlot.add(McsCategoryAllocator.forSlot(slot).level());
        }
        assertThatThrownBy(() -> McsCategoryAllocator.allocate(everySlot))
                .as("""
                        Wrapping around would hand a NEW domain a category a LIVE domain \
                        already holds — the one failure in this design that fails OPEN (the \
                        two pods stop being SELinux-isolated and nothing reports it). The \
                        registry must refuse the 385th own-IdP domain instead.""")
                .isInstanceOf(McsCategoryAllocator.Exhausted.class)
                .hasMessageContaining("exhausted");

        // ...and the range really is 384 domains, so the refusal is not a small-range artefact.
        assertThat(McsCategoryAllocator.MAX_SLOT + 1).isEqualTo(384);
    }

    @Test
    @DisplayName("isCategoryCollision fires ONLY on the MCS constraints, not on other duplicates")
    void isCategoryCollision_discriminates() {
        assertThat(McsCategoryAllocator.isCategoryCollision(new RuntimeException(
                "duplicate key value violates unique constraint \"uq_domain_registry_selinux_level\"")))
                .isTrue();
        assertThat(McsCategoryAllocator.isCategoryCollision(new RuntimeException("wrapper",
                new RuntimeException("... UQ_DOMAIN_REGISTRY_SELINUX_LEVEL_PG ..."))))
                .as("H2 upper-cases constraint names; the match must be case-insensitive and "
                        + "walk the cause chain, because R2DBC wraps the driver exception")
                .isTrue();
        assertThat(McsCategoryAllocator.isCategoryCollision(new RuntimeException(
                "duplicate key value violates unique constraint \"uq_domain_registry_cluster_domain\"")))
                .as("""
                        A duplicate cluster_domain is the caller's 409 and must NOT be retried \
                        — retrying it would turn a legitimate conflict into five pointless \
                        round-trips and then the same error.""")
                .isFalse();
        assertThat(McsCategoryAllocator.isCategoryCollision(
                new RuntimeException("uq_domain_registry_ns_prefix")))
                .as("a duplicate SLUG is likewise a real conflict, not an allocation race")
                .isFalse();
        assertThat(McsCategoryAllocator.isCategoryCollision(new RuntimeException((String) null)))
                .isFalse();
    }

    @Test
    @DisplayName("isInReservedRange refuses the static matrix, the placeholders and junk")
    void isInReservedRange_refusesAnythingOutsideThePerDomainRange() {
        assertThat(McsCategoryAllocator.isInReservedRange("s0:c256")).isTrue();
        assertThat(McsCategoryAllocator.isInReservedRange("s0:c1023")).isTrue();
        assertThat(McsCategoryAllocator.isInReservedRange("s0:c257"))
                .as("a range check, NOT a parity check — the odd half of a pair is in range")
                .isTrue();

        assertThat(McsCategoryAllocator.isInReservedRange("s0:c85"))
                .as("hugmesh-generator docs/DOMAIN-IDP.md:56 forbids the base's s0:c85 / s0:c86 "
                        + "placeholders ever going live on a domain. They are UNIQUE values, so "
                        + "no constraint can catch them — only the writer can.")
                .isFalse();
        assertThat(McsCategoryAllocator.isInReservedRange("s0:c86")).isFalse();
        assertThat(McsCategoryAllocator.isInReservedRange("s0:c88"))
                .as("the highest statically assigned category on 2026-09-17 is below the floor")
                .isFalse();
        assertThat(McsCategoryAllocator.isInReservedRange("s0:c1024"))
                .as("containerd selinux_category_range = 1024 makes c1024 invalid")
                .isFalse();
        assertThat(McsCategoryAllocator.isInReservedRange("s0")).isFalse();
        assertThat(McsCategoryAllocator.isInReservedRange("")).isFalse();
        assertThat(McsCategoryAllocator.isInReservedRange(null)).isFalse();
    }

    private static int category(String level) {
        return Integer.parseInt(level.substring("s0:c".length()));
    }
}
