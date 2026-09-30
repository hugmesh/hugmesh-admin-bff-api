package net.hugmesh.adminbff.domainregistry;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DuplicateKeyException;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The MCS-allocation RETRY LOOP of {@link DomainRegistryRepository#insert} — operator DECISION
 * 29c's race arbitration, in isolation.
 *
 * <h3>Why this test exists</h3>
 * 29c says the writer allocates the MCS pair AT INSERT, under a uniqueness constraint, so that
 * the CONSTRAINT — not the read — decides who wins a concurrent allocation. The loser then
 * re-reads and retries, bounded. Everything about that sentence was asserted in prose and
 * nothing exercised it: a mutation run that cut {@link DomainRegistryRepository#MCS_ALLOCATION_ATTEMPTS}
 * from 5 to 1 left the whole domainregistry suite GREEN, i.e. the retry could have been deleted
 * and no test would have noticed. A real race cannot be provoked against the single-connection
 * H2 slice, so the collision is injected here: the row repository is a mock that fails the
 * insert with the MCS constraint name exactly as PostgreSQL and the H2 PG-compat store do.
 *
 * <p>These four tests pin the loop in BOTH directions — that it retries at all, that it
 * re-reads the taken set on each attempt (a retry against a stale read would loop onto the same
 * doomed category), that it is bounded at exactly {@code MCS_ALLOCATION_ATTEMPTS}, and that a
 * {@code cluster_domain} / {@code ns_prefix} duplicate is NOT retried (it is a legitimate 409;
 * retrying it would be five round-trips to the same error).
 */
class DomainRegistryRepositoryRetryTest {

    /** The constraint name PostgreSQL and the H2 PG-compat store put in the violation message. */
    private static final String MCS_VIOLATION =
            "duplicate key value violates unique constraint \"uq_domain_registry_selinux_level\"";
    /** A duplicate that is a REAL conflict for the caller — never a retry. */
    private static final String NATURAL_KEY_VIOLATION =
            "duplicate key value violates unique constraint \"domain_registry_cluster_domain_key\"";

    private static DomainRegistration draft() {
        return new DomainRegistration(null, "acme.test", "acme", "Acme Inc", "vault:pki/acme",
                "acme", "acme-org", "tag:acme", true, null, null, null);
    }

    private static DomainRegistryRow persisted() {
        Instant now = Instant.now();
        return new DomainRegistryRow("gen-id", "acme.test", "acme", "Acme Inc", "vault:pki/acme",
                "acme", "acme-org", "tag:acme", true, now, "superadmin@infra", now,
                false, false, 0L, DomainIdp.SUPERDOMAIN, "s0:c256", "s0:c257");
    }

    /** A mock row repository whose taken-set read is empty and whose id read returns one row. */
    private static DomainRegistryRowRepository mockRows() {
        DomainRegistryRowRepository rows = mock(DomainRegistryRowRepository.class);
        when(rows.findAll()).thenReturn(Flux.empty());
        when(rows.findById(anyString())).thenReturn(Mono.just(persisted()));
        return rows;
    }

    @SafeVarargs
    private static void stubInsert(DomainRegistryRowRepository rows, Mono<String> first,
                                   Mono<String>... rest) {
        when(rows.insertReturningId(anyString(), anyString(), anyString(), anyString(),
                anyString(), anyString(), anyString(), anyBoolean(), any(), anyString(),
                any(), anyString(), anyString(), anyString(), any(), any()))
                .thenReturn(first, rest);
    }

    @Test
    @DisplayName("a losing insert retries and the fifth attempt lands (the bound is 5, not 1)")
    void mcsCollision_isRetried_untilAnAttemptWins() {
        DomainRegistryRowRepository rows = mockRows();
        Mono<String> collide = Mono.error(new DuplicateKeyException(MCS_VIOLATION));
        // Four losses, then a win: this passes ONLY while MCS_ALLOCATION_ATTEMPTS >= 5.
        stubInsert(rows, collide, collide, collide, collide, Mono.just("gen-id"));

        StepVerifier.create(new DomainRegistryRepository(rows).insert(draft(), "superadmin@infra"))
                .assertNext(saved -> org.assertj.core.api.Assertions
                        .assertThat(saved.clusterDomain()).isEqualTo("acme.test"))
                .verifyComplete();

        verify(rows, times(5)).insertReturningId(anyString(), anyString(), anyString(),
                anyString(), anyString(), anyString(), anyString(), anyBoolean(), any(),
                anyString(), any(), anyString(), anyString(), anyString(), any(), any());
    }

    @Test
    @DisplayName("each retry RE-READS the taken set — a stale read would re-pick the lost slot")
    void eachRetry_reReadsTheTakenSet() {
        DomainRegistryRowRepository rows = mockRows();
        Mono<String> collide = Mono.error(new DuplicateKeyException(MCS_VIOLATION));
        stubInsert(rows, collide, collide, Mono.just("gen-id"));

        new DomainRegistryRepository(rows).insert(draft(), "superadmin@infra").block();

        // One taken-set read per attempt. Allocating once and re-submitting the SAME pair would
        // race onto the same category forever — the retry has to re-observe what won.
        verify(rows, times(3)).findAll();
    }

    @Test
    @DisplayName("the loop is BOUNDED at 5 attempts — a stuck constraint surfaces, never spins")
    void mcsCollision_givesUpAtTheBound_andPropagatesTheViolation() {
        DomainRegistryRowRepository rows = mockRows();
        stubInsert(rows, Mono.error(new DuplicateKeyException(MCS_VIOLATION)));

        StepVerifier.create(new DomainRegistryRepository(rows).insert(draft(), "superadmin@infra"))
                .verifyErrorSatisfies(e -> org.assertj.core.api.Assertions.assertThat(e)
                        .isInstanceOf(DuplicateKeyException.class)
                        .hasMessageContaining("uq_domain_registry_selinux_level"));

        // Exactly the bound: fewer means the retry was weakened, more means it was unbounded.
        verify(rows, times(5)).insertReturningId(anyString(), anyString(), anyString(),
                anyString(), anyString(), anyString(), anyString(), anyBoolean(), any(),
                anyString(), any(), anyString(), anyString(), anyString(), any(), any());
    }

    @Test
    @DisplayName("a cluster_domain duplicate is NOT retried — it is a 409, not a lost race")
    void naturalKeyDuplicate_isNotRetried() {
        DomainRegistryRowRepository rows = mockRows();
        stubInsert(rows, Mono.error(new DuplicateKeyException(NATURAL_KEY_VIOLATION)));

        StepVerifier.create(new DomainRegistryRepository(rows).insert(draft(), "superadmin@infra"))
                .verifyErrorSatisfies(e -> org.assertj.core.api.Assertions.assertThat(e)
                        .isInstanceOf(DuplicateKeyException.class));

        verify(rows, times(1)).insertReturningId(anyString(), anyString(), anyString(),
                anyString(), anyString(), anyString(), anyString(), anyBoolean(), any(),
                anyString(), any(), anyString(), anyString(), anyString(), any(), any());
    }
}
