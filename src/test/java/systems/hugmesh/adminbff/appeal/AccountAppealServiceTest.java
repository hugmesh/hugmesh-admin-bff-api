package systems.hugmesh.adminbff.appeal;

import org.junit.jupiter.api.Test;
import org.mockito.InOrder;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import systems.hugmesh.adminbff.suspension.AccessSuspension;
import systems.hugmesh.adminbff.suspension.SuspensionService;
import systems.hugmesh.commons.security.PrincipalDomain;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * THE HONESTY KEYSTONE for this feature: {@link AccountAppealService#decide} on
 * APPROVED must actually reverse the underlying {@code access_suspension} PROFILE row
 * (via {@link SuspensionService#clearByHandle}, localpart-normalized so an admin's
 * differently-formatted ban target still resolves) — never just flip the appeal row's
 * status. And a FAILED restore must never let the appeal render as applied: the CAS
 * write to the appeal row must not even be attempted unless the restore already
 * succeeded. A restore that finds NOTHING to clear (0 rows) is honestly distinct from
 * an error — it still proceeds to APPROVED, because by construction it means the
 * localpart is already not PROFILE-restricted (see {@link SuspensionService#clearByHandle}).
 */
class AccountAppealServiceTest {

    private static final PrincipalDomain SCOPE = PrincipalDomain.forDomain("brandx");

    private static AccountAppeal pending() {
        return new AccountAppeal("ap1", "google:alice@x.com", "alice@x.com", "brandx",
                "let me back in", null, AccountAppeal.STATUS_PENDING, Instant.now(), null, null);
    }

    @Test
    void approve_restoresAccess_beforeMarkingAppealApproved() {
        AccountAppealRepository repo = mock(AccountAppealRepository.class);
        SuspensionService suspensions = mock(SuspensionService.class);
        AccountAppealService service = new AccountAppealService(repo, suspensions);

        when(repo.findById(eq("ap1"), eq(SCOPE))).thenReturn(Mono.just(pending()));
        // The banning admin free-typed the ban target as "google:alice@x.com" — a
        // DIFFERENT string than the appellant's bare handle "alice@x.com". This is
        // exactly the case clearByHandle (localpart-normalized) exists to still find;
        // an exact-string clear() would have missed this row entirely.
        when(suspensions.clearByHandle(eq(AccessSuspension.ROLE_PROFILE), eq("alice@x.com"), eq("admin-x"), eq(SCOPE)))
                .thenReturn(Mono.just(1L));
        when(repo.decide(eq("ap1"), eq("APPROVED"), eq("admin-x"), eq(SCOPE))).thenReturn(Mono.just(1L));

        StepVerifier.create(service.decide("ap1", "APPROVED", "admin-x", SCOPE))
                .expectNext(1L)
                .verifyComplete();

        // The restore of the REAL banned-state mechanism happens, and happens BEFORE
        // the appeal row is CASed to APPROVED — never a bare status flip.
        InOrder order = inOrder(suspensions, repo);
        order.verify(suspensions).clearByHandle(AccessSuspension.ROLE_PROFILE, "alice@x.com", "admin-x", SCOPE);
        order.verify(repo).decide("ap1", "APPROVED", "admin-x", SCOPE);
    }

    @Test
    void approve_whenNothingActiveMatchesTheLocalpart_stillApproves_becauseThatMeansAlreadyUnrestricted() {
        // clearByHandle finding 0 rows is NOT a matching miss the way an exact-string
        // clear() would be — it is the SAME localpart read statusFor()/the access gate
        // itself performs, so 0 honestly means "not PROFILE-restricted any more".
        AccountAppealRepository repo = mock(AccountAppealRepository.class);
        SuspensionService suspensions = mock(SuspensionService.class);
        AccountAppealService service = new AccountAppealService(repo, suspensions);

        when(repo.findById(eq("ap1"), eq(SCOPE))).thenReturn(Mono.just(pending()));
        when(suspensions.clearByHandle(eq(AccessSuspension.ROLE_PROFILE), eq("alice@x.com"), eq("admin-x"), eq(SCOPE)))
                .thenReturn(Mono.just(0L));
        when(repo.decide(eq("ap1"), eq("APPROVED"), eq("admin-x"), eq(SCOPE))).thenReturn(Mono.just(1L));

        StepVerifier.create(service.decide("ap1", "APPROVED", "admin-x", SCOPE))
                .expectNext(1L)
                .verifyComplete();

        verify(repo).decide("ap1", "APPROVED", "admin-x", SCOPE);
    }

    @Test
    void approve_whenRestoreFails_neverMarksAppealApproved_andPropagatesTheError() {
        AccountAppealRepository repo = mock(AccountAppealRepository.class);
        SuspensionService suspensions = mock(SuspensionService.class);
        AccountAppealService service = new AccountAppealService(repo, suspensions);

        when(repo.findById(eq("ap1"), eq(SCOPE))).thenReturn(Mono.just(pending()));
        when(suspensions.clearByHandle(anyString(), anyString(), anyString(), any()))
                .thenReturn(Mono.error(new RuntimeException("casdoor unreachable")));

        StepVerifier.create(service.decide("ap1", "APPROVED", "admin-x", SCOPE))
                .expectErrorMessage("casdoor unreachable")
                .verify();

        // The failed restore must NEVER let the appeal row render as applied.
        verify(repo, never()).decide(anyString(), anyString(), anyString(), any());
    }

    @Test
    void deny_neverCallsSuspensionClear() {
        AccountAppealRepository repo = mock(AccountAppealRepository.class);
        SuspensionService suspensions = mock(SuspensionService.class);
        AccountAppealService service = new AccountAppealService(repo, suspensions);

        when(repo.findById(eq("ap1"), eq(SCOPE))).thenReturn(Mono.just(pending()));
        when(repo.decide(eq("ap1"), eq("DENIED"), eq("admin-x"), eq(SCOPE))).thenReturn(Mono.just(1L));

        StepVerifier.create(service.decide("ap1", "DENIED", "admin-x", SCOPE))
                .expectNext(1L)
                .verifyComplete();

        verify(suspensions, never()).clearByHandle(anyString(), anyString(), anyString(), any());
    }

    @Test
    void decide_whenAppealAlreadyDecided_isNoOp() {
        AccountAppealRepository repo = mock(AccountAppealRepository.class);
        SuspensionService suspensions = mock(SuspensionService.class);
        AccountAppealService service = new AccountAppealService(repo, suspensions);

        AccountAppeal decided = new AccountAppeal("ap1", "google:alice@x.com", "alice@x.com", "brandx",
                "r", null, AccountAppeal.STATUS_APPROVED, Instant.now(), Instant.now(), "someone-else");
        when(repo.findById(eq("ap1"), eq(SCOPE))).thenReturn(Mono.just(decided));

        StepVerifier.create(service.decide("ap1", "APPROVED", "admin-x", SCOPE))
                .expectNext(0L)
                .verifyComplete();

        verify(suspensions, never()).clearByHandle(anyString(), anyString(), anyString(), any());
        verify(repo, never()).decide(anyString(), anyString(), anyString(), any());
    }

    @Test
    void submit_whenPendingAlreadyExists_returnsExistingRow_andNeverInserts() {
        AccountAppealRepository repo = mock(AccountAppealRepository.class);
        SuspensionService suspensions = mock(SuspensionService.class);
        AccountAppealService service = new AccountAppealService(repo, suspensions);

        AccountAppeal existing = pending();
        when(repo.findPendingForUser("google:alice@x.com", "brandx")).thenReturn(Mono.just(existing));

        StepVerifier.create(service.submit("google:alice@x.com", "alice@x.com", "brandx", "again", null))
                .expectNext(existing)
                .verifyComplete();

        verify(repo, never()).insertPending(anyString(), anyString(), anyString(), anyString(), any());
    }
}
