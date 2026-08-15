package net.hugmesh.adminbff.workload;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Flux;
import reactor.test.StepVerifier;
import net.hugmesh.adminbff.device.SshLicense;
import net.hugmesh.adminbff.device.SshLicenseRepository;
import net.hugmesh.adminbff.lease.LeaderElection;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * {@code mint} must never key an entry under a blank subject.
 *
 * <h2>Why</h2>
 * {@code validate(subject, token)} resolves the caller through {@code tokens.get(subject)} — the
 * same map {@code mint} writes. An entry stored under {@code ""} would therefore make
 * {@code validate("", token)} succeed for any caller whose subject resolved to blank. Before this
 * check, {@code mint} license-gated {@code operatorId} but never inspected {@code subject}, and
 * the two are separate arguments on the {@code WorkloadSuperadminController} path.
 *
 * <p>Reaching that needed a JWT with an empty {@code sub} on a {@code SUPERADMIN}-gated endpoint,
 * so this is defense in depth rather than the fix for a live hole — but the token map must not be
 * poisonable at all, and the gates' own blank-subject rejection is a second layer, not the only
 * one. (The desktop mint path passes the same value as both subject and operatorId, so a blank
 * there already failed the licence check.)
 */
class WorkloadStepUpServiceMintTest {

    private final LeaderElection leader = mock(LeaderElection.class);
    private final SshLicenseRepository licenses = mock(SshLicenseRepository.class);

    private WorkloadStepUpService leaderOnly() {
        when(leader.isLeader()).thenReturn(true);
        when(leader.label()).thenReturn("test-leader");
        return new WorkloadStepUpService(leader, licenses);
    }

    /** A leader replica whose {@code operatorId} holds an active licence. */
    private WorkloadStepUpService licensedLeader(String operatorId) {
        SshLicense lic = mock(SshLicense.class);
        when(lic.operator()).thenReturn(operatorId);
        when(licenses.listActiveAll()).thenReturn(Flux.just(lic));
        return leaderOnly();
    }

    @Test
    void mint_withBlankSubject_isDenied_evenWhenTheOperatorIsLicensed() {
        WorkloadStepUpService svc = licensedLeader("licensed-operator");
        StepVerifier.create(svc.mint("", "licensed-operator"))
                .verifyErrorSatisfies(e -> assertThat(e.getMessage())
                        .as("a blank subject must be refused BEFORE anything is stored")
                        .contains("no subject"));
        // And nothing was poisoned into the map.
        assertThat(svc.validate("", "anything"))
                .as("no entry may exist under a blank subject").isFalse();
    }

    @Test
    void mint_withNullSubject_isDenied() {
        WorkloadStepUpService svc = licensedLeader("licensed-operator");
        StepVerifier.create(svc.mint(null, "licensed-operator"))
                .verifyErrorSatisfies(e -> assertThat(e.getMessage()).contains("no subject"));
    }

    @Test
    void mint_withARealSubject_stillWorks_andValidates() {
        WorkloadStepUpService svc = licensedLeader("licensed-operator");
        String token = svc.mint("admin-x", "licensed-operator").block();
        assertThat(token).as("the ordinary mint path is unchanged").isNotBlank();
        assertThat(svc.validate("admin-x", token)).isTrue();
        assertThat(svc.validate("admin-x", "wrong-token")).isFalse();
        assertThat(svc.validate("someone-else", token))
                .as("a token is bound to its subject").isFalse();
    }
}
