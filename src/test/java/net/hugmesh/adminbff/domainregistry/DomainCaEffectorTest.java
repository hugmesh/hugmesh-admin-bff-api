package net.hugmesh.adminbff.domainregistry;

import net.hugmesh.adminbff.domainregistry.DomainCaEffector.CaOutcome;
import net.hugmesh.adminbff.domainregistry.DomainCaEffector.Status;
import net.hugmesh.adminbff.lease.LeaderElection;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.netty.http.client.HttpClient;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * The per-domain CA effector (hugmesh-admin-bff-api#99) against a REAL loopback fake Vault
 * ({@link FakeVaultPki}) and a mocked registry facade. Proves, per the task's done-when:
 * success records the PKI path + flips {@code ca_provisioned}; a Vault 4xx or 5xx leaves the
 * row untouched and reports FAILED; an already-provisioned row and the property-off default
 * are no-ops that send no HTTP. Plus the key-material contract: the root is always generated
 * with the {@code internal} type (Vault keeps the key) and the token never reaches an outcome.
 */
class DomainCaEffectorTest {

    private FakeVaultPki vault;
    private DomainRegistryRepository repo;
    private DomainCaProperties props;

    @BeforeEach
    void setUp() throws Exception {
        vault = new FakeVaultPki();
        repo = mock(DomainRegistryRepository.class);
        when(repo.markCaProvisioned(anyString(), anyString())).thenReturn(Mono.just(true));
        props = new DomainCaProperties();
        props.setEnabled(true);
        props.setVaultAddr(vault.baseUrl());
        props.setVaultToken(FakeVaultPki.TOKEN);
    }

    @AfterEach
    void tearDown() {
        vault.close();
    }

    private VaultPkiClient client(String token) {
        return new VaultPkiClient(vault.baseUrl(), token, VaultPkiClient.RootSpec.of(props), 5000,
                HttpClient.create());
    }

    private DomainCaEffector effector() {
        return new DomainCaEffector(repo, client(FakeVaultPki.TOKEN), props);
    }

    private static DomainRegistration row(String caRef, boolean caProvisioned) {
        return new DomainRegistration("id-acme", "acme.test", "acme", "Acme Inc", caRef, "acme",
                "acme-org", "tag:acme", true, null, "superadmin@infra", null,
                caProvisioned, false, 0L);
    }

    @Test
    void generateRow_mountsPki_generatesInternalRoot_andRecordsThePath() {
        CaOutcome out = effector().provision(row("generate", false)).block();

        assertThat(out).isNotNull();
        assertThat(out.status()).isEqualTo(Status.PROVISIONED);
        assertThat(out.caRef()).isEqualTo("pki-domain-acme");
        verify(repo).markCaProvisioned("id-acme", "pki-domain-acme");

        assertThat(vault.mounts).containsEntry("pki-domain-acme", "pki");
        assertThat(vault.rooted).containsExactly("pki-domain-acme");
        // Exactly the four documented calls, in order, all carrying the token.
        assertThat(vault.requests).extracting(r -> r.method() + " " + r.path())
                .containsExactly(
                        "GET /v1/sys/mounts/pki-domain-acme",
                        "POST /v1/sys/mounts/pki-domain-acme",
                        "GET /v1/pki-domain-acme/issuers",
                        "POST /v1/pki-domain-acme/root/generate/internal");
        assertThat(vault.requests).allSatisfy(r -> assertThat(r.token()).isEqualTo(FakeVaultPki.TOKEN));
        var gen = vault.requests.get(3).body();
        assertThat(gen.path("common_name").asText()).isEqualTo("acme.test Root CA");
        assertThat(gen.path("key_type").asText()).isEqualTo("rsa");
        assertThat(gen.path("key_bits").asInt()).isEqualTo(4096);
        assertThat(vault.requests.get(1).body().path("type").asText()).isEqualTo("pki");
    }

    @Test
    void neverAsksVaultToExportTheKey() {
        effector().provision(row("generate", false)).block();
        assertThat(vault.requests).noneSatisfy(r -> assertThat(r.path()).contains("exported"));
        assertThat(vault.requests).noneSatisfy(r -> assertThat(r.path()).contains("/keys"));
    }

    @Test
    void vault4xx_leavesTheRowUnprovisioned_andReportsTheStep() {
        vault.forcedStatus.put("POST /root/generate/internal", 403);

        CaOutcome out = effector().provision(row("generate", false)).block();

        assertThat(out).isNotNull();
        assertThat(out.status()).isEqualTo(Status.FAILED);
        assertThat(out.caRef()).isEqualTo("generate");
        assertThat(out.detail()).contains("GENERATE_ROOT").contains("403");
        verify(repo, never()).markCaProvisioned(anyString(), anyString());
    }

    @Test
    void wrongToken_403_isFailed_andTheTokenIsNotInTheDetail() {
        DomainCaEffector eff = new DomainCaEffector(repo, client("hvs.wrong-token"), props);

        CaOutcome out = eff.provision(row("generate", false)).block();

        assertThat(out).isNotNull();
        assertThat(out.status()).isEqualTo(Status.FAILED);
        assertThat(out.detail()).contains("READ_MOUNT").contains("403")
                .doesNotContain("hvs.wrong-token").doesNotContain(FakeVaultPki.TOKEN);
        verify(repo, never()).markCaProvisioned(anyString(), anyString());
        assertThat(vault.mounts).isEmpty();
    }

    @Test
    void vault5xx_leavesTheRowUnprovisioned() {
        vault.forcedStatus.put("POST /v1/sys/mounts/pki-domain-acme", 503);

        CaOutcome out = effector().provision(row("generate", false)).block();

        assertThat(out).isNotNull();
        assertThat(out.status()).isEqualTo(Status.FAILED);
        assertThat(out.detail()).contains("ENABLE_MOUNT").contains("503");
        verify(repo, never()).markCaProvisioned(anyString(), anyString());
        assertThat(vault.count("POST", "/root/generate/internal")).isZero();
    }

    @Test
    void vaultUnreachable_isFailed_notAnError() throws Exception {
        String dead = vault.baseUrl();
        vault.close();
        props.setVaultAddr(dead);
        DomainCaEffector eff = new DomainCaEffector(repo,
                new VaultPkiClient(dead, FakeVaultPki.TOKEN, VaultPkiClient.RootSpec.of(props), 2000,
                        HttpClient.create()), props);

        CaOutcome out = eff.provision(row("generate", false)).block();

        assertThat(out).isNotNull();
        assertThat(out.status()).isEqualTo(Status.FAILED);
        verify(repo, never()).markCaProvisioned(anyString(), anyString());
    }

    @Test
    void alreadyProvisioned_isANoOp_withNoVaultCall() {
        CaOutcome out = effector().provision(row("pki-domain-acme", true)).block();

        assertThat(out).isNotNull();
        assertThat(out.status()).isEqualTo(Status.SKIPPED);
        assertThat(vault.requests).isEmpty();
        verify(repo, never()).markCaProvisioned(anyString(), anyString());
    }

    @Test
    void generateButAlreadyFlagged_isStillANoOp() {
        CaOutcome out = effector().provision(row("generate", true)).block();

        assertThat(out).isNotNull();
        assertThat(out.status()).isEqualTo(Status.SKIPPED);
        assertThat(vault.requests).isEmpty();
    }

    @Test
    void caRefNamingAnExistingCa_isANoOp() {
        CaOutcome out = effector().provision(row("vault:pki/acme", false)).block();

        assertThat(out).isNotNull();
        assertThat(out.status()).isEqualTo(Status.SKIPPED);
        assertThat(vault.requests).isEmpty();
        verify(repo, never()).markCaProvisioned(anyString(), anyString());
    }

    @Test
    void propertyOff_isANoOp_noVaultCall_noDbRead_noDbWrite() {
        props.setEnabled(false);
        DomainCaEffector eff = effector();

        CaOutcome out = eff.provision(row("generate", false)).block();
        List<CaOutcome> pass = eff.provisionPending().collectList().block();

        assertThat(out).isNotNull();
        assertThat(out.status()).isEqualTo(Status.DISABLED);
        assertThat(pass).isEmpty();
        assertThat(vault.requests).isEmpty();
        verifyNoInteractions(repo);
    }

    @Test
    void noVaultClient_isANoOp_evenWithThePropertyOn() {
        DomainCaEffector eff = new DomainCaEffector(repo, null, props);

        assertThat(eff.provision(row("generate", false)).block().status()).isEqualTo(Status.DISABLED);
        assertThat(eff.provisionPending().collectList().block()).isEmpty();
        verifyNoInteractions(repo);
    }

    @Test
    void rerunAfterRootWasMadeButNotRecorded_reusesTheRoot_noSecondRoot() {
        vault.mounts.put("pki-domain-acme", "pki");
        vault.rooted.add("pki-domain-acme");

        CaOutcome out = effector().provision(row("generate", false)).block();

        assertThat(out).isNotNull();
        assertThat(out.status()).isEqualTo(Status.PROVISIONED);
        assertThat(vault.count("POST", "/v1/sys/mounts/pki-domain-acme")).isZero();
        assertThat(vault.count("POST", "/root/generate/internal")).isZero();
        verify(repo).markCaProvisioned("id-acme", "pki-domain-acme");
    }

    @Test
    void rerunAfterMountButNoRoot_generatesWithoutRemounting() {
        vault.mounts.put("pki-domain-acme", "pki");

        CaOutcome out = effector().provision(row("generate", false)).block();

        assertThat(out.status()).isEqualTo(Status.PROVISIONED);
        assertThat(vault.count("POST", "/v1/sys/mounts/pki-domain-acme")).isZero();
        assertThat(vault.count("POST", "/root/generate/internal")).isEqualTo(1);
    }

    @Test
    void mountPathTakenByAnotherEngine_isFailed_neverReused() {
        vault.mounts.put("pki-domain-acme", "kv");

        CaOutcome out = effector().provision(row("generate", false)).block();

        assertThat(out.status()).isEqualTo(Status.FAILED);
        assertThat(out.detail()).contains("READ_MOUNT").contains("'kv'");
        assertThat(vault.count("POST", "/root/generate/internal")).isZero();
        verify(repo, never()).markCaProvisioned(anyString(), anyString());
    }

    @Test
    void rowChangedUnderneath_isReported_notOverwritten() {
        when(repo.markCaProvisioned(anyString(), anyString())).thenReturn(Mono.just(false));

        CaOutcome out = effector().provision(row("generate", false)).block();

        assertThat(out.status()).isEqualTo(Status.SKIPPED);
        assertThat(out.caRef()).isEqualTo("generate");
    }

    @Test
    void invalidSlug_isFailed_withoutCallingVault() {
        DomainRegistration bad = new DomainRegistration("id-x", "x.test", "x", "X", "generate",
                "../sys", "x-org", "tag:x", true, null, null, null, false, false, 0L);

        CaOutcome out = effector().provision(bad).block();

        assertThat(out.status()).isEqualTo(Status.FAILED);
        assertThat(vault.requests).isEmpty();
    }

    @Test
    void provisionPending_worksThroughEveryPendingRow() {
        DomainRegistration a = row("generate", false);
        DomainRegistration b = new DomainRegistration("id-beta", "beta.test", "beta", "Beta", "generate",
                "beta", "beta-org", "tag:beta", true, null, null, null, false, false, 0L);
        when(repo.findCaPendingGenerate()).thenReturn(Flux.just(a, b));

        List<CaOutcome> outs = effector().provisionPending().collectList().block();

        assertThat(outs).extracting(CaOutcome::status).containsExactly(Status.PROVISIONED, Status.PROVISIONED);
        assertThat(vault.mounts).containsKeys("pki-domain-acme", "pki-domain-beta");
    }

    @Test
    void reconciler_notLeader_touchesNothing() {
        LeaderElection leader = mock(LeaderElection.class);
        when(leader.isLeader()).thenReturn(false);
        when(leader.label()).thenReturn("test");
        DomainCaReconciler rec = new DomainCaReconciler(effector(), leader);

        assertThat(rec.runOnce().block()).isEmpty();
        verify(repo, never()).findCaPendingGenerate();
        assertThat(vault.requests).isEmpty();
    }

    @Test
    void reconciler_leader_provisionsPendingRows() {
        LeaderElection leader = mock(LeaderElection.class);
        when(leader.isLeader()).thenReturn(true);
        when(repo.findCaPendingGenerate()).thenReturn(Flux.just(row("generate", false)));

        List<CaOutcome> outs = new DomainCaReconciler(effector(), leader).runOnce().block();

        assertThat(outs).extracting(CaOutcome::status).containsExactly(Status.PROVISIONED);
        verify(repo).markCaProvisioned(any(), any());
    }
}
