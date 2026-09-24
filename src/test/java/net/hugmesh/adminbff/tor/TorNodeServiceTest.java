package net.hugmesh.adminbff.tor;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.security.PrincipalDomain;
import net.hugmesh.commons.web.ApiException;
import net.hugmesh.adminbff.device.Device;
import net.hugmesh.adminbff.device.DeviceRegistryRepository;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * {@link TorNodeService}: report validation, the operator view's join, the domain-ADMIN
 * redaction, and the SUPERADMIN upstream write (hugmesh-admin-bff-api#108).
 */
class TorNodeServiceTest {

    static final String A = "a".repeat(56) + ".onion";
    static final String B = "b".repeat(56) + ".onion";
    static final String C = "c".repeat(56) + ".onion";

    private static Device device(String fp, String domain) {
        return new Device("id-" + fp, fp, "host-" + fp, "tn", Device.IMAGE_PRIMARY, "x86",
                Device.OWNER_SUPERADMIN, "root", domain, "mesh-1", Instant.now(), null);
    }

    private static TorNodeReport report(String fp, String primary, Map<String, String> domains) {
        return new TorNodeReport(fp, primary, domains, Instant.now(), Instant.now(), 3L);
    }

    // ── report validation ──────────────────────────────────────────────────────

    @Test
    void reportRefusal_acceptsWhatTheAgentExports() {
        assertThat(TorNodeService.reportRefusal(A, Map.of("brandb", B, "zeta", C))).isNull();
        assertThat(TorNodeService.reportRefusal(null, null)).isNull();          // not minted yet
        assertThat(TorNodeService.reportRefusal(A, Map.of())).isNull();
    }

    @Test
    void reportRefusal_refusesAnythingElse() {
        assertThat(TorNodeService.reportRefusal("not-an-onion", null)).contains("primary");
        assertThat(TorNodeService.reportRefusal(A, Map.of("brand.b", B))).contains("brand.b");
        assertThat(TorNodeService.reportRefusal(A, Map.of("brandb", "x.onion"))).contains("brandb");
        Map<String, String> tooMany = new HashMap<>();
        for (int i = 0; i <= TorOnionRules.MAX_DOMAINS; i++) tooMany.put("d" + i, B);
        assertThat(TorNodeService.reportRefusal(A, tooMany)).contains("at most");
    }

    @Test
    void report_refused_writesNothing_and422s() {
        TorNodeReportRowRepository reports = mock(TorNodeReportRowRepository.class);
        TorNodeService svc = new TorNodeService(reports, mock(TorNodeConfigRowRepository.class),
                mock(DeviceRegistryRepository.class));
        assertThatThrownBy(() -> svc.report("fp-1", "bogus", null).block())
                .isInstanceOf(ApiException.class)
                .satisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(422));
        verify(reports, never()).upsert(anyString(), any(), any());
    }

    @Test
    void report_accepted_storesTheSortedLineEncoding() {
        TorNodeReportRowRepository reports = mock(TorNodeReportRowRepository.class);
        when(reports.upsert("fp-1", A, "brandb " + B + "\nzeta " + C + "\n")).thenReturn(Mono.just(1L));
        when(reports.findByMachineKeyFp("fp-1")).thenReturn(Mono.just(new TorNodeReportRow("r1", "fp-1", A,
                "brandb " + B + "\nzeta " + C + "\n", Instant.now(), Instant.now(), 1L)));
        TorNodeService svc = new TorNodeService(reports, mock(TorNodeConfigRowRepository.class),
                mock(DeviceRegistryRepository.class));
        Map<String, String> unsorted = new HashMap<>(Map.of("zeta", C, "brandb", B));
        TorNodeReport r = svc.report("fp-1", A, unsorted).block();
        assertThat(r.domainOnions()).containsExactly(Map.entry("brandb", B), Map.entry("zeta", C));
        verify(reports).upsert("fp-1", A, "brandb " + B + "\nzeta " + C + "\n");
    }

    @Test
    void domainOnionEncoding_roundTrips_andSkipsGarbage() {
        Map<String, String> m = Map.of("brandb", B, "zeta", C);
        assertThat(TorNodeReport.decodeDomainOnions(TorNodeReport.encodeDomainOnions(m))).isEqualTo(m);
        assertThat(TorNodeReport.encodeDomainOnions(Map.of())).isEmpty();
        assertThat(TorNodeReport.decodeDomainOnions("junk\nbrandb " + B + "\na b c\n"))
                .containsExactly(Map.entry("brandb", B));
    }

    // ── the operator view ──────────────────────────────────────────────────────

    @Test
    void join_unionsReportsAndConfigs_andMarksRegistration() {
        List<TorNodeView> rows = TorNodeService.join(
                List.of(report("fp-1", A, Map.of("brandb", B)), report("fp-ghost", C, Map.of())),
                List.of(new TorNodeConfig("fp-1", true, "10.0.0.7:443", 2L, "root", Instant.now()),
                        new TorNodeConfig("fp-3", true, null, 1L, "root", Instant.now())),
                List.of(device("fp-1", "default"), device("fp-3", "default")));
        assertThat(rows).extracting(TorNodeView::node).containsExactly("fp-1", "fp-3", "fp-ghost");
        TorNodeView one = rows.get(0);
        assertThat(one.hostname()).isEqualTo("host-fp-1");
        assertThat(one.registered()).isTrue();
        assertThat(one.primary()).isEqualTo(A);
        assertThat(one.domains()).containsExactly(Map.entry("brandb", B));
        assertThat(one.upstream()).isEqualTo("10.0.0.7:443");
        assertThat(one.configGeneration()).isEqualTo(2L);
        assertThat(rows.get(1).primary()).isNull();          // configured, never reported
        assertThat(rows.get(1).upstreamManaged()).isTrue();
        assertThat(rows.get(2).registered()).isFalse();      // reported by an unknown fp
        assertThat(rows.get(2).hostname()).isNull();
    }

    @Test
    void redactFor_brandAdmin_seesOnlyTheirOwnOnion_noNodeIdentityNoRouting() {
        TorNodeView full = TorNodeService.join(
                List.of(report("fp-1", A, Map.of("brandb", B, "zeta", C))),
                List.of(new TorNodeConfig("fp-1", true, "10.0.0.7:443", 2L, "root", Instant.now())),
                List.of(device("fp-1", "default"))).get(0);
        TorNodeView b = TorNodeService.redactFor(full, "brandb");
        assertThat(b).isNotNull();
        assertThat(b.domains()).containsExactly(Map.entry("brandb", B));
        assertThat(b.primary()).isNull();                    // the primary is default's door
        assertThat(b.node()).isNull();
        assertThat(b.hostname()).isNull();
        assertThat(b.residencyDomain()).isNull();
        assertThat(b.upstream()).isNull();
        assertThat(b.upstreamManaged()).isFalse();
        assertThat(b.configGeneration()).isZero();
        assertThat(b.reportCount()).isZero();
    }

    @Test
    void redactFor_defaultAdmin_seesThePrimaryOnly() {
        TorNodeView full = TorNodeService.join(List.of(report("fp-1", A, Map.of("brandb", B))), List.of(),
                List.of(device("fp-1", "default"))).get(0);
        TorNodeView d = TorNodeService.redactFor(full, "default");
        assertThat(d.primary()).isEqualTo(A);
        assertThat(d.domains()).isEmpty();
    }

    @Test
    void redactFor_dropsRowsWithNothingToShow_andUnregisteredReporters() {
        TorNodeView reg = TorNodeService.join(List.of(report("fp-1", A, Map.of("brandb", B))), List.of(),
                List.of(device("fp-1", "default"))).get(0);
        assertThat(TorNodeService.redactFor(reg, "brandc")).isNull();
        assertThat(TorNodeService.redactFor(reg, null)).isNull();
        assertThat(TorNodeService.redactFor(reg, PrincipalDomain.NO_DOMAIN)).isNull();
        TorNodeView ghost = TorNodeService.join(List.of(report("fp-ghost", A, Map.of("brandb", B))), List.of(),
                List.of()).get(0);
        assertThat(TorNodeService.redactFor(ghost, "brandb")).isNull();
        assertThat(TorNodeService.redactFor(ghost, "default")).isNull();
    }

    @Test
    void list_superadminSeesEverything_adminSeesRedactedOwnRows() {
        TorNodeReportRowRepository reports = mock(TorNodeReportRowRepository.class);
        TorNodeConfigRowRepository configs = mock(TorNodeConfigRowRepository.class);
        DeviceRegistryRepository devices = mock(DeviceRegistryRepository.class);
        when(reports.findByOrderByMachineKeyFpAsc()).thenReturn(Flux.just(
                new TorNodeReportRow("r1", "fp-1", A, "brandb " + B + "\n", Instant.now(), Instant.now(), 1L),
                new TorNodeReportRow("r2", "fp-2", C, "", Instant.now(), Instant.now(), 1L)));
        when(configs.findByOrderByMachineKeyFpAsc()).thenReturn(Flux.empty());
        when(devices.listAll()).thenReturn(Flux.just(device("fp-1", "default"), device("fp-2", "default")));
        TorNodeService svc = new TorNodeService(reports, configs, devices);

        assertThat(svc.list(PrincipalDomain.superadminFor("default")).collectList().block())
                .extracting(TorNodeView::node).containsExactly("fp-1", "fp-2");
        List<TorNodeView> admin = svc.list(PrincipalDomain.forDomain("brandb")).collectList().block();
        assertThat(admin).hasSize(1);
        assertThat(admin.get(0).node()).isNull();
        assertThat(admin.get(0).domains()).containsExactly(Map.entry("brandb", B));
    }

    // ── the SUPERADMIN upstream write ──────────────────────────────────────────

    @Test
    void setUpstream_malformed_is422_andNeverTouchesTheStore() {
        TorNodeConfigRowRepository configs = mock(TorNodeConfigRowRepository.class);
        DeviceRegistryRepository devices = mock(DeviceRegistryRepository.class);
        TorNodeService svc = new TorNodeService(mock(TorNodeReportRowRepository.class), configs, devices);
        assertThatThrownBy(() -> svc.setUpstream("fp-1", "10.0.0.7 :443", "root").block())
                .isInstanceOf(ApiException.class)
                .satisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(422));
        verify(configs, never()).upsertUpstream(anyString(), any(), any());
        verify(devices, never()).findByMachineKey(anyString());
    }

    @Test
    void setUpstream_unknownNode_is422_andWritesNothing() {
        TorNodeConfigRowRepository configs = mock(TorNodeConfigRowRepository.class);
        DeviceRegistryRepository devices = mock(DeviceRegistryRepository.class);
        when(devices.findByMachineKey("typo")).thenReturn(Mono.empty());
        when(configs.findByMachineKeyFp("typo")).thenReturn(Mono.empty());
        TorNodeService svc = new TorNodeService(mock(TorNodeReportRowRepository.class), configs, devices);
        assertThatThrownBy(() -> svc.setUpstream("typo", "10.0.0.7:443", "root").block())
                .isInstanceOf(ApiException.class)
                .satisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(422));
        verify(configs, never()).upsertUpstream(anyString(), any(), any());
    }

    @Test
    void setUpstream_knownNode_writes_andNullMeansTheAgentDefault() {
        TorNodeConfigRowRepository configs = mock(TorNodeConfigRowRepository.class);
        DeviceRegistryRepository devices = mock(DeviceRegistryRepository.class);
        when(devices.findByMachineKey("fp-1")).thenReturn(Mono.just(device("fp-1", "default")));
        when(configs.upsertUpstream("fp-1", null, "root")).thenReturn(Mono.just(1L));
        when(configs.findByMachineKeyFp("fp-1")).thenReturn(Mono.just(
                new TorNodeConfigRow("c1", "fp-1", true, null, 4L, "root", Instant.now())));
        TorNodeConfig c = new TorNodeService(mock(TorNodeReportRowRepository.class), configs, devices)
                .setUpstream("fp-1", null, "root").block();
        assertThat(c.upstreamManaged()).isTrue();
        assertThat(c.upstream()).isNull();
        verify(configs).upsertUpstream("fp-1", null, "root");
    }
}
