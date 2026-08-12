package net.hugmesh.adminbff.capability;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.security.PrincipalDomain;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The {@link DomainCapabilityService#isActive} TRUTH TABLE — the security-critical
 * two-tier predicate the not-yet-wired user-bff claim path will rely on — plus the
 * grant/enable read-modify-write independence (each write must never clobber the OTHER
 * key) and the scoped list.
 */
class DomainCapabilityServiceTest {

    private DomainCapabilityRepository repo;
    private DomainCapabilityService service;

    private static final String DOMAIN = "brandx";
    private static final String CAP = DomainCapability.USER_MESH_DEVICES;

    @BeforeEach
    void setup() {
        repo = mock(DomainCapabilityRepository.class);
        service = new DomainCapabilityService(repo);
        when(repo.maxGeneration()).thenReturn(Mono.just(5L));
    }

    private static DomainCapability row(String domain, boolean granted, boolean enabled) {
        return new DomainCapability("id", domain, CAP, granted, enabled, "root", Instant.now(), 1);
    }

    private void global(boolean granted) {
        when(repo.find(DomainCapability.GLOBAL_DOMAIN, CAP))
                .thenReturn(Mono.just(row(DomainCapability.GLOBAL_DOMAIN, granted, false)));
    }

    private void perDomain(boolean granted, boolean enabled) {
        when(repo.find(DOMAIN, CAP)).thenReturn(Mono.just(row(DOMAIN, granted, enabled)));
    }

    // ════════════════════════ isActive truth table ═══════════════════════════════════

    @Test
    void globalOff_killsEverything_evenWhenPerDomainBothOn() {
        global(false);
        perDomain(true, true);
        assertThat(service.isActive(DOMAIN, CAP).block()).isFalse();
    }

    @Test
    void grantedNotEnabled_isInactive() {
        global(true);
        perDomain(true, false);
        assertThat(service.isActive(DOMAIN, CAP).block()).isFalse();
    }

    @Test
    void enabledNotGranted_isInactive() {
        global(true);
        perDomain(false, true);
        assertThat(service.isActive(DOMAIN, CAP).block()).isFalse();
    }

    @Test
    void bothGrantedAndEnabled_globalOn_isActive() {
        global(true);
        perDomain(true, true);
        assertThat(service.isActive(DOMAIN, CAP).block()).isTrue();
    }

    @Test
    void absentGlobalRow_isInactive_failsClosed() {
        when(repo.find(DomainCapability.GLOBAL_DOMAIN, CAP)).thenReturn(Mono.empty());
        perDomain(true, true);
        assertThat(service.isActive(DOMAIN, CAP).block()).isFalse();
    }

    @Test
    void absentPerDomainRow_isInactive_failsClosed() {
        global(true);
        when(repo.find(DOMAIN, CAP)).thenReturn(Mono.empty());
        assertThat(service.isActive(DOMAIN, CAP).block()).isFalse();
    }

    @Test
    void repositoryError_isInactive_failsClosed_neverThrows() {
        global(true);
        when(repo.find(DOMAIN, CAP)).thenReturn(Mono.error(new RuntimeException("db down")));
        assertThat(service.isActive(DOMAIN, CAP).block()).isFalse();
    }

    // ════════════════════════ grant()/enable() key independence ═══════════════════════

    @Test
    void grant_preservesExistingEnabledValue() {
        perDomain(false, true); // admin already enabled; not yet granted
        when(repo.upsert(eq(DOMAIN), eq(CAP), eq(true), eq(true), anyString(), anyLong()))
                .thenReturn(Mono.just(row(DOMAIN, true, true)));

        DomainCapability out = service.grant(DOMAIN, CAP, true, "superadmin@root").block();

        assertThat(out.granted()).isTrue();
        assertThat(out.enabled()).isTrue();
        verify(repo).upsert(eq(DOMAIN), eq(CAP), eq(true), eq(true), anyString(), anyLong());
    }

    @Test
    void grant_onFreshRow_defaultsEnabledFalse() {
        when(repo.find(DOMAIN, CAP)).thenReturn(Mono.empty());
        when(repo.upsert(eq(DOMAIN), eq(CAP), eq(true), eq(false), anyString(), anyLong()))
                .thenReturn(Mono.just(row(DOMAIN, true, false)));

        service.grant(DOMAIN, CAP, true, "superadmin@root").block();

        verify(repo).upsert(eq(DOMAIN), eq(CAP), eq(true), eq(false), anyString(), anyLong());
    }

    @Test
    void enable_preservesExistingGrantedValue() {
        perDomain(true, false); // already granted; admin now opts in
        when(repo.upsert(eq(DOMAIN), eq(CAP), eq(true), eq(true), anyString(), anyLong()))
                .thenReturn(Mono.just(row(DOMAIN, true, true)));

        DomainCapability out = service.enable(DOMAIN, CAP, true, "admin@brandx").block();

        assertThat(out.granted()).isTrue();
        assertThat(out.enabled()).isTrue();
        verify(repo).upsert(eq(DOMAIN), eq(CAP), eq(true), eq(true), anyString(), anyLong());
    }

    @Test
    void enable_onFreshRow_defaultsGrantedFalse_neverSelfGrants() {
        // An admin flipping "enabled" on a NEVER-granted domain must not silently grant it.
        when(repo.find(DOMAIN, CAP)).thenReturn(Mono.empty());
        when(repo.upsert(eq(DOMAIN), eq(CAP), eq(false), eq(true), anyString(), anyLong()))
                .thenReturn(Mono.just(row(DOMAIN, false, true)));

        DomainCapability out = service.enable(DOMAIN, CAP, true, "admin@brandx").block();

        assertThat(out.granted()).isFalse();
        verify(repo).upsert(eq(DOMAIN), eq(CAP), eq(false), eq(true), anyString(), anyLong());
    }

    // ════════════════════════ listForScope ═════════════════════════════════════════

    @Test
    void listForScope_scopedAdmin_listsOwnDomainOnly() {
        when(repo.listForDomain(DOMAIN)).thenReturn(Flux.just(row(DOMAIN, true, true)));
        var out = service.listForScope(PrincipalDomain.forDomain(DOMAIN)).collectList().block();
        assertThat(out).hasSize(1);
        assertThat(out.get(0).domain()).isEqualTo(DOMAIN);
        verify(repo).listForDomain(DOMAIN);
    }

    @Test
    void listForScope_superadmin_listsEverything() {
        when(repo.listAll()).thenReturn(Flux.just(row(DOMAIN, true, true),
                row(DomainCapability.GLOBAL_DOMAIN, false, false)));
        var out = service.listForScope(PrincipalDomain.superadminFor(DOMAIN)).collectList().block();
        assertThat(out).hasSize(2);
        verify(repo).listAll();
    }
}
