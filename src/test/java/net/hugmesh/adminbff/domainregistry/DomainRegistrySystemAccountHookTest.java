package net.hugmesh.adminbff.domainregistry;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.notification.SystemAccountProvisioner;
import net.hugmesh.adminbff.support.TestDatabaseConfig;
import net.hugmesh.adminbff.web.dto.CreateDomainRequest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Proves the DOMAIN-CREATE HOOK (Notifications PR3): registering a domain idempotently
 * provisions THAT domain's {@code @system} account (best-effort), and a provisioning
 * failure NEVER loses the registered domain row. Uses the same Liquibase-applied H2
 * (PG-compat) wiring as {@code DomainRegistryServiceTest}, with a mocked
 * {@link SystemAccountProvisioner}.
 */
@DataR2dbcTest
@Import(TestDatabaseConfig.class)
@ActiveProfiles("test")
class DomainRegistrySystemAccountHookTest {

    @Autowired DatabaseClient db;

    @org.junit.jupiter.api.BeforeEach
    void clear() {
        db.sql("DELETE FROM domain_registry").fetch().rowsUpdated().block();
    }

    private static CreateDomainRequest create(String clusterDomain) {
        return new CreateDomainRequest(clusterDomain, "acme", "Acme Inc", "vault:pki/acme",
                "acme", "acme-org", "tag:acme", null);
    }

    @Test
    void create_firesPerDomainSystemAccountProvisioning() {
        SystemAccountProvisioner provisioner = mock(SystemAccountProvisioner.class);
        when(provisioner.provision(eq("acme.test"))).thenReturn(Mono.empty());
        DomainRegistryService svc =
                new DomainRegistryService(new DomainRegistryRepository(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.adminbff.domainregistry.DomainRegistryRowRepository.class)), provisioner);

        DomainRegistration saved = svc.create(create("acme.test"), "superadmin@infra").block();

        assertThat(saved).isNotNull();
        assertThat(saved.clusterDomain()).isEqualTo("acme.test");
        // The hook provisions @system for THIS domain (and only this domain).
        verify(provisioner).provision("acme.test");
        verify(provisioner, never()).provision("other.test");
    }

    @Test
    void create_provisioningFailure_keepsTheDomainRow() {
        SystemAccountProvisioner provisioner = mock(SystemAccountProvisioner.class);
        // A Casdoor outage mid-provision must NOT roll back / lose the domain registration.
        when(provisioner.provision(eq("acme.test")))
                .thenReturn(Mono.error(new RuntimeException("casdoor down")));
        DomainRegistryService svc =
                new DomainRegistryService(new DomainRegistryRepository(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.adminbff.domainregistry.DomainRegistryRowRepository.class)), provisioner);

        DomainRegistration saved = svc.create(create("acme.test"), "superadmin@infra").block();

        // Create still succeeded despite the provisioning failure (best-effort hook).
        assertThat(saved).isNotNull();
        assertThat(saved.clusterDomain()).isEqualTo("acme.test");
        // And the row is durably present.
        DomainRegistration fetched = svc.get("acme.test").block();
        assertThat(fetched).isNotNull();
        assertThat(fetched.clusterDomain()).isEqualTo("acme.test");
        verify(provisioner).provision("acme.test");
    }

    @Test
    void create_withNoProvisioner_stillWorks_backCompatConstructor() {
        // The back-compat constructor wires no provisioner → create is unchanged.
        DomainRegistryService svc = new DomainRegistryService(new DomainRegistryRepository(net.hugmesh.adminbff.testutil.R2dbcRepos.of(db, net.hugmesh.adminbff.domainregistry.DomainRegistryRowRepository.class)));
        DomainRegistration saved = svc.create(create("acme.test"), "superadmin@infra").block();
        assertThat(saved).isNotNull();
        assertThat(saved.clusterDomain()).isEqualTo("acme.test");
    }
}
