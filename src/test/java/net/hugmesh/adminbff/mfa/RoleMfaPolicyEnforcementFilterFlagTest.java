package net.hugmesh.adminbff.mfa;

import net.hugmesh.authcore.casdoor.MfaStepUpService;
import net.hugmesh.commons.security.DomainRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.ConfigDataApplicationContextInitializer;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * The DARK half of {@link RoleMfaPolicyEnforcementFilter}: with the flag unset, false, or only the
 * pre-existing {@code app.casdoor.mfa.enabled} switched on, the filter bean does not exist, so no
 * request can reach it or the policy store.
 *
 * <p>The first test loads the REAL {@code application.yml} (not a hand-written property), so it
 * goes red if a default ever flips the flag on.
 */
class RoleMfaPolicyEnforcementFilterFlagTest {

    private ApplicationContextRunner runner() {
        return new ApplicationContextRunner()
                .withBean(RoleMfaPolicyService.class, () -> mock(RoleMfaPolicyService.class))
                .withBean(MfaStepUpService.class, () -> mock(MfaStepUpService.class))
                .withBean(DomainRegistry.class, () -> new DomainRegistry("", ""))
                .withUserConfiguration(RoleMfaPolicyEnforcementFilter.class);
    }

    @Test
    void applicationYmlDefault_registersNoFilter() {
        runner().withInitializer(new ConfigDataApplicationContextInitializer())
                .run(ctx -> assertThat(ctx).doesNotHaveBean(RoleMfaPolicyEnforcementFilter.class));
    }

    @Test
    void theExistingCasdoorMfaFlag_alone_doesNotArmIt() {
        runner().withPropertyValues("app.casdoor.mfa.enabled=true")
                .run(ctx -> assertThat(ctx).doesNotHaveBean(RoleMfaPolicyEnforcementFilter.class));
    }

    @Test
    void explicitFalse_registersNoFilter() {
        runner().withPropertyValues(RoleMfaPolicyEnforcementFilter.FLAG + "=false")
                .run(ctx -> assertThat(ctx).doesNotHaveBean(RoleMfaPolicyEnforcementFilter.class));
    }

    @Test
    void explicitTrue_registersTheFilter() {
        runner().withPropertyValues(RoleMfaPolicyEnforcementFilter.FLAG + "=true")
                .run(ctx -> assertThat(ctx).hasSingleBean(RoleMfaPolicyEnforcementFilter.class));
    }
}
