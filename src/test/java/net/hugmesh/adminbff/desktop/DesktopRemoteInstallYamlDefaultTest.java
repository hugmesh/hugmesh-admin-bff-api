package net.hugmesh.adminbff.desktop;

import net.hugmesh.adminbff.desktop.terminal.DeviceSshChannelFactory;
import net.hugmesh.adminbff.desktop.terminal.UnconfiguredDeviceSshChannelFactory;
import org.junit.jupiter.api.Test;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.core.env.PropertySource;
import org.springframework.core.io.ClassPathResource;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@code app.desktop.remote-install.enabled} must be a VISIBLE, overridable entry in the shipped
 * {@code application.yml}, defaulting to false.
 *
 * <p>Before this entry the key existed only as a {@code @ConditionalOnProperty(matchIfMissing = true)}
 * bean condition, so a deployment manifest had no name to override and a reader of the yaml could not
 * tell the lever existed. {@link DesktopClientWiringTest} cannot see that: its context runner never
 * loads {@code application.yml}. This test loads the REAL file, so deleting the entry, renaming its
 * placeholder, or flipping its default turns it red, and it proves the documented env name
 * ({@code DESKTOP_REMOTE_INSTALL_ENABLED}) really flips the bean.
 */
class DesktopRemoteInstallYamlDefaultTest {

    private static PropertySource<?> shippedYaml() throws Exception {
        List<PropertySource<?>> sources = new YamlPropertySourceLoader()
                .load("shipped-application-yml", new ClassPathResource("application.yml"));
        assertThat(sources).as("application.yml on the test classpath").isNotEmpty();
        return sources.get(0);
    }

    private ApplicationContextRunner shipped() throws Exception {
        PropertySource<?> yml = shippedYaml();
        return new ApplicationContextRunner()
                .withInitializer(ctx -> ctx.getEnvironment().getPropertySources().addLast(yml))
                .withUserConfiguration(DesktopRemoteInstallConfig.class)
                .withBean(DeviceSshChannelFactory.class, UnconfiguredDeviceSshChannelFactory::new);
    }

    @Test
    void entryIsDeclared_withTheEnvPlaceholder_andDefaultFalse() throws Exception {
        PropertySource<?> yml = shippedYaml();
        assertThat(yml.getProperty("app.desktop.remote-install.enabled"))
                .as("the explicit app.desktop.remote-install.enabled entry")
                .isEqualTo("${DESKTOP_REMOTE_INSTALL_ENABLED:false}");
        assertThat(yml.getProperty("app.desktop.remote-install.command"))
                .isEqualTo("${DESKTOP_REMOTE_INSTALL_COMMAND:flatpak install -y {ref}}");
    }

    /**
     * The other two governance flags, pinned to the exact env names the generator's cluster manifest
     * and compose stack set (hugmesh-generator tests/desktop-governance/test-governance-flags-visible.sh
     * pins that end). A renamed placeholder here would leave those overrides silently inert.
     */
    @Test
    void theTwoDeviceTerminalFlags_keepTheirEnvNames_andDefaultFalse() throws Exception {
        PropertySource<?> yml = shippedYaml();
        assertThat(yml.getProperty("app.device-terminal.enabled"))
                .isEqualTo("${DEVICE_TERMINAL_ENABLED:false}");
        assertThat(yml.getProperty("app.device-terminal.dial.enabled"))
                .isEqualTo("${DEVICE_TERMINAL_DIAL_ENABLED:false}");
    }

    @Test
    void withTheShippedYaml_andNoOverride_theNoopIsWired() throws Exception {
        shipped().run(ctx -> {
            assertThat(ctx.getEnvironment().getProperty("app.desktop.remote-install.enabled"))
                    .isEqualTo("false");
            assertThat(ctx.getEnvironment().getProperty("app.desktop.remote-install.command"))
                    .isEqualTo("flatpak install -y {ref}");
            assertThat(ctx.getBean(DesktopSshClient.class)).isInstanceOf(NoopDesktopSshClient.class);
            assertThat(ctx.getBean(DesktopSshClient.class).isReal()).isFalse();
        });
    }

    @Test
    void theDocumentedEnvName_flipsTheBean() throws Exception {
        shipped().withPropertyValues("DESKTOP_REMOTE_INSTALL_ENABLED=true").run(ctx -> {
            assertThat(ctx.getEnvironment().getProperty("app.desktop.remote-install.enabled"))
                    .isEqualTo("true");
            assertThat(ctx.getBean(DesktopSshClient.class)).isInstanceOf(RestDesktopSshClient.class);
        });
    }

    @Test
    void flagOn_withTheDialSeamUnconfigured_stillCannotDial() throws Exception {
        // The flag adds no second trust path: with the dial seam off the channel factory refuses.
        shipped().withPropertyValues("DESKTOP_REMOTE_INSTALL_ENABLED=true").run(ctx ->
                assertThat(ctx.getBean(DeviceSshChannelFactory.class).canDial()).isFalse());
    }
}
