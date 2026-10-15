package net.hugmesh.adminbff.desktop.terminal;

import org.junit.jupiter.api.Test;
import net.hugmesh.adminbff.sshterminal.DeviceSshDial;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Decision 73d = A (hugmesh-admin-bff-api#53): with no {@code DEVICE_TERMINAL_DIAL_KEY_FILE} the
 * dial reads {@code <key-mount-path>/<k8s_secret_name>/dial_private_key} — the key name every
 * producer writes (the generator's device-ssh-&lt;deviceId&gt; ExternalSecret, the build Job's
 * mount). RED on origin/main 86cdf79: both defaults are {@code id_dial}.
 */
class DeviceTerminalDialKeyFileDefaultTest {

    @Test
    void boundDefault_resolvesDialPrivateKey_inTheDevicesOwnSecretDir() throws Exception {
        DeviceTerminalDialProperties props = new DeviceTerminalDialProperties();   // nothing set
        assertThat(props.getKeyFile()).isEqualTo("dial_private_key");
        assertThat(SshjDeviceSshChannelFactory.keyFileRefusal(props)).isNull();

        DeviceSshDial dial = new DeviceSshDial("d1", "dev-3f2a9b1c4d5e", "bff-dial",
                "ssh-ed25519 AAAA", "SHA256:hostfp", "SHA256:dialfp",
                "hugmesh/device/dev-3f2a9b1c4d5e/ssh", "device-ssh-dev-3f2a9b1c4d5e", null,
                DeviceSshDial.STATUS_ACTIVE, 1L, null, null);
        assertThat(SshjDeviceSshChannelFactory.resolveDialKeyPath(props, dial)).isEqualTo(Path.of(
                "/var/run/secrets/device-ssh-dial/device-ssh-dev-3f2a9b1c4d5e/dial_private_key"));
    }

    /** The shipped application.yml default must agree (the context runner never loads it). */
    @Test
    void applicationYml_keyFileDefault_isDialPrivateKey() throws Exception {
        String yml;
        try (InputStream in = getClass().getResourceAsStream("/application.yml")) {
            assertThat(in).as("application.yml on the test classpath").isNotNull();
            yml = new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
        Matcher m = Pattern.compile("(?m)^\\s*key-file:\\s*\"\\$\\{DEVICE_TERMINAL_DIAL_KEY_FILE:([^}]*)}\"")
                .matcher(yml);
        assertThat(m.find()).as("key-file line with a DEVICE_TERMINAL_DIAL_KEY_FILE default").isTrue();
        assertThat(m.group(1)).isEqualTo("dial_private_key");
        assertThat(m.find()).as("exactly one such line").isFalse();
    }
}
