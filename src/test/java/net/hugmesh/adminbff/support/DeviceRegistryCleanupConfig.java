package net.hugmesh.adminbff.support;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import net.hugmesh.adminbff.desktop.DesktopInstallRequestR2dbcRepository;
import net.hugmesh.adminbff.desktop.DesktopSudoGrantR2dbcRepository;
import net.hugmesh.adminbff.device.DeviceRowRepository;
import net.hugmesh.adminbff.device.SshLicenseRowRepository;
import net.hugmesh.adminbff.radio.RadioDeviceR2dbcRepository;
import net.hugmesh.adminbff.storage.StoragePoolR2dbcRepository;

/**
 * Supplies {@link DeviceRegistryCleanup} to the fixtures that clear {@code device_registry}.
 *
 * <p><b>Why this is separate from {@link TestDatabaseConfig}.</b> The cleanup needs six Spring
 * Data reactive repositories. {@code TestDatabaseConfig} is imported by {@code @WebFluxTest}
 * slices too ({@code AuthControllerTest}, {@code AdminControllerAllowlistTest} and friends),
 * and a WebFlux slice has no R2DBC repositories at all — putting the bean there made those
 * four classes fail to load their context with "No qualifying bean", 34 errors that had
 * nothing to do with what they test.
 *
 * <p>Keeping it in its own {@code @TestConfiguration} means only the {@code @DataR2dbcTest}
 * fixtures that actually clear the table pull the repositories in, and a web slice cannot
 * accidentally acquire a database dependency it has no business having.
 */
@TestConfiguration(proxyBeanMethods = false)
public class DeviceRegistryCleanupConfig {

    @Bean
    public DeviceRegistryCleanup deviceRegistryCleanup(
            DesktopSudoGrantR2dbcRepository sudoGrants,
            DesktopInstallRequestR2dbcRepository installRequests,
            SshLicenseRowRepository sshLicenses,
            StoragePoolR2dbcRepository storagePools,
            RadioDeviceR2dbcRepository radioDevices,
            DeviceRowRepository devices) {
        return new DeviceRegistryCleanup(sudoGrants, installRequests, sshLicenses,
                storagePools, radioDevices, devices);
    }
}
