package net.hugmesh.adminbff.support;

import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.desktop.DesktopInstallRequestR2dbcRepository;
import net.hugmesh.adminbff.desktop.DesktopSudoGrantR2dbcRepository;
import net.hugmesh.adminbff.device.DeviceRowRepository;
import net.hugmesh.adminbff.device.SshLicenseRowRepository;
import net.hugmesh.adminbff.radio.RadioDeviceR2dbcRepository;
import net.hugmesh.adminbff.storage.StoragePoolR2dbcRepository;

import java.util.List;

/**
 * FK-safe truncation of {@code device_registry} for test fixtures, over the Spring Data
 * reactive repositories — no raw SQL, and the chain stays a {@link Mono} the caller composes.
 *
 * <p><b>Why this exists.</b> Seventeen test classes clear {@code device_registry} in
 * {@code @BeforeEach}, and most listed only the tables they personally cared about. But the
 * table has seven FK children, and five of them are {@code NO ACTION} — so the delete only
 * succeeds while every one of those five happens to be empty. Three classes
 * ({@code DesktopSudoGrant{Service,Repository}Test}, {@code DesktopRemoteInstallServiceTest})
 * clear {@code desktop_sudo_grant} in {@code @BeforeEach} and never after, so their rows
 * outlive them; the next class to clear {@code device_registry} without clearing that child
 * first died on {@code fk_desktop_sudo_grant_device}. A full-suite run was <b>38 errors</b>,
 * while every one of those classes passed when run alone — the pollution needs an earlier
 * class in the same JVM to exist at all.
 *
 * <p>The fix is not "add one more DELETE". It is that a fixture clearing a parent must clear
 * <em>every blocking child</em>, and that list grows with each migration — so it is written
 * down once, here, and {@link DeviceRegistryCleanupCoverageTest} asserts against the live
 * schema that it is still complete.
 */
public class DeviceRegistryCleanup {

    /**
     * Children of {@code device_registry} whose FK is {@code NO ACTION}, i.e. the ones that
     * block the parent delete — the table names, purely so the coverage test can compare this
     * class against the live schema. The deletes themselves go through the repositories below.
     *
     * <p>{@code device_ssh_dial} and {@code admin_ssh_issued_key} are deliberately ABSENT:
     * their FKs are {@code ON DELETE CASCADE}, so the database clears them itself. Adding them
     * here would work, but would hide which children actually constrain the delete.
     */
    public static final List<String> BLOCKING_CHILDREN = List.of(
            "desktop_sudo_grant",
            "desktop_install_request",
            "device_ssh_license",
            "node_storage_pool",
            "node_radio_device");

    private final DesktopSudoGrantR2dbcRepository sudoGrants;
    private final DesktopInstallRequestR2dbcRepository installRequests;
    private final SshLicenseRowRepository sshLicenses;
    private final StoragePoolR2dbcRepository storagePools;
    private final RadioDeviceR2dbcRepository radioDevices;
    private final DeviceRowRepository devices;

    public DeviceRegistryCleanup(DesktopSudoGrantR2dbcRepository sudoGrants,
                                 DesktopInstallRequestR2dbcRepository installRequests,
                                 SshLicenseRowRepository sshLicenses,
                                 StoragePoolR2dbcRepository storagePools,
                                 RadioDeviceR2dbcRepository radioDevices,
                                 DeviceRowRepository devices) {
        this.sudoGrants = sudoGrants;
        this.installRequests = installRequests;
        this.sshLicenses = sshLicenses;
        this.storagePools = storagePools;
        this.radioDevices = radioDevices;
        this.devices = devices;
    }

    /**
     * Clears every blocking child, then {@code device_registry} itself. {@code then()} keeps
     * the order the foreign keys require — the parent delete is only subscribed once every
     * child delete has completed. Safe to call from a fixture that has already emptied some of
     * these tables: a second {@code deleteAll()} removes nothing.
     */
    public Mono<Void> clearDeviceRegistry() {
        return sudoGrants.deleteAll()
                .then(installRequests.deleteAll())
                .then(sshLicenses.deleteAll())
                .then(storagePools.deleteAll())
                .then(radioDevices.deleteAll())
                .then(devices.deleteAll());
    }
}
