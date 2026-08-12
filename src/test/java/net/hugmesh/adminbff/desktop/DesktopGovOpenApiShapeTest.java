package net.hugmesh.adminbff.desktop;

import io.swagger.v3.oas.annotations.media.Schema;
import org.junit.jupiter.api.Test;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import net.hugmesh.adminbff.sshterminal.DesktopDialAdminController;
import net.hugmesh.adminbff.web.dto.DesktopSshSessionDescriptor;
import net.hugmesh.adminbff.web.dto.DesktopTerminalStepUpResponse;
import net.hugmesh.adminbff.web.dto.DeviceSshDialResponse;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * BFF-OPENAPI spec-shape smoke (lightweight, no full-context boot — mirrors the
 * {@code DesktopShipsDarkTest} structural style): the new desktop-gov controllers are mounted at the
 * documented paths and the new response DTOs are {@code record}s carrying springdoc {@code @Schema}
 * metadata, so {@code /v3/api-docs} reflects them as the typed contract of record (a future
 * ng-openapi-gen adoption stays unblocked; it is NOT adopted now). This asserts the SURFACE the spec
 * is generated from rather than booting springdoc, keeping it fast + offline-deterministic.
 */
class DesktopGovOpenApiShapeTest {

    @Test
    void stepUpControllerMountedAtDocumentedPath() {
        RequestMapping rm = DesktopStepUpController.class.getAnnotation(RequestMapping.class);
        assertThat(rm).isNotNull();
        assertThat(rm.value()).containsExactly("/bff/admin/desktop/step-up");
    }

    @Test
    void descriptorControllerMountedAtDocumentedPath() {
        RequestMapping rm = DesktopSshTerminalController.class.getAnnotation(RequestMapping.class);
        assertThat(rm).isNotNull();
        assertThat(rm.value()).containsExactly("/bff/admin/desktop/ssh-terminal");
    }

    @Test
    void dialAdminControllerMountedAtSuperadminPath_withActivateAndRevoke() throws NoSuchMethodException {
        RequestMapping rm = DesktopDialAdminController.class.getAnnotation(RequestMapping.class);
        assertThat(rm).isNotNull();
        assertThat(rm.value()).containsExactly("/bff/superadmin/desktop/dials");
        // the two trust-state mutations exist and are POSTs at the documented sub-paths. Each
        // now also carries the A5 unified step-up's session-cookie + Authorization-header params
        // (parity with the other 4 step-up gates' mfaFresh leg).
        PostMapping activate = DesktopDialAdminController.class
                .getMethod("activate", String.class, String.class, String.class, String.class,
                        org.springframework.security.core.Authentication.class)
                .getAnnotation(PostMapping.class);
        assertThat(activate.value()).containsExactly("/{deviceId}/activate");
        PostMapping revoke = DesktopDialAdminController.class
                .getMethod("revoke", String.class, String.class, String.class, String.class,
                        org.springframework.security.core.Authentication.class)
                .getAnnotation(PostMapping.class);
        assertThat(revoke.value()).containsExactly("/{deviceId}/revoke");
    }

    @Test
    void newDtosAreRecords_withSchemaMetadata() {
        assertThat(DesktopTerminalStepUpResponse.class.isRecord()).isTrue();
        assertThat(DesktopSshSessionDescriptor.class.isRecord()).isTrue();
        assertThat(DeviceSshDialResponse.class.isRecord()).isTrue();

        assertThat(DesktopTerminalStepUpResponse.class.getAnnotation(Schema.class)).isNotNull();
        assertThat(DesktopSshSessionDescriptor.class.getAnnotation(Schema.class)).isNotNull();
        assertThat(DeviceSshDialResponse.class.getAnnotation(Schema.class)).isNotNull();
    }

    @Test
    void dialResponseProjectsOnlyNonSecretFields_neverPrivateKeyBytes() {
        // the DTO must NOT carry any private-key component (only refs/pins/status). Component names
        // are the non-secret projection; assert no 'private'/'secretBytes'-style accessor exists.
        var components = java.util.Arrays.stream(DeviceSshDialResponse.class.getRecordComponents())
                .map(java.lang.reflect.RecordComponent::getName).toList();
        assertThat(components).containsExactlyInAnyOrder(
                "deviceId", "dialUser", "hostKeyFp", "dialPubFp", "vaultRef", "k8sSecretName",
                "status", "generation");
        assertThat(components).noneMatch(n -> n.toLowerCase().contains("privatekey"));
    }
}
