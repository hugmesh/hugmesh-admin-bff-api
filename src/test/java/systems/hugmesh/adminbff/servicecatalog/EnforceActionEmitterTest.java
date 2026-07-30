package systems.hugmesh.adminbff.servicecatalog;

import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The SHIPS-DARK enforce-action seam — proves it parses the opaque enforce_actions list and
 * returns the emitted count WITHOUT any real effect (no ArgoCD/Casdoor/cert client).
 */
class EnforceActionEmitterTest {

    private static ServiceDeployment withActions(String actions) {
        return new ServiceDeployment("d", "brandx", "owncast", null,
                ServiceDeployment.STATE_ENDED, Instant.now(), Instant.now(), actions,
                ServiceDeployment.PROP_PENDING, Instant.now(), "root");
    }

    @Test
    void emit_returnsActionCount_forCsv() {
        EnforceActionEmitter emitter = new EnforceActionEmitter();
        Integer count = emitter.emit(withActions("teardown,revoke-roles,revoke-certs,alert")).block();
        assertThat(count).isEqualTo(4);
    }

    @Test
    void emit_returnsZero_forBlankOrNull() {
        EnforceActionEmitter emitter = new EnforceActionEmitter();
        assertThat(emitter.emit(withActions(null)).block()).isEqualTo(0);
        assertThat(emitter.emit(withActions("  ")).block()).isEqualTo(0);
    }

    @Test
    void parse_tolerates_jsonArray_and_whitespace() {
        assertThat(EnforceActionEmitter.parse("[\"teardown\", \"alert\"]"))
                .containsExactly("teardown", "alert");
        assertThat(EnforceActionEmitter.parse("teardown   alert"))
                .containsExactly("teardown", "alert");
    }
}
