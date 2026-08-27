package net.hugmesh.adminbff.optionalservices;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The SHIPPED DEFAULT client's contract. {@code app.optional-services.reconcile.enabled}
 * defaults to {@code false}, so {@link NoopOptionalServiceClient} is the bean in every dev / CI
 * run and in the as-merged cluster state — which makes its behaviour the behaviour a superadmin
 * actually meets today.
 *
 * <p>The reads/status writes no-op quietly, as the reconcile contract requires. The SPEC write
 * must NOT: a {@code setEnabled} that returned success without a cluster would make
 * {@code PUT /bff/superadmin/optional-services/{slug}} answer 200 for a toggle that reached
 * nothing — the same silently-inert shape as the {@code character-forge} registry gap, just one
 * layer up. The controller's dark test mocks the client, so without THIS test nothing would
 * catch that regression in the default implementation.
 */
class NoopOptionalServiceClientTest {

    private final NoopOptionalServiceClient client = new NoopOptionalServiceClient();

    @Test
    void readsAndStatusWrites_noOpQuietly_soTheReconcileTickIsInert() {
        assertThat(client.listDesired()).isEmpty();
        assertThat(client.updateStatus(
                new OptionalServiceCr("akkoma", "devops", "akkoma", true, null, null, 1L, "1"),
                new OptionalServiceStatus(1L, false, OptionalServiceStatus.PHASE_DISABLED,
                        "optional-akkoma", null, null))).isTrue();
        assertThat(client.isReal()).isFalse();
    }

    @Test
    void specWrite_REFUSES_ratherThanReportingASuccessItCannotDeliver() {
        assertThatThrownBy(() -> client.setEnabled("akkoma", true, "because", "superadmin-1"))
                .isInstanceOf(OptionalServiceWriteException.class)
                .satisfies(e -> assertThat(((OptionalServiceWriteException) e).kind())
                        .isEqualTo(OptionalServiceWriteException.Kind.NOT_WIRED))
                .hasMessageContaining("app.optional-services.reconcile.enabled=false")
                .hasMessageContaining("nothing was written");
    }
}
