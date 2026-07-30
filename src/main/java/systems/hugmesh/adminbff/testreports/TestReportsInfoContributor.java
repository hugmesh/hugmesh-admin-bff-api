package systems.hugmesh.adminbff.testreports;

import org.springframework.boot.actuate.info.Info;
import org.springframework.boot.actuate.info.InfoContributor;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * Publishes the test-reports launch seam's REALNESS as a boot-time
 * {@code /actuator/info} signal — the runtime evidence the design's prod-hygiene
 * gate (PART B4) requires: "a manifest scan can't see a Java stub body ... each seam
 * emits a startup self-report". A {@code testReports.launchReal=false} here means the
 * BFF is still on the {@link NoopJobLauncher} (the trigger would not actually start a
 * Job), so a deployment that advertises the Test-Reports run trigger as live while
 * this reads {@code false} (and carries no explicit {@code stub-seam-ok} annotation)
 * fails the gate.
 *
 * <p>Exposed under {@code /actuator/info} (permitAll, like the health probe) so the
 * gate / an operator can read it without a token; it leaks nothing sensitive — only
 * whether the launcher is wired to a cluster.
 */
@Component
public class TestReportsInfoContributor implements InfoContributor {

    private final JobLauncher launcher;

    public TestReportsInfoContributor(JobLauncher launcher) {
        this.launcher = launcher;
    }

    @Override
    public void contribute(Info.Builder builder) {
        builder.withDetail("testReports", Map.of(
                "launchReal", launcher.isReal(),
                "seam", "test-runner-launch"));
    }
}
