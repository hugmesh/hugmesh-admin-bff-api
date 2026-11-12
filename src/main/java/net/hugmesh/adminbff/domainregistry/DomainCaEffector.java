package net.hugmesh.adminbff.domainregistry;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * The per-domain CA effector (hugmesh-admin-bff-api#99). Operator decisions, 2026-09-23:
 * <ul>
 *   <li><b>87a = B</b> — the admin-bff creates the CA in Vault's PKI engine and records it on
 *       the {@code domain_registry} row (instead of the node agent's report-back path);</li>
 *   <li><b>87b = A</b> — {@code ca_ref = "generate"} means a NEW self-signed root per domain,
 *       so each domain gets its own PKI mount ({@code <mount-prefix><slug>});</li>
 *   <li><b>87d = B</b> — domain setup is NOT gated on the CA: a failure leaves
 *       {@code ca_provisioned = false} (the flag the console already shows), logs a WARN naming
 *       the domain and the failing Vault step, and is retried on the next pass.</li>
 * </ul>
 *
 * <p>Work list: rows with {@code ca_ref = 'generate'} and {@code ca_provisioned = false}.
 * Success writes the mount path into {@code ca_ref} and sets {@code ca_provisioned = true} in
 * one compare-and-set UPDATE. Every other row — already provisioned, or with a {@code ca_ref}
 * naming an existing CA — is a no-op. With {@code app.domain-registry.ca.enabled=false} (the
 * default) every call answers {@link Status#DISABLED} without touching Vault or the database.
 *
 * <p>Out of scope here and still manual: live issuance against a real Vault, and distributing
 * the new root into the per-brand and wide trust stores (87b's domain-add hook).
 */
@SuppressFBWarnings(value = "EI_EXPOSE_REP2",
        justification = "Spring constructor injection (DomainCaConfig's @Bean): the container owns these singleton collaborators and this class never mutates them after construction; a defensive copy of a bean is meaningless (not caller-owned mutable data).")
public class DomainCaEffector {

    private static final Logger log = LoggerFactory.getLogger(DomainCaEffector.class);

    /** The {@code ca_ref} value that asks for a newly generated per-domain root. */
    public static final String GENERATE = "generate";

    /** How one domain came out of a pass. */
    public enum Status { DISABLED, SKIPPED, PROVISIONED, FAILED }

    /**
     * One domain's result. {@code caRef} is the recorded PKI path on {@link Status#PROVISIONED};
     * {@code detail} is a human-readable reason (no secrets, no response bodies).
     */
    public record CaOutcome(String clusterDomain, Status status, @Nullable String caRef, String detail) { }

    private final DomainRegistryRepository repo;
    @Nullable
    private final VaultPkiClient vault;
    private final DomainCaProperties props;

    public DomainCaEffector(DomainRegistryRepository repo, @Nullable VaultPkiClient vault,
                            DomainCaProperties props) {
        this.repo = repo;
        this.vault = vault;
        this.props = props;
    }

    private boolean active() {
        return props.isEnabled() && vault != null;
    }

    /**
     * One pass over every pending {@code generate} row, sequentially. Disabled: completes
     * empty without even reading the table.
     */
    public Flux<CaOutcome> provisionPending() {
        if (!active()) {
            return Flux.empty();
        }
        return repo.findCaPendingGenerate().concatMap(this::provision);
    }

    /** Provision {@code d}'s CA if (and only if) it is a pending {@code generate} row. */
    public Mono<CaOutcome> provision(DomainRegistration d) {
        if (!active()) {
            return Mono.just(new CaOutcome(d.clusterDomain(), Status.DISABLED, d.caRef(),
                    "app.domain-registry.ca.enabled=false"));
        }
        if (d.caProvisioned()) {
            return Mono.just(new CaOutcome(d.clusterDomain(), Status.SKIPPED, d.caRef(),
                    "already provisioned"));
        }
        if (!GENERATE.equals(d.caRef())) {
            return Mono.just(new CaOutcome(d.clusterDomain(), Status.SKIPPED, d.caRef(),
                    "ca_ref is not '" + GENERATE + "'"));
        }
        String mount = mountPathFor(d);
        if (!VaultPkiClient.isValidMountPath(mount)) {
            return Mono.just(failed(d, "cannot derive a Vault PKI mount path from slug '"
                    + d.nsPrefix() + "'"));
        }
        VaultPkiClient client = vault;
        return client.ensureRoot(mount, commonNameFor(d))
                // Deferred: the row is written only AFTER Vault holds the root, never assembled
                // (and so never timestamped or invoked) on a path where Vault failed.
                .then(Mono.defer(() -> repo.markCaProvisioned(d.id(), mount)))
                .map(updated -> recorded(d, mount, updated))
                .onErrorResume(e -> Mono.just(failed(d, describe(e))));
    }

    /** The outcome once Vault holds the root: {@code updated} is the compare-and-set result. */
    private CaOutcome recorded(DomainRegistration d, String mount, boolean updated) {
        if (updated) {
            log.info("[domain-ca] {}: per-domain root ready at Vault PKI mount '{}', ca_provisioned=true",
                    d.clusterDomain(), mount);
            return new CaOutcome(d.clusterDomain(), Status.PROVISIONED, mount, "root ready");
        }
        log.warn("[domain-ca] {}: root ready at '{}' but the row changed underneath "
                + "(ca_ref re-pointed or already provisioned) — not overwritten",
                d.clusterDomain(), mount);
        return new CaOutcome(d.clusterDomain(), Status.SKIPPED, d.caRef(),
                "row changed while provisioning; left as is");
    }

    private CaOutcome failed(DomainRegistration d, String reason) {
        log.warn("[domain-ca] {}: per-domain CA NOT provisioned, ca_provisioned stays false "
                + "(setup is not gated, retried next pass): {}", d.clusterDomain(), reason);
        return new CaOutcome(d.clusterDomain(), Status.FAILED, d.caRef(), reason);
    }

    /** {@code <mount-prefix><slug>} — the slug is immutable, so the mount never moves. */
    String mountPathFor(DomainRegistration d) {
        String slug = d.nsPrefix() == null ? "" : d.nsPrefix().trim();
        if (!DomainSlug.isValid(slug)) {
            return "";
        }
        String prefix = props.getMountPrefix() == null ? "" : props.getMountPrefix().trim();
        return prefix + slug;
    }

    private static String commonNameFor(DomainRegistration d) {
        return d.clusterDomain() + " Root CA";
    }

    /** A failure reason safe to log: the Vault step + status, or the exception type + message. */
    private static String describe(Throwable e) {
        if (e instanceof VaultPkiClient.VaultPkiException v) {
            return v.getMessage();
        }
        String msg = e.getMessage();
        if (msg != null && msg.length() > 200) {
            msg = msg.substring(0, 200) + "...";
        }
        return e.getClass().getSimpleName() + (msg == null ? "" : ": " + msg);
    }
}
