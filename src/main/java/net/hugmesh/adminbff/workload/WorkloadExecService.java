package net.hugmesh.adminbff.workload;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import net.hugmesh.adminbff.device.RegistrySigner;
import net.hugmesh.adminbff.usage.UsageService;
import net.hugmesh.adminbff.workload.WorkloadDtos.ExecResult;
import net.hugmesh.commons.security.RoleName;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

/**
 * The DANGEROUS-tier exec broker (DECISION 1). Two variants:
 *
 * <ul>
 *   <li>{@link #execReadOnly} — a one-shot exec whose command's first token MUST be on the
 *       read-only allowlist ({@code app.workload-console.exec-read-only-commands}); a
 *       non-allowlisted command is refused;</li>
 *   <li>{@link #appendTranscript} — the tamper-evident, append-only SIGNED transcript a full
 *       interactive TTY session writes (the WS handler calls it per stdin/stdout chunk). Each
 *       entry is signed with {@link RegistrySigner} over the canonical
 *       {@code seq|session|ts|direction|hash(prev)} so a tampered/dropped entry is detectable;
 *       the signed line is written to the logging stack (via {@link UsageService} + the
 *       audit log).</li>
 * </ul>
 *
 * <p>EVERY exec (read-only or TTY) is audited BEFORE it runs ({@link #auditBeforeExec}); a
 * failed audit aborts. After a TTY session the WS handler force-reschedules the pod (the
 * detection-gap quarantine) via the {@link WorkloadClient}. Authorization (SA-only +
 * dangerous-tier + step-up + Lease + device/SSH-license + tailnet-only) is the central
 * predicate's + the step-up service's job — this service trusts it has run.
 */
@Service
public class WorkloadExecService {

    private static final Logger log = LoggerFactory.getLogger(WorkloadExecService.class);

    private final WorkloadClient client;
    private final WorkloadConsoleProperties props;
    private final RegistrySigner signer;
    private final UsageService usage;

    public WorkloadExecService(WorkloadClient client, WorkloadConsoleProperties props,
                               RegistrySigner signer, UsageService usage) {
        this.client = client;
        this.props = props;
        this.signer = signer;
        this.usage = usage;
    }

    /** Audit an exec attempt BEFORE it runs; a failed audit aborts the exec. */
    public Mono<Void> auditBeforeExec(String actor, String namespace, String pod, String container,
                                      List<String> command, boolean tty) {
        log.warn("[workload-exec] AUDIT actor={} ns={} pod={} container={} tty={} cmd={}",
                actor, namespace, pod, container, tty, command);
        return usage.record(actor, List.of(RoleName.ADMIN.value()),
                tty ? "workload.exec.tty" : "workload.exec.readonly");
    }

    /** One-shot read-only exec — the command head must be allowlisted. */
    public Mono<ExecResult> execReadOnly(String actor, String namespace, String pod,
                                         String container, List<String> command) {
        if (!props.execReadOnlyAllowed(command)) {
            return Mono.error(new ExecDeniedException(
                    "command is not on the read-only exec allowlist: " + command));
        }
        return auditBeforeExec(actor, namespace, pod, container, command, false)
                .then(client.execReadOnly(namespace, pod, container, command));
    }

    /** Open a full interactive TTY session (the WS handler bridges it to xterm.js). */
    public Mono<WorkloadClient.ExecSession> openTty(String actor, String namespace, String pod,
                                                    String container, List<String> command) {
        return auditBeforeExec(actor, namespace, pod, container, command, true)
                .then(client.openExec(namespace, pod, container, command));
    }

    /** Force a reschedule of the pod after a TTY session closes (detection-gap quarantine). */
    public Mono<Void> rescheduleAfter(String namespace, String pod) {
        log.warn("[workload-exec] QUARANTINE force-reschedule after exec ns={} pod={}", namespace, pod);
        return client.rescheduleAfterExec(namespace, pod);
    }

    // ── tamper-evident signed transcript ──────────────────────────────────────────

    /** A signed, append-only transcript chain for one TTY session. */
    public Transcript newTranscript(String sessionId, String actor) {
        return new Transcript(sessionId, actor);
    }

    /** A signed, append-only transcript. Each entry hashes the previous so a dropped/edited
     *  entry breaks the chain; each line is signed (Ed25519 detached) and emitted to the
     *  logging stack. */
    public final class Transcript {
        private final String sessionId;
        private final String actor;
        private final AtomicLong seq = new AtomicLong();
        private volatile String prevHash = "GENESIS";

        Transcript(String sessionId, String actor) {
            this.sessionId = sessionId;
            this.actor = actor;
        }

        /** Append one transcript entry (direction = "in"/"out"), returning the signed line. */
        public synchronized String append(String direction, byte[] data) {
            long n = seq.incrementAndGet();
            String dataHash = RegistrySigner.contentHash(data == null ? new byte[0] : data);
            String canonical = "v1\nseq=" + n + "\nsession=" + sessionId + "\nactor=" + actor
                    + "\nts=" + Instant.now() + "\ndir=" + direction
                    + "\nprev=" + prevHash + "\ndata=" + dataHash;
            byte[] bytes = canonical.getBytes(StandardCharsets.UTF_8);
            String sig = signer.sign(bytes);
            String entryHash = RegistrySigner.contentHash(bytes);
            this.prevHash = entryHash;
            String signed = canonical + "\nentry=" + entryHash + "\nsig=" + (sig == null ? "UNSIGNED" : sig);
            // emit to the logging stack (the append-only sink)
            log.info("[workload-exec-transcript] {}", signed.replace('\n', '|'));
            return signed;
        }
    }

    /** A refusal to exec (mapped to 403 by the controller). */
    public static class ExecDeniedException extends RuntimeException {
        public ExecDeniedException(String message) {
            super(message);
        }
    }
}
