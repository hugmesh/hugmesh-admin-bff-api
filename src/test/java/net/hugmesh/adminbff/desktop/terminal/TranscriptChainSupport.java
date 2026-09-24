package net.hugmesh.adminbff.desktop.terminal;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.slf4j.LoggerFactory;
import net.hugmesh.adminbff.device.RegistrySigner;
import net.hugmesh.adminbff.usage.UsageService;
import net.hugmesh.adminbff.workload.WorkloadClient;
import net.hugmesh.adminbff.workload.WorkloadConsoleProperties;
import net.hugmesh.adminbff.workload.WorkloadExecService;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.Mockito.mock;

/**
 * Test support for decision 104 (hugmesh-admin-bff-api#11): a REAL {@link WorkloadExecService}
 * signing with an ephemeral Ed25519 key, a capture of the transcript lines it emits to its log sink,
 * and a VERIFIER that re-walks the chain from those lines alone — the way a copy of the transcript
 * kept elsewhere would be checked.
 *
 * <p>There is no chain verifier in {@code src/main} (the workload console only writes the chain), so
 * this verifier is built from the production primitives it must agree with:
 * {@link RegistrySigner#contentHash} (the {@code data}/{@code entry}/{@code prev} hashes) and
 * {@link RegistrySigner#verify} (the Ed25519 signature over the canonical {@code v1} text).
 */
final class TranscriptChainSupport {

    /** The prefix {@link WorkloadExecService} writes every transcript line with. */
    static final String LINE_PREFIX = "[workload-exec-transcript] ";

    private TranscriptChainSupport() {
    }

    /** An ephemeral key and a signer built through the PUBLIC (production) constructor. */
    record Keys(RegistrySigner signer, String publicKeyBase64) {
    }

    static Keys ephemeralKeys() {
        KeyPair kp = RegistrySigner.ephemeral();
        String priv = Base64.getEncoder().encodeToString(kp.getPrivate().getEncoded());
        String pub = Base64.getEncoder().encodeToString(kp.getPublic().getEncoded());
        return new Keys(new RegistrySigner(priv, "", pub), pub);
    }

    /** The real service; its client/props/usage are not on the transcript path. */
    static WorkloadExecService realTranscripts(RegistrySigner signer) {
        return new WorkloadExecService(mock(WorkloadClient.class), mock(WorkloadConsoleProperties.class),
                signer, mock(UsageService.class));
    }

    /** Attach a thread-safe capture to {@link WorkloadExecService}'s logger (the transcript sink). */
    static ListAppender<ILoggingEvent> captureSink() {
        LoggerContext ctx = (LoggerContext) LoggerFactory.getILoggerFactory();
        ch.qos.logback.classic.Logger logger = ctx.getLogger(WorkloadExecService.class);
        logger.setLevel(Level.INFO);
        ListAppender<ILoggingEvent> app = new ListAppender<>();
        app.list = new java.util.concurrent.CopyOnWriteArrayList<>();
        app.start();
        logger.addAppender(app);
        return app;
    }

    static void release(ListAppender<ILoggingEvent> app) {
        LoggerContext ctx = (LoggerContext) LoggerFactory.getILoggerFactory();
        ctx.getLogger(WorkloadExecService.class).detachAppender(app);
        app.stop();
    }

    /** The captured transcript lines (sink form) whose session starts with {@code sessionPrefix}. */
    static List<String> linesFor(ListAppender<ILoggingEvent> app, String sessionPrefix) {
        List<String> out = new ArrayList<>();
        for (ILoggingEvent e : app.list) {
            String m = e.getFormattedMessage();
            if (m.startsWith(LINE_PREFIX) && m.contains("|session=" + sessionPrefix)) {
                out.add(m);
            }
        }
        return out;
    }

    /** One parsed entry: its fields and the exact canonical text that was hashed and signed. */
    record Entry(Map<String, String> fields, String canonical) {
        String get(String k) {
            return fields.get(k);
        }
    }

    static Entry parse(String sinkLine) {
        String body = sinkLine.substring(LINE_PREFIX.length());
        // The sink replaced every '\n' of the signed entry with '|'; undo it.
        String[] parts = body.split("\\|", -1);
        Map<String, String> fields = new LinkedHashMap<>();
        List<String> canonicalLines = new ArrayList<>();
        boolean inCanonical = true;
        for (String p : parts) {
            if (p.startsWith("entry=")) {
                inCanonical = false;
            }
            if (inCanonical) {
                canonicalLines.add(p);
            }
            int eq = p.indexOf('=');
            if (eq > 0) {
                fields.put(p.substring(0, eq), p.substring(eq + 1));
            } else {
                fields.put(p, "");
            }
        }
        return new Entry(fields, String.join("\n", canonicalLines));
    }

    /**
     * Verify a transcript chain from its sink lines alone. Returns {@code null} when it holds, else
     * the first reason it does not: version, sequence 1..n without gaps, one session, {@code prev}
     * linking to the previous entry's hash (from {@code GENESIS}), {@code entry} equal to the hash
     * of the canonical text, and a valid Ed25519 signature over that text.
     */
    static String verifyChain(List<String> sinkLines, String publicKeyBase64) {
        String prev = "GENESIS";
        String session = null;
        long expectSeq = 1;
        for (String line : sinkLines) {
            Entry e = parse(line);
            if (!e.canonical().startsWith("v1\n")) {
                return "entry " + expectSeq + " is not a v1 entry";
            }
            if (!Long.toString(expectSeq).equals(e.get("seq"))) {
                return "sequence gap: expected " + expectSeq + " got " + e.get("seq");
            }
            if (session == null) {
                session = e.get("session");
            } else if (!session.equals(e.get("session"))) {
                return "session changed mid-chain at seq " + expectSeq;
            }
            if (!prev.equals(e.get("prev"))) {
                return "prev hash does not link at seq " + expectSeq;
            }
            byte[] canonical = e.canonical().getBytes(StandardCharsets.UTF_8);
            String entryHash = RegistrySigner.contentHash(canonical);
            if (!entryHash.equals(e.get("entry"))) {
                return "entry hash mismatch at seq " + expectSeq;
            }
            if (!RegistrySigner.verify(canonical, e.get("sig"), publicKeyBase64)) {
                return "signature does not verify at seq " + expectSeq;
            }
            prev = entryHash;
            expectSeq++;
        }
        return null;
    }
}
