package net.hugmesh.adminbff.workload;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.reactive.socket.WebSocketHandler;
import org.springframework.web.reactive.socket.WebSocketMessage;
import org.springframework.web.reactive.socket.WebSocketSession;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.UUID;

/**
 * The FULL INTERACTIVE TTY exec WebSocket handler (DECISION 1 — exec -it parity, xterm.js on
 * the UI). Handshake path: {@code /bff/superadmin/workloads/exec-tty/{namespace}/{pod}}
 * (query {@code ?container=&command=}). The handshake is an HTTP GET that matches the
 * {@code /bff/superadmin/workloads/**} prefix, so it is gated by BOTH Spring Security's
 * {@code hasRole('SUPERADMIN')} AND the central {@link WorkloadAuthorizationFilter} (the path
 * contains {@code /exec} → DANGEROUS tier → STEP 0 dangerous-tier kill + step-up + Lease +
 * device/SSH-license + namespace allowlist), so an unauthorized upgrade is refused before this
 * handler ever runs.
 *
 * <h3>Protocol (xterm.js attach addon style)</h3>
 * Inbound text frames are JSON: {@code {"type":"stdin","data":"..."}} or
 * {@code {"type":"resize","cols":N,"rows":N}}. Outbound text frames carry the container's
 * stdout/stderr bytes (UTF-8). EVERY inbound/outbound chunk is appended to the tamper-evident
 * SIGNED transcript ({@link WorkloadExecService.Transcript}). When the session closes the pod
 * is force-rescheduled (detection-gap quarantine).
 */
public class WorkloadExecWebSocketHandler implements WebSocketHandler {

    private static final Logger log = LoggerFactory.getLogger(WorkloadExecWebSocketHandler.class);

    private final WorkloadExecService exec;
    private final ObjectMapper mapper;

    public WorkloadExecWebSocketHandler(WorkloadExecService exec, ObjectMapper mapper) {
        this.exec = exec;
        this.mapper = mapper;
    }

    @Override
    public Mono<Void> handle(WebSocketSession session) {
        String path = session.getHandshakeInfo().getUri().getPath();
        String[] parts = path.split("/exec-tty/", 2);
        if (parts.length < 2) {
            return session.close();
        }
        String[] seg = parts[1].split("/");
        if (seg.length < 2) {
            return session.close();
        }
        String namespace = decode(seg[0]);
        String pod = decode(seg[1]);
        var query = parseQuery(session.getHandshakeInfo().getUri().getQuery());
        String container = query.get("container");
        List<String> command = query.containsKey("command")
                ? List.of(query.get("command").split(","))
                : List.of("/bin/sh");
        String actor = session.getHandshakeInfo().getPrincipal()
                .map(java.security.Principal::getName).block();
        if (actor == null) actor = "superadmin";
        String sessionId = UUID.randomUUID().toString();
        WorkloadExecService.Transcript transcript = exec.newTranscript(sessionId, actor);

        return exec.openTty(actor, namespace, pod, container, command)
                // Wire the exec session to WS outbound + inbound and run both sides until close.
                .flatMap(execSession -> runExecSession(execSession, session, transcript))
                // detection-gap quarantine: force-reschedule the pod after the session
                .then(exec.rescheduleAfter(namespace, pod))
                .onErrorResume(e -> {
                    log.warn("[workload-exec-ws] session error ns={} pod={}: {}", namespace, pod, e.toString());
                    return session.close();
                });
    }

    /** Pipe the exec session to the WS session: outbound frames + inbound stdin/resize, then await. */
    private Mono<Void> runExecSession(WorkloadClient.ExecSession execSession,
                                       WebSocketSession session,
                                       WorkloadExecService.Transcript transcript) {
        // outbound: container stdout/stderr → WS text frames (transcript "out")
        Flux<WebSocketMessage> out = execSession.output()
                .doOnNext(bytes -> transcript.append("out", bytes))
                .map(bytes -> session.textMessage(new String(bytes, StandardCharsets.UTF_8)));
        // inbound: WS frames → stdin / resize (transcript "in")
        Mono<Void> in = session.receive()
                .doOnNext(msg -> handleInbound(msg, execSession, transcript))
                .doFinally(sig -> execSession.close()).then();
        return Mono.zip(session.send(out), in).then();
    }

    private void handleInbound(WebSocketMessage msg, WorkloadClient.ExecSession execSession,
                               WorkloadExecService.Transcript transcript) {
        try {
            String text = msg.getPayloadAsText();
            JsonNode node = mapper.readTree(text);
            String type = node.path("type").asText("stdin");
            if ("resize".equals(type)) {
                execSession.resize(node.path("cols").asInt(80), node.path("rows").asInt(24));
            } else {
                byte[] data = node.path("data").asText("").getBytes(StandardCharsets.UTF_8);
                transcript.append("in", data);
                execSession.writeStdin(data);
            }
        } catch (Exception e) {
            log.debug("[workload-exec-ws] bad inbound frame: {}", e.toString());
        }
    }

    private static java.util.Map<String, String> parseQuery(String q) {
        java.util.Map<String, String> out = new java.util.LinkedHashMap<>();
        if (q == null || q.isBlank()) return out;
        for (String pair : q.split("&")) {
            int i = pair.indexOf('=');
            if (i > 0) {
                out.put(decode(pair.substring(0, i)), decode(pair.substring(i + 1)));
            }
        }
        return out;
    }

    private static String decode(String s) {
        try {
            return java.net.URLDecoder.decode(s, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return s;
        }
    }
}
