package net.hugmesh.adminbff.web.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;

import java.util.List;

/**
 * Body for {@code POST /bff/internal/aio-triage/ingest} — one collected signal batch from the
 * in-cluster node/DaemonSet collector tailing Snort/Suricata + AIDE + k8s events, the caller
 * half the edge-AI AIOps feature shipped without (see
 * {@code net.hugmesh.adminbff.inference.AioTriageIngestController}).
 *
 * <p>camelCase on the wire (the {@code ImageBuildIngestRequest} shape, not the snake_case
 * {@code PhoneIngestRequest} one — the collector is a first-party in-cluster agent, not the jq
 * emitter in {@code phone-wizard.sh}). Unknown keys are ignored explicitly (the
 * external-producer convention) so an additive collector field never breaks ingest.
 *
 * <p><b>NO AUTHORIZING FIELD.</b> The batch carries the tenant and the admin recipient subjects
 * the collector resolved, plus the raw signal text — nothing that grants anything. Tenancy is
 * the caller's concern at this internal hop (no untrusted principal reaches it); the bounds
 * below only keep a malformed or runaway batch from reaching the service and the model.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record AioTriageIngestRequest(

        /* The tenant the alert is emitted for. Bounded by the outbox tenant column
         * (notification_outbox.domain is varchar(64)). */
        @NotBlank(message = "domain is required")
        @Size(max = 64, message = "domain is too long")
        String domain,

        /* The admin/superadmin Casdoor subjects to alert. The service never widens the
         * audience beyond this list, so an EMPTY list is a clean 400 rather than a silent
         * no-op; each subject is bounded by the Casdoor-subject band the other admin
         * surfaces use (varchar(400) column, 255 on the wire like the notification
         * trigger's recipientSubject). */
        @NotEmpty(message = "at least one admin recipient is required")
        @Size(max = 100, message = "too many admin recipients")
        List<@NotBlank(message = "admin recipient must not be blank")
             @Size(max = 255, message = "admin recipient is too long") String> adminSubjects,

        /* Stable key for THIS batch — a retried batch re-derives the same per-admin outbox
         * natural key, so it never double-alerts. */
        @NotBlank(message = "eventKey is required")
        @Size(max = 200, message = "eventKey is too long")
        String eventKey,

        /* The raw NIDS / file-integrity / k8s signal text handed to the model. Capped so a
         * runaway collector cannot post an unbounded prompt to the edge-AI node. */
        @NotBlank(message = "signals is required")
        @Size(max = 16384, message = "signals is too long")
        String signals) {
}
