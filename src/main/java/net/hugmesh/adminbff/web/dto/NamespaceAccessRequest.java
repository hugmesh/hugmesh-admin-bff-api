package net.hugmesh.adminbff.web.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Body for {@code POST/DELETE /bff/admin/namespace-access}. {@code user} +
 * {@code namespace} are both required (a clean 400 if blank). The namespace
 * MEMBERSHIP check (it must be one of {@code AccountStore.NAMESPACES}) and the
 * reserved-username gate stay in the controller — they return the specific error
 * messages the admin-ui + tests expect, and the namespace membership is mirrored by
 * the DB {@code ck_namespace_grant_namespace} CHECK (changeset 007).
 */
public record NamespaceAccessRequest(
        @NotBlank(message = "user is required")
        @Size(max = 400, message = "user is too long")
        String user,

        @NotBlank(message = "namespace is required")
        @Size(max = 128, message = "namespace is too long")
        String namespace) {
}
