package net.hugmesh.adminbff.web.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Body for the SUPERADMIN App-Store curation endpoints
 * ({@code POST /bff/superadmin/service-store/{domain}/offer} and
 * {@code .../withdraw}) — the {@code service_key} to offer/withdraw FOR a {@code domain}.
 *
 * <p>NOTE: the {@code domain} is taken from the PATH (the superadmin's explicit target),
 * NEVER from this body — a brand admin never sets a domain here at all (they only have a
 * read surface). The {@code @NotBlank}/{@code @Size} guards make a malformed request a
 * clean 400 via
 * {@link net.hugmesh.adminbff.web.ValidationExceptionHandler} BEFORE any write.
 */
public record ServiceCurationRequest(
        @NotBlank(message = "serviceKey is required")
        @Size(max = 128, message = "serviceKey is too long")
        String serviceKey) {
}
