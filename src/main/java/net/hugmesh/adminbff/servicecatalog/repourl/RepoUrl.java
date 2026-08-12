package net.hugmesh.adminbff.servicecatalog.repourl;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Bean-validation constraint for an App-Store service-catalog {@code repoUrl}. Delegates to
 * {@link RepoUrlValidator}: the value must be a well-formed URI whose scheme is one of
 * {@code {https, git, ssh}}, with a non-empty host, no whitespace/control characters, length
 * ≤ 512, and (when {@code app.appstore.repo-host-allowlist} is configured) a host on that
 * allowlist. A failing value is a 400 on the controller {@code @Valid} path.
 *
 * <p>This is LAYER 1 (the request-DTO guard); {@code KanikoBuildLauncher} re-runs the same
 * {@link RepoUrlValidator} as LAYER 2 (the sink backstop) so an internal caller cannot bypass it.
 *
 * <p>{@code null}/blank is treated as INVALID (the field is required); pair with {@code @NotBlank}
 * for the canonical "required" message if desired — this constraint also reports it.
 */
@Documented
@Constraint(validatedBy = RepoUrlConstraintValidator.class)
@Target({ElementType.FIELD, ElementType.PARAMETER, ElementType.RECORD_COMPONENT})
@Retention(RetentionPolicy.RUNTIME)
public @interface RepoUrl {

    String message() default "repoUrl is not a valid https/git/ssh repository URL";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}
