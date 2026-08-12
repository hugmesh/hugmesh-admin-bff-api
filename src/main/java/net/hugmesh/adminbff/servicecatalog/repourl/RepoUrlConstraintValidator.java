package net.hugmesh.adminbff.servicecatalog.repourl;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import org.springframework.beans.factory.annotation.Value;

import java.util.Set;

/**
 * The {@link RepoUrl} constraint implementation — a Spring-managed {@link ConstraintValidator}
 * (Spring Boot wires ConstraintValidators as beans by default) so it can read the OPTIONAL,
 * configurable host allowlist from {@code app.appstore.repo-host-allowlist} (a comma-separated
 * list; unset/empty = any valid host). The structural decision lives entirely in
 * {@link RepoUrlValidator}; this class only adapts it to the bean-validation contract and
 * substitutes the precise failure reason into the constraint message.
 */
public class RepoUrlConstraintValidator implements ConstraintValidator<RepoUrl, String> {

    /** Comma-separated host allowlist; unset/blank → unconstrained (any valid host accepted). */
    private final Set<String> hostAllowlist;

    public RepoUrlConstraintValidator(
            @Value("${app.appstore.repo-host-allowlist:}") String hostAllowlistCsv) {
        this.hostAllowlist = RepoUrlValidator.parseHostAllowlist(hostAllowlistCsv);
    }

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        RepoUrlValidator.Result result = RepoUrlValidator.validate(value, hostAllowlist);
        if (result.valid()) {
            return true;
        }
        // Replace the default message with the precise structural reason so the 400 is actionable
        // (e.g. "repoUrl scheme must be one of [https, git, ssh] (got 'file')").
        context.disableDefaultConstraintViolation();
        context.buildConstraintViolationWithTemplate(escape(result.reason()))
                .addConstraintViolation();
        return false;
    }

    /** EL/message-template metacharacters ({@code $} and {@code {}}) in the reason would be
     *  interpreted by the validator's message interpolator; neutralise them so the host/scheme
     *  echoed back is rendered literally. */
    private static String escape(String reason) {
        if (reason == null) {
            return "repoUrl is invalid";
        }
        return reason.replace("$", "").replace("{", "(").replace("}", ")");
    }
}
