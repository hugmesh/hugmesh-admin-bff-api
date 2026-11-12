package net.hugmesh.adminbff.imagegen;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

/**
 * The {@link GeneratorPlatform} constraint. No Spring dependencies, so it works the same in a
 * slice test, a plain {@code Validation.buildDefaultValidatorFactory()} and the running BFF.
 *
 * <p>The refusal names the accepted platforms. It never echoes the refused value: the message is
 * a bean-validation TEMPLATE, and caller text in a template would be interpolated (EL). The
 * platform list itself is safe to put there, because {@link GeneratorPlatforms} only loads
 * tokens of letters, digits and hyphens.
 */
public class GeneratorPlatformValidator implements ConstraintValidator<GeneratorPlatform, String> {

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        if (value == null || GeneratorPlatforms.isEntryPlatform(value)) {
            return true;
        }
        context.disableDefaultConstraintViolation();
        context.buildConstraintViolationWithTemplate(
                        "must be a platform in the generator worklist schema (accepted: "
                                + GeneratorPlatforms.describeEntryPlatforms() + ")")
                .addConstraintViolation();
        return false;
    }
}
