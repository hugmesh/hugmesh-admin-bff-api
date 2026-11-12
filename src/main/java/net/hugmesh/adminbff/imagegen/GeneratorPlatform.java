package net.hugmesh.adminbff.imagegen;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * The value must be a worklist ENTRY platform listed by the vendored generator worklist schema
 * ({@link GeneratorPlatforms#entryPlatforms()}). A bean-validation {@code @Pattern} needs a
 * compile-time constant, which is exactly the hand list this replaces; this constraint reads the
 * set the schema declares instead. {@code null} is valid here (pair it with {@code @NotBlank}),
 * following the bean-validation convention.
 */
@Documented
@Constraint(validatedBy = GeneratorPlatformValidator.class)
@Target({ElementType.FIELD, ElementType.PARAMETER, ElementType.RECORD_COMPONENT})
@Retention(RetentionPolicy.RUNTIME)
public @interface GeneratorPlatform {

    String message() default "must be a platform in the generator worklist schema";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}
