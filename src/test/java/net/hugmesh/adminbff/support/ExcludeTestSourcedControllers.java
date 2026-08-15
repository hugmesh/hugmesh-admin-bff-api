package net.hugmesh.adminbff.support;

import org.springframework.beans.factory.annotation.AnnotatedBeanDefinition;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.BeanDefinitionRegistryPostProcessor;
import org.springframework.stereotype.Controller;

import java.security.CodeSource;

/**
 * Keeps a FULL-CONTEXT ({@code @SpringBootTest}) boot mounting the PRODUCTION controller surface
 * only, by withdrawing every {@code @Controller} bean that was compiled from {@code src/test/java}.
 *
 * <p><b>Why this is needed at all.</b> A full-context boot component-scans all of
 * {@code net.hugmesh.adminbff}, and that scan reaches {@code target/test-classes} as well as
 * {@code target/classes}. Spring Boot's {@code TestTypeExcludeFilter} already hides test classes
 * and anything NESTED inside one, so the usual {@code static class Probe} declared inside a slice
 * test is invisible here. What it does NOT hide is a TOP-LEVEL package-private controller declared
 * alongside a test in the same file — of which this module has three, all in
 * {@code net.hugmesh.adminbff.config}: {@code Probes} (SecurityConfigPathRulesTest),
 * {@code Guarded} (MethodSecuritySuperadminBypassTest) and {@code InternalProbes}
 * (InternalSurfaceRoleMatrixTest). To the scanner those are ordinary classes, so they are
 * registered as beans and then either collide with a real controller ("Ambiguous mapping", the
 * boot fails loudly) or — worse, because it is SILENT — contribute a phantom path to the OpenAPI
 * document that {@code OpenApiSpecDumpTest} writes to a committed file.
 *
 * <p><b>Why the rule is derived rather than listed.</b> This replaces a hardcoded
 * {@code Set.of("…config.Probes", "…config.Guarded")} that had been copy-pasted into FOUR tests.
 * {@code InternalProbes} was added to the same test package later, none of the four lists were
 * updated, and its {@code /bff/internal/**} catch-all leaked a 114-line path with seven operations
 * into the committed spec on every {@code ./mvnw test} — with the whole suite green. The
 * membership test here is instead a PROPERTY of the bean ("its class came out of the test
 * compilation unit"), so a probe written tomorrow is excluded the day it is written and there is
 * no list to forget.
 *
 * <p><b>Scope.</b> Deliberately narrowed to {@code @Controller} (which {@code @RestController}
 * meta-annotates): test-sourced {@code @TestConfiguration} and support beans are legitimate
 * context wiring and must survive. Only handler beans distort the mounted HTTP surface.
 *
 * <p><b>Where it is deliberately fail-open.</b> The check reads SCANNED annotation metadata, so a
 * controller contributed by a test {@code @Bean} factory method (no {@code @Controller} on the
 * definition itself) is not withdrawn. That is not a hole in the contract, because it is not this
 * class that certifies the result: {@code OpenApiSpecDumpTest} independently asserts, against the
 * live routing table and the generated document, that nothing test-sourced is mounted and that no
 * spec path lacks a {@code src/main/java} handler. This class decides what to withdraw; that test
 * decides whether the withdrawal was complete — and it names no probe, so it cannot go stale.
 *
 * @see net.hugmesh.adminbff.OpenApiSpecDumpTest
 */
public final class ExcludeTestSourcedControllers implements BeanDefinitionRegistryPostProcessor {

    /**
     * The classpath root this class itself was loaded from — i.e. {@code target/test-classes}.
     * Every class compiled from {@code src/test/java} shares it and nothing from {@code src/main}
     * does, which makes "same code source as me" an exact, self-anchoring definition of
     * test-sourced (no {@code "/test-classes/"} substring convention to match on). Captured once:
     * it is a constant for the JVM.
     *
     * <p>NEVER null in practice, and the constructor below refuses to let it be. A null here would
     * make {@link #isTestSourced} answer {@code false} for everything, which silently degrades the
     * exclusion AND both of {@code OpenApiSpecDumpTest}'s guards to no-ops at the same instant —
     * precisely the green-while-corrupting mode this class exists to eliminate. That it is
     * currently loud anyway is an ACCIDENT, not a design: the un-withdrawn {@code Probes} collides
     * with {@code AdminController} on {@code GET /bff/admin/allowlist} and boot fails on an
     * ambiguous mapping. Take the advice in the guard's own failure message — nest the probes
     * inside their tests — and that collision disappears, leaving a null code source silent again.
     * So the check is here, at the source, not left to depend on a coincidence elsewhere.
     */
    private static final String TEST_CLASSES_ROOT = requireCodeSource();

    private static String requireCodeSource() {
        String root = codeSourceRootOf(ExcludeTestSourcedControllers.class);
        if (root == null) {
            throw new IllegalStateException(
                    "ExcludeTestSourcedControllers could not resolve its own CodeSource, so it "
                    + "cannot tell test-sourced classes from main-sourced ones. Failing closed: "
                    + "proceeding would silently disable the test-controller exclusion and both "
                    + "OpenApiSpecDumpTest guards, and the suite would go green while rewriting "
                    + "the committed OpenAPI contract with phantom paths.");
        }
        return root;
    }

    @Override
    public void postProcessBeanDefinitionRegistry(BeanDefinitionRegistry registry) {
        // Runs AFTER component scanning has registered every bean definition and BEFORE the
        // RequestMappingHandlerMapping is built — the only window in which a scanned controller
        // can still be withdrawn.
        for (String name : registry.getBeanDefinitionNames()) {
            if (isTestSourcedController(registry.getBeanDefinition(name))) {
                registry.removeBeanDefinition(name);
            }
        }
    }

    @Override
    public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) {
        // no-op
    }

    /**
     * Whether {@code type} was compiled from {@code src/test/java}. Exposed so a test can assert
     * the same property against the live handler mapping that this class applies to the bean
     * registry — one definition of "test-sourced", enforced on one side and verified on the other.
     */
    public static boolean isTestSourced(Class<?> type) {
        String root = codeSourceRootOf(type);
        return root != null && root.equals(TEST_CLASSES_ROOT);
    }

    private static boolean isTestSourcedController(BeanDefinition definition) {
        String className = definition.getBeanClassName();
        if (className == null || !(definition instanceof AnnotatedBeanDefinition annotated)) {
            // Infrastructure definitions and @Bean factory methods carry no scanned type
            // metadata; a leaked probe is always a scanned ScannedGenericBeanDefinition.
            return false;
        }
        // Cheap ASM-metadata check first — it resolves the @RestController -> @Controller
        // meta-annotation without loading anything, so the class-load below only ever touches
        // actual controllers, which the context is about to instantiate anyway.
        if (!annotated.getMetadata().getAnnotations().isPresent(Controller.class)) {
            return false;
        }
        Class<?> type = resolve(className);
        return type != null && isTestSourced(type);
    }

    /**
     * Resolves through the loader that loaded THIS class, so the comparison against
     * {@link #TEST_CLASSES_ROOT} is made in the same loader that produced it. Resolves WITHOUT
     * initializing: a code-source probe must not run anyone's static block.
     */
    private static Class<?> resolve(String className) {
        try {
            return Class.forName(className, false, ExcludeTestSourcedControllers.class.getClassLoader());
        } catch (ClassNotFoundException | LinkageError e) {
            return null;
        }
    }

    private static String codeSourceRootOf(Class<?> type) {
        CodeSource source = type.getProtectionDomain().getCodeSource();
        if (source == null || source.getLocation() == null) {
            return null;
        }
        return source.getLocation().toString();
    }
}
