package net.hugmesh.adminbff.workload;

import org.junit.jupiter.api.Test;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * ARCHITECTURE TEST — the {@link WorkloadAdminController} (the admin READ surface) must carry
 * ZERO mutating mappings (DECISION 4: a granted admin is read-only; it can never
 * stream/exec/mutate). Reflection-based (no ArchUnit on the classpath): asserts no method is
 * annotated with @PostMapping/@PutMapping/@DeleteMapping/@PatchMapping (nor a @RequestMapping
 * with a mutating method), and no mapping path mentions exec/stream/lifecycle/port-forward.
 */
class WorkloadAdminControllerArchTest {

    @Test
    void adminController_hasNoMutatingMapping() {
        List<String> violations = new ArrayList<>();
        for (Method m : WorkloadAdminController.class.getDeclaredMethods()) {
            if (m.isAnnotationPresent(PostMapping.class)
                    || m.isAnnotationPresent(PutMapping.class)
                    || m.isAnnotationPresent(DeleteMapping.class)
                    || m.isAnnotationPresent(PatchMapping.class)) {
                violations.add(m.getName() + " has a mutating mapping annotation");
            }
            RequestMapping rm = m.getAnnotation(RequestMapping.class);
            if (rm != null) {
                for (var method : rm.method()) {
                    switch (method) {
                        case POST, PUT, DELETE, PATCH ->
                                violations.add(m.getName() + " has a mutating @RequestMapping method");
                        default -> {
                        }
                    }
                }
            }
        }
        assertThat(violations)
                .as("the admin workload console surface must be strictly read-only")
                .isEmpty();
    }

    @Test
    void adminController_hasNoDangerousMappingPaths() {
        List<String> violations = new ArrayList<>();
        for (Method m : WorkloadAdminController.class.getDeclaredMethods()) {
            var get = m.getAnnotation(org.springframework.web.bind.annotation.GetMapping.class);
            if (get != null) {
                for (String path : get.value()) {
                    if (path.contains("exec") || path.contains("stream")
                            || path.contains("lifecycle") || path.contains("port-forward")
                            || path.contains("rollout-restart")) {
                        violations.add(m.getName() + " maps a dangerous path: " + path);
                    }
                }
            }
        }
        assertThat(violations)
                .as("the admin surface must not expose exec/stream/lifecycle/port-forward")
                .isEmpty();
    }
}
