// NOTE ON THE DIRECTORY: the templating renderer substitutes tokens in file
// CONTENT only (paths are static), so this file lives under the neutral
// src/main/java/net/hugmesh/app/ directory while declaring the REAL
// per-repo package net.hugmesh.{{APP_SLUG}}. javac places classes by the
// DECLARED package (source directories need not match), so the build is
// unaffected; after adopting the tree, `git mv` the sources into
// src/main/java/net/hugmesh/{{APP_SLUG}}/ to restore the conventional
// layout. See README.md, "Package layout".
package net.hugmesh.{{APP_SLUG}};

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * {{BRAND_TITLE}} {{APP_SLUG}} BFF — minimal, runnable Spring Boot 4 WebFlux
 * service rendered by the spring-bff archetype's base-absent skeleton. One
 * public-health / authenticated-elsewhere security chain, one hello endpoint,
 * fully {@code ${ENV:default}}-driven config. Grow it into a real BFF by adding
 * controllers under this package (component scan roots here).
 */
@SpringBootApplication
public class Application {

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}
