# {{BRAND_TITLE}} — {{REPO_NAME}} (Spring-BFF runnable example skeleton)

A minimal but **REAL** Spring Boot 4 / WebFlux BFF in the platform shape,
rendered by the mesh repo-templating **spring-bff** archetype when the Tier-2
base (`hugmesh-{{REPO_NAME}}`) is not pullable. Unlike the old placeholder
this tree **builds, tests and runs**:

```
mvn -s settings.xml package      # compile + WebTestClient tests + boot jar
java -jar target/{{APP_SLUG}}-bff-0.1.0.jar
curl -s localhost:8080/actuator/health          # public  -> {"status":"UP"}
curl -si localhost:8080/api/{{APP_SLUG}}/hello  # no JWT  -> 401
```

## What it contains

| Piece | File | Shape |
|---|---|---|
| Org parent | `pom.xml` | `net.hugmesh:hugmesh-parent` (the admin-bff-api exemplar's pin) — injects WebFlux/actuator/security/OAuth2 + the shared test stack |
| App | `src/main/java/.../Application.java` | `@SpringBootApplication`, package `net.hugmesh.{{APP_SLUG}}` |
| API | `HelloController` | `GET /api/{{APP_SLUG}}/hello` -> `{service, message}` |
| Security | `SecurityConfig` | permitAll `/actuator/health(/**)`, `authenticated()` everywhere else, Bearer-JWT resource server, CSRF off (no cookie mint) |
| Config | `application.yml` | fully `${ENV:default}`-driven (Casdoor issuer/JWKS, management include, port) |
| Test | `HelloControllerTest` | full-context WebTestClient: health public+UP, hello 401 without JWT, exact payload with `mockJwt()` |
| Image | `Dockerfile` + `settings.xml` | BuildKit-secret CI_JOB_TOKEN private-dep resolution (admin-bff-api pattern) |
| CI | `.gitlab-ci.yml` | fleet include (centralized pentest stage) + test + image build |
| Deploy | `deploy/{deployment,kustomization}.yaml` | fleet-convention Deployment (probes, non-root) + registry image rewrite |

## APP_SLUG constraint (READ THIS before rendering)

The `repos[].identity` **`app_slug` for this skeleton MUST match `[a-z0-9]+`**
(lowercase alphanumeric, NO hyphens, non-empty): it is rendered into the Java
package `net.hugmesh.{{APP_SLUG}}` and Java package names cannot contain
`-`. Slugs like `character-studio` are fine for the angular-mfe archetype but
NOT here — pick `characterstudio`-style slugs for a skeleton-rendered BFF. The
same rule is recorded in the archetype `recipe.yaml` header comment.

## Package layout

The templating renderer substitutes tokens in file CONTENT only (paths are
static), so the sources live under the neutral directory
`src/main/java/net/hugmesh/app/` while declaring the real package
`net.hugmesh.{{APP_SLUG}}`. javac places classes by the DECLARED package,
so the build is unaffected. After adopting the tree, restore the conventional
layout with:

```
git mv src/main/java/net/hugmesh/app src/main/java/net/hugmesh/{{APP_SLUG}}
git mv src/test/java/net/hugmesh/app src/test/java/net/hugmesh/{{APP_SLUG}}
```

## No persistence yet — deliberately

`hugmesh-parent` injects the fleet data stack (R2DBC + Liquibase), but this
skeleton declares no tables, so `application.yml` excludes both auto-configs
(startup must never depend on a datastore the service does not use — the same
idiom admin-bff-api applies to Cassandra). When real persistence lands, delete
the two excludes and copy the exemplar's `spring.r2dbc.*` / `spring.liquibase.*`
env-default blocks + the Testcontainers CI wiring.

## Growing into a real BFF

The archetype's real path is overlay-on-base: when `hugmesh-{{REPO_NAME}}`
is resolvable, `render-repo-tree.sh` pulls it and anchor-edits only the
brand-coupled seams (see `templates/archetypes/spring-bff/recipe.yaml`). This
skeleton is the standing example codebase + the base-absent fallback — see
docs/FEDERATION-EXAMPLES.md for the full walkthrough of wiring a new BFF into
the federation surface.
