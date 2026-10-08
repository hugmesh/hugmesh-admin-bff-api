# {{BRAND_TITLE}} — {{REPO_NAME}} (remote-fragment placeholder)

The Tier-2 base (`hugmesh-remote-fragment`) was NOT pullable, so the
remote-fragment archetype fell back to this placeholder. Unlike the spring-bff /
angular-mfe / angular-host archetypes there is deliberately NO runnable skeleton
here: the fragment is a Spring-Native sync sidecar + static-nginx pod whose
entire value IS the real base code (Casdoor client-credentials sync of published
federation bundles into the nginx docroot) — a minimal fake would be a
non-functional lie.

**The real base repo IS the example codebase.** Make it resolvable and re-render:

```
REMOTE_FRAGMENT_BASE_DIR=<path-to-clone> \
  scripts/render-repo-tree.sh brands/<brand>.conf --enable-repo-tree \
    --repo remote-fragment --archetype remote-fragment --out-dir out
```

(`<path-to-clone>` = a local `hugmesh-remote-fragment` checkout — a real
path substituted in; the angle placeholder keeps the pointer README's own emit
secret-scan from reading the long `VAR=/deep/path` run as an opaque token.)

The overlay applies exactly one anchored edit (the CI include org/group ->
`{{GENERATOR_ORG_GROUP}}`); everything else — sync loop, nginx serving, deploy/
(base-owned), the `${ENV}`-driven manifest/Casdoor seams — rides through
unchanged. See docs/FEDERATION-EXAMPLES.md in hugmesh-generator, section 1 ("The example trio
(+ remote-fragment)"), for how the fragment serves remotes this mesh does not build.
