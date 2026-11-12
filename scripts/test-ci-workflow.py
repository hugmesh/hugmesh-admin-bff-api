#!/usr/bin/env python3
"""Pins .github/workflows/ci.yml: the GitHub workflow that runs the Maven suite with the
cross-repo drift guards ARMED.

ImageCatalogDriftTest and AppProfileSchemaMirrorTest compare this repo with a sibling checkout
and SKIP when that checkout is absent. A workflow that runs the suite without the siblings, or
that lets the pom's catalog-copy profile refresh the vendored catalogs before the test reads
them, is green while checking nothing. That is how the vendored image-gen catalogs drifted from
the generator for seven weeks unnoticed. Each check below names one way to disarm the guard.

Whole-line comments are dropped first, so prose cannot satisfy or defeat a check. Standard
library only (no PyYAML), no network.

Run: python3 scripts/test-ci-workflow.py [path/to/ci.yml]
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PATH = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, ".github", "workflows", "ci.yml")
SIBLING = "${CATALOG_SIBLING_ROOT}"
GEN_DIR = SIBLING + "/hugmesh-generator/docs/catalog"
# WorklistSchemaDriftTest reads the generator's docs/schemas, the sibling of GEN_DIR.
GEN_SCHEMA = SIBLING + "/hugmesh-generator/docs/schemas/worklist.v1.schema.json"
CONSOLE_DIR = SIBLING + "/hugmesh-superadmin-service-catalog-ui/schemas"
FAILURES = 0


def check(desc, ok, detail=""):
    global FAILURES
    if ok:
        print(f"ok   {desc}")
    else:
        FAILURES += 1
        print(f"FAIL {desc}" + (f"\n---- {detail}\n----" if detail else ""), file=sys.stderr)


def finish():
    if FAILURES:
        print(f"\ntest-ci-workflow: {FAILURES} failure(s) in {PATH}", file=sys.stderr)
        sys.exit(1)
    print("\ntest-ci-workflow: all checks passed")
    sys.exit(0)


if not os.path.isfile(PATH):
    check("the CI workflow exists (without it the suite, and every drift guard, never runs on GitHub)",
          False, PATH)
    finish()

RAW = open(PATH, encoding="utf-8").read()
CODE = "\n".join(line for line in RAW.splitlines() if not line.lstrip().startswith("#")) + "\n"
LINES = CODE.splitlines()


def block(header_re, indent):
    """The lines after the first line matching header_re, up to the next line at <= indent."""
    for i, line in enumerate(LINES):
        if re.match(header_re, line):
            out = []
            for nxt in LINES[i + 1:]:
                if nxt.strip() and len(nxt) - len(nxt.lstrip()) <= indent:
                    break
                out.append(nxt)
            return "\n".join(out)
    return None


def steps():
    """Every step's text, split on the '- ' that opens a step under the (single) job's steps:."""
    out = []
    for i, line in enumerate(LINES):
        m = re.match(r"^(\s*)steps:\s*$", line)
        if not m:
            continue
        base = len(m.group(1))
        cur, marker = None, None
        for nxt in LINES[i + 1:]:
            if nxt.strip() and len(nxt) - len(nxt.lstrip()) <= base:
                break
            if marker is None and nxt.strip():
                marker = " " * (len(nxt) - len(nxt.lstrip())) + "- "
            if marker and nxt.startswith(marker):
                if cur is not None:
                    out.append("\n".join(cur))
                cur = [nxt]
            elif cur is not None:
                cur.append(nxt)
        if cur is not None:
            out.append("\n".join(cur))
    return out


def logical_commands(text):
    """Shell lines with backslash continuations joined and a trailing ' #...' comment dropped."""
    cmds, buf = [], ""
    for line in text.splitlines():
        line = re.sub(r"\s+#.*$", "", line)
        if line.rstrip().endswith("\\"):
            buf += line.rstrip()[:-1] + " "
            continue
        cmds.append((buf + line).strip())
        buf = ""
    if buf:
        cmds.append(buf.strip())
    return cmds


# ── triggers ─────────────────────────────────────────────────────────────────────────────
on = block(r"^on:\s*$", 0)
check("the workflow has an on: block", on is not None)
on = on or ""
check("triggers on pull_request (a PR that breaks a guard is red before it merges)",
      re.search(r"^  pull_request:", on, re.M) is not None, on)
check("triggers on a schedule with a cron (generator drift goes red with no commit here)",
      re.search(r"^  schedule:", on, re.M) is not None and re.search(r"^\s+- cron: '[^']+'", on, re.M) is not None, on)
check("no pull_request_target (it would run with this repo's secrets on a fork's code)",
      "pull_request_target" not in CODE)

# ── runners and permissions ──────────────────────────────────────────────────────────────
runs_on = re.findall(r"^\s+runs-on:\s*(.*?)\s*$", CODE, re.M)
check("every job declares runs-on", len(runs_on) >= 1, str(runs_on))
check("every job runs on a literal ubuntu-latest (pull_request must never reach a self-hosted runner)",
      all(r == "ubuntu-latest" for r in runs_on), str(runs_on))
check("workflow permissions are contents: read", re.search(r"^permissions:\n  contents: read\s*$", CODE, re.M) is not None)
check("nothing in the workflow asks for a write permission", re.search(r":\s*write\b", CODE) is None)
check("no continue-on-error (a failing guard must fail the run)", "continue-on-error" not in CODE)

# ── the sibling checkouts ────────────────────────────────────────────────────────────────
STEPS = steps()


def step_with(*needles):
    for i, s in enumerate(STEPS):
        if all(n in s for n in needles):
            return i, s
    return None, ""


gi, gen = step_with("repository: hugmesh/hugmesh-generator")
check("checks out hugmesh/hugmesh-generator", gi is not None)
check("the generator is read at main (the question is what the generator ships today)",
      re.search(r"^\s+ref: main\s*$", gen, re.M) is not None, gen)
check("the generator lands under .catalog-sibling/ (never ../hugmesh-generator)",
      re.search(r"^\s+path: \.catalog-sibling/hugmesh-generator\s*$", gen, re.M) is not None, gen)


def sparse_paths(step):
    """The paths a checkout step's sparse-checkout names: one inline value, or a | block."""
    lines = step.splitlines()
    for i, line in enumerate(lines):
        m = re.match(r"^(\s+)sparse-checkout:\s*(.*?)\s*$", line)
        if not m:
            continue
        if m.group(2) not in ("|", "|-", ">", ">-"):
            return [m.group(2)] if m.group(2) else []
        out = []
        for nxt in lines[i + 1:]:
            if nxt.strip() and len(nxt) - len(nxt.lstrip()) <= len(m.group(1)):
                break
            if nxt.strip():
                out.append(nxt.strip())
        return out
    return []


SPARSE_PATHS = sparse_paths(gen)
check("the generator sparse checkout includes docs/catalog (ImageCatalogDriftTest's source)",
      "docs/catalog" in SPARSE_PATHS, str(SPARSE_PATHS))
check("the generator sparse checkout includes docs/schemas (WorklistSchemaDriftTest's source)",
      "docs/schemas" in SPARSE_PATHS, str(SPARSE_PATHS))
ci, con = step_with("repository: hugmesh/hugmesh-superadmin-service-catalog-ui")
check("checks out hugmesh/hugmesh-superadmin-service-catalog-ui", ci is not None)
check("the console lands under .catalog-sibling/",
      re.search(r"^\s+path: \.catalog-sibling/hugmesh-superadmin-service-catalog-ui\s*$", con, re.M) is not None, con)
check("CATALOG_SIBLING_ROOT is the workspace's .catalog-sibling",
      re.search(r"^\s+CATALOG_SIBLING_ROOT: \$\{\{ github\.workspace \}\}/\.catalog-sibling\s*$", CODE, re.M) is not None)
GUARD_PROBE = '[ -e "${GITHUB_WORKSPACE}/../hugmesh-generator" ]'
check("the preflight refuses a generator at ../hugmesh-generator (the catalog-copy profile activates there)",
      GUARD_PROBE in CODE)
check("nothing else names ../hugmesh-generator (no checkout, clone or source dir there)",
      CODE.count("../hugmesh-generator") == CODE.count(GUARD_PROBE), CODE.count("../hugmesh-generator"))

# ── the preflight ────────────────────────────────────────────────────────────────────────
pi, pre = step_with("test -f")
check("a preflight step asserts the sibling files with test -f", pi is not None)
for f in (GEN_DIR + "/image-catalog.json", GEN_DIR + "/packages-catalog.json", GEN_SCHEMA,
          CONSOLE_DIR + "/app-profile.schema.json"):
    check(f"the preflight names {f}", f in pre, pre)
check("the preflight fails the step (exit non-zero) when a file is missing",
      re.search(r"rc=1", pre) is not None and re.search(r"exit \$\{?rc\}?", pre) is not None, pre)

# ── the Maven command ────────────────────────────────────────────────────────────────────
mi, mvn_step = step_with("./mvnw")
mvn = [c for c in logical_commands(mvn_step) if c.startswith("./mvnw")]
check("exactly one ./mvnw command", len(mvn) == 1, str(mvn))
cmd = mvn[0] if mvn else ""
tokens = cmd.split()
check("the build runs the verify goal (compile, the whole suite, and the analysis gates)", "verify" in tokens, cmd)
check("the build reads the GitHub Packages settings", "-s .github/maven-ci-settings.xml" in cmd, cmd)
check("-Dcatalog.source.dir points at the generator sibling (arms ImageCatalogDriftTest)",
      f'-Dcatalog.source.dir="{GEN_DIR}"' in cmd, cmd)
check("-Dappprofile.schema.console.dir points at the console sibling",
      f'-Dappprofile.schema.console.dir="{CONSOLE_DIR}"' in cmd, cmd)
check("-Dappprofile.schema.mirror.required=true (a missing console fails instead of skipping)",
      "-Dappprofile.schema.mirror.required=true" in tokens, cmd)
check("the catalog-copy profile is switched off by name", "-P '!catalog-copy'" in cmd, cmd)
check("the catalog-copy profile is never switched on (it would refresh the copy into agreement)",
      re.search(r"-P\s*['\"]?catalog-copy", cmd) is None and re.search(r"-P\s*['\"]?[^'\"\s]*,catalog-copy", cmd) is None, cmd)
for bad in ("skipTests", "maven.test.skip", "-Dtest=", "-fn", "--fail-never", "-fae", "--fail-at-end",
            "hugmesh.analysis.skip", "-Dsurefire.failIfNoSpecifiedTests", "|| true"):
    check(f"the build does not pass {bad}", bad not in cmd, cmd)
check("the build step runs under set -euo pipefail", "set -euo pipefail" in mvn_step, mvn_step)
check("the build has the package read token", "UPSTREAM_PACKAGES_TOKEN: ${{ secrets.PACKAGES_READ_TOKEN }}" in mvn_step, mvn_step)

# ── order: guard, token, siblings, preflight, build, clean tree ──────────────────────────
ti, tok = step_with("PACKAGES_READ_TOKEN", "exit 1")
check("a missing package token fails by name before the build", ti is not None and "-z" in tok, tok)
di, _ = step_with("git diff --exit-code")
si, _ = step_with("python3 scripts/test-ci-workflow.py")
check("this pin runs in the workflow", si is not None)
order = [si, ti, gi, ci, pi, mi, di]
check("steps run in order: pin, token, generator, console, preflight, build, clean-tree",
      None not in order and order == sorted(order), str(order))

finish()
