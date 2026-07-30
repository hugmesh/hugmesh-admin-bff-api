# HugMesh admin-bff-api — developer make targets.
#
# These mirror the CI pen-test stage (.gitlab-ci.yml -> generator
# tests/pentest/ci/pentest-stage.gitlab-ci.yml) so a dev can run the SAME OWASP
# checks locally before pushing. CI is the source of truth; this is a convenience
# wrapper and intentionally does NOT hard-fail when tooling/targets are absent.

# Generator repo carrying the shared DAST harness (run-pentest.sh) + CI template.
GENERATOR_REPO ?= https://github.com/hugmesh-net/hugmesh-generator.git
# Local checkout of the generator, if present alongside this repo (sibling dir).
GENERATOR_DIR  ?= ../hugmesh-generator
# DAST target; when unset the DAST half is skipped (no hard fail).
DAST_TARGET_URL ?=

.PHONY: pentest pentest-sca pentest-dast

## pentest: run the local SCA self-scan (mirrors CI) + DAST harness if a target is set.
pentest: pentest-sca pentest-dast

## pentest-sca: OWASP Dependency-Check over this repo, mirroring the CI .pentest-sca job.
pentest-sca:
	@echo "== pen-test SCA (OWASP Dependency-Check) =="
	@if [ -x ./mvnw ]; then \
		echo "-> running ./mvnw org.owasp:dependency-check-maven:check -DfailBuildOnCVSS=9"; \
		./mvnw org.owasp:dependency-check-maven:check -DfailBuildOnCVSS=9 -B || \
			echo "WARN: dependency-check reported issues or could not run (non-blocking; see CI for the gating run)"; \
	elif command -v docker >/dev/null 2>&1; then \
		echo "-> no ./mvnw; running via eclipse-temurin docker image as CI does"; \
		docker run --rm -v "$$(pwd):/workspace" -w /workspace --entrypoint "" \
			eclipse-temurin:21-jdk-noble \
			./mvnw org.owasp:dependency-check-maven:check -DfailBuildOnCVSS=9 -B || \
			echo "WARN: dependency-check reported issues or could not run (non-blocking)"; \
	else \
		echo "SKIP: neither ./mvnw nor docker available for the SCA self-scan"; \
	fi

## pentest-dast: delegate the full DAST harness (ZAP baseline + probes + nuclei) to the generator.
pentest-dast:
	@echo "== pen-test DAST (generator harness) =="
	@if [ -z "$(DAST_TARGET_URL)" ]; then \
		echo "SKIP: DAST_TARGET_URL not set — export DAST_TARGET_URL=https://... to run the harness"; \
	elif [ -f "$(GENERATOR_DIR)/tests/pentest/run-pentest.sh" ]; then \
		echo "-> bash $(GENERATOR_DIR)/tests/pentest/run-pentest.sh --env compose --scan baseline --pipeline main"; \
		DAST_TARGET_URL="$(DAST_TARGET_URL)" bash "$(GENERATOR_DIR)/tests/pentest/run-pentest.sh" \
			--env compose --scan baseline --pipeline main || \
			echo "WARN: DAST harness reported issues or could not run (non-blocking)"; \
	else \
		echo "NOTE: generator harness not found at $(GENERATOR_DIR)/tests/pentest/run-pentest.sh"; \
		echo "      clone it and re-run, e.g.:"; \
		echo "        git clone $(GENERATOR_REPO) $(GENERATOR_DIR)"; \
		echo "        DAST_TARGET_URL=$(DAST_TARGET_URL) bash $(GENERATOR_DIR)/tests/pentest/run-pentest.sh --env compose --scan baseline --pipeline main"; \
	fi
