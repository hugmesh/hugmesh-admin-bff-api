# Backup & Recovery worker — manifests + operator follow-up

These resources back the admin BFF's cloud Backup & Recovery feature
(`/bff/admin/backups`, `/bff/admin/restores`, `/bff/admin/usb-devices`). The BFF
orchestrates by **templating a Kubernetes Job** (the same infra-orchestration
shape the admin surface already uses) — it does not shell out on the BFF pod.

## Files (shipped in this repo)

| File | Role |
|------|------|
| `backup-job.yaml`   | Job template for a backup. `BackupOrchestrator.renderManifest` fills `${JOB_ID} ${SCOPE} ${TARGET} ${ENCRYPTED} ${LOCATION_REF}`. |
| `restore-job.yaml`  | Job template for a restore (`MODE=restore`). |
| `backup-worker.sh`  | The worker entrypoint: etcd snapshot / `pg_dump` / `rsync` / Secret+ConfigMap export, `tar` bundle, and **AES-256-CBC + PBKDF2 (210000 iters)** encrypt/decrypt via `openssl`. Mounted as a ConfigMap (`backup-worker-script`). |
| `rbac.yaml`         | ServiceAccount + (Cluster)Role(Binding)s — **apply once** (`kubectl apply -f rbac.yaml`). |

## Encryption (tool + KDF)

- **Tool:** `openssl enc -aes-256-cbc -pbkdf2 -iter 210000 -salt` (symmetric AES-256).
- **KDF:** PBKDF2-HMAC-SHA256, 210 000 iterations — the same algorithm + iteration
  count the BFF uses for its `backup_history` **verifier** (`BackupCrypto`). The
  BFF stores only the one-way verifier (+ salt); the actual AES key is derived
  **inside the worker** from the password, so the BFF never holds the data key.
- **Password delivery:** the BFF creates an **ephemeral Secret** `backup-pw-<id>`
  with an `ownerReference` to the Job, mounted read-only at `/run/backup/password`.
  It is garbage-collected when the Job is reaped (`ttlSecondsAfterFinished`). The
  password is never an env var, never in the manifest, never logged.
- **Wrong password on restore:** verified by the BFF against the stored PBKDF2
  verifier **before** the restore Job is applied → `403 incorrect decryption
  password`. The key is never derived/revealed on a mismatch.

## USB targeting

`GET /bff/admin/usb-devices` lists connected/mountable USB devices (and backups
found on them). Enumeration runs **on the node** (the worker / a node agent reads
`lsblk -J -o NAME,LABEL,MOUNTPOINT,SIZE,FSAVAIL,RO,TRAN` filtered to `TRAN=usb`);
the BFF pod has no host block-device visibility. A `USB` backup/restore mounts the
device at `/mnt/usb` (`hostPath` in the Job template). The default
`UsbDeviceProvider` returns an empty list until the node-agent endpoint is wired —
see *Implemented vs follow-up* below.

## Implemented in this repo vs. operator follow-up

**Implemented (BFF):** the full REST + SSE contract, scope/target/USB validation,
the PBKDF2 verifier + wrong-password 403, the durable `backup_history` lifecycle,
the Job-manifest templating, and the worker script + manifests + RBAC here.

**Operator follow-up (documented, not auto-applied):**
1. Apply `rbac.yaml` and create the `backup-worker-script` ConfigMap from
   `backup-worker.sh`, the `hugmesh-backup-staging` PVC, and build/publish the
   `backup-worker` image (etcdctl + kubectl + pg_dump + rsync + openssl).
2. Wire `BackupOrchestrator.applyJob` to the cluster (fabric8 / official k8s
   client) to actually `create` the rendered Job + ephemeral Secret and tail the
   pod log into the SSE stream. It is a no-op seam today (dev/test BFF has no
   cluster), so the BFF drives the canonical phase progression instead.
3. Wire `UsbDeviceProvider` to the node-agent USB enumeration endpoint.
4. **etcd restore** is control-plane and intentionally left operator-gated (the
   worker logs a notice rather than restoring etcd in-place).

## Test-runner Job (Test-Reports console)

These resources back the admin **Test-Reports** console
(`/bff/admin/test-reports`) — the test-architecture run list / report download /
on-demand trigger / live SSE progress.

| File | Role |
|------|------|
| `test-runner-job.yaml`  | Job template for a run. `TestRunOrchestrator.renderManifest` fills `${RUN_ID} ${TIER} ${COMMIT_SHA} ${TRIGGER_SOURCE}`. The runner image bundles the generator `tests/e2e` Playwright suite + `tests/qemu/seed-accounts.sh` (ENV=test only). |
| `test-runner-rbac.yaml` | ServiceAccount + Role(Binding) for the BFF to launch runner Jobs + the shared `hugmesh-test-reports` PVC — **apply once**. |

### REAL launch vs. backup's no-op seam

Unlike the backup `applyJob` (a documented **no-op**), the test-runner launch is
**built for real**: `Fabric8JobLauncher` applies the rendered Job with the fabric8
`KubernetesClient` (already on the classpath via the spring-cloud-kubernetes leader
starter). It is wired **only** when `testreports.launch.enabled=true`; otherwise the
cluster-less `NoopJobLauncher` runs (dev/test/CI), so the
start → ingest → SSE → durable-status contract is exercisable without a cluster. The
seam's realness is published at `/actuator/info` (`testReports.launchReal`) — the
runtime signal the prod-hygiene gate reads (a manifest scan cannot see a Java stub).

### REAL event-ingest path

The runner POSTs per-`(suite,role)` events back to
`POST /bff/admin/test-reports/${RUN_ID}/ingest` (admin-gated + the runner's own
pre-minted token in the `test-runner-ingest-token` Secret). The orchestrator upserts
the durable `test_run_result` matrix **and** fans an SSE event to live subscribers;
the run-terminal event closes out the `test_run` row. The SSE replay buffer is
**bounded** (`testreports.sse.replay-buffer`, default 256) — a reconnecting admin (or
a different replica / a restarted pod) recovers full state from the durable matrix.

### Report storage + download (secrets scrubbed)

The runner writes the artifact bundle (`junit.xml`, `summary.json`, sanitized
`logs/`) to the shared `hugmesh-test-reports` PVC under
`<tier>/run-<ts>-<commit>/` and reports that path back as the run's `report_ref`.
`GET /{id}/download` streams it as a `tar.gz`, resolving `report_ref` **under** the
PVC root (a `../` traversal or absolute ref is a 400) and **re-scrubbing** every text
entry through `ReportScrubber` on read — defence-in-depth on top of the runner's
write-time scrub.

### Operator follow-up (documented, not auto-applied)

1. Apply `test-runner-rbac.yaml` (SA + Role + report PVC), build/publish the
   `test-runner` image (Playwright + `seed-accounts.sh`), and create the
   `test-runner-ingest-token` Secret (a Casdoor client-credentials token scoped to
   the ingest path).
2. Flip `testreports.launch.enabled=true` (+ `testreports.launch.namespace` if the
   deployment relocates) so `Fabric8JobLauncher` applies Jobs for real.
3. The cluster orchestrator (hugmesh-generator `apps/99-test-runner.yaml`) is the
   automated trigger for the LEAN (fe/be/pki-ready) + HEAVY (x86-attach) runs; the
   admin `POST /run` is the on-demand path. Both write the same `test_run` rows.
