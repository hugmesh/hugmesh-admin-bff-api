# Backup & Recovery worker — manifests + operator follow-up

These resources back the admin BFF's cloud Backup & Recovery feature
(`/bff/admin/backups`, `/bff/admin/restores`, `/bff/admin/usb-devices`). The BFF
orchestrates by **templating a Kubernetes Job**, the same shape the rest of the admin
surface uses. It does not shell out on the BFF pod.

## Files (shipped in this repo)

| File | Role |
|------|------|
| `backup-job.yaml`   | Job template for a backup. `BackupOrchestrator.renderManifest` fills `${JOB_ID} ${SCOPE} ${TARGET} ${ENCRYPTED} ${LOCATION_REF}`. |
| `restore-job.yaml`  | Job template for a restore (`MODE=restore`). |
| `backup-worker.sh`  | The worker entrypoint: etcd snapshot / `pg_dump` / `rsync` / Secret+ConfigMap export, `tar` bundle, and **AES-256-CBC + PBKDF2 (210000 iters)** encrypt/decrypt via `openssl`. Mounted as a ConfigMap (`backup-worker-script`). |
| `rbac.yaml`         | ServiceAccount + (Cluster)Role(Binding)s — **apply once** (`kubectl apply -f rbac.yaml`). |

## Encryption (tool + KDF)

- **Tool:** `openssl enc -aes-256-cbc -pbkdf2 -iter 210000 -salt` (symmetric AES-256).
- **KDF:** PBKDF2-HMAC-SHA256, 210 000 iterations. The BFF uses the same algorithm and
  iteration count for its `backup_history` **verifier** (`BackupCrypto`). The BFF
  stores only the one-way verifier and its salt. The worker derives the AES key from
  the password, **inside the worker**, so the BFF never holds the data key.
- **Password delivery (the design; `applyJob` is still a no-op, see follow-up 2):**
  the BFF creates an **ephemeral Secret** `backup-pw-<id>` with an `ownerReference` to
  the Job, mounted read-only at `/run/backup/password`. It is garbage-collected when
  the Job is reaped (`ttlSecondsAfterFinished`, 3600 in `backup-job.yaml`). The
  password is never an env var, never in the manifest, never logged. Today nothing
  creates that Secret, because nothing applies the Job.
- **Wrong password on restore:** the BFF checks it against the stored PBKDF2 verifier
  **before** it applies the restore Job, and answers `403 incorrect decryption
  password`. On a mismatch the key is never derived or revealed.

## USB targeting

`GET /bff/admin/usb-devices` lists connected, mountable USB devices and the backups
found on them. Enumeration runs **on the node**: the worker or a node agent reads
`lsblk -J -o NAME,LABEL,MOUNTPOINT,SIZE,FSAVAIL,RO,TRAN` filtered to `TRAN=usb`. The
BFF pod cannot see host block devices. A `USB` backup or restore mounts the device at
`/mnt/usb`: the Job template mounts the node's `hostPath` `/mnt/hugmesh-usb` there.
The default `UsbDeviceProvider` returns an empty list until the node-agent endpoint is
wired. See *Implemented vs follow-up* below.

## Implemented in this repo vs. operator follow-up

**Implemented (BFF):** the full REST and SSE contract, scope, target and USB
validation, the PBKDF2 verifier and the wrong-password 403, the durable
`backup_history` lifecycle, the Job-manifest templating, and the worker script,
manifests and RBAC here.

**Operator follow-up (documented, not auto-applied):**
1. Apply `rbac.yaml` and create the `backup-worker-script` ConfigMap from
   `backup-worker.sh`, the `hugmesh-backup-staging` PVC, and build/publish the
   `backup-worker` image (etcdctl + kubectl + pg_dump + rsync + openssl).
2. Wire `BackupOrchestrator.applyJob` to the cluster (fabric8 or the official k8s
   client) so it `create`s the rendered Job and the ephemeral Secret and tails the pod
   log into the SSE stream. It is a no-op seam today (the dev/test BFF has no
   cluster), so the BFF drives the canonical phase progression instead.
3. Wire `UsbDeviceProvider` to the node-agent USB enumeration endpoint.
4. **etcd restore** is control-plane and intentionally left operator-gated (the
   worker logs a notice rather than restoring etcd in-place).

## Test-runner Job (Test-Reports console)

These resources back the admin **Test-Reports** console (`/bff/admin/test-reports`):
the test-architecture run list, report download, on-demand trigger and live SSE
progress.

| File | Role |
|------|------|
| `test-runner-job.yaml`  | Job template for a run. `TestRunOrchestrator.renderManifest` fills `${RUN_ID} ${TIER} ${COMMIT_SHA} ${TRIGGER_SOURCE}`. The runner image bundles the generator `tests/e2e` Playwright suite + `tests/qemu/seed-accounts.sh` (ENV=test only). |
| `test-runner-rbac.yaml` | ServiceAccount + Role(Binding) for the BFF to launch runner Jobs + the shared `hugmesh-test-reports` PVC — **apply once**. |

### REAL launch vs. backup's no-op seam

The backup `applyJob` is a documented **no-op**. The test-runner launch is **real**:
`Fabric8JobLauncher` applies the rendered Job with the fabric8 `KubernetesClient`
(already on the classpath via the spring-cloud-kubernetes leader starter). It is wired
**only** when `testreports.launch.enabled=true`. Otherwise the cluster-less
`NoopJobLauncher` runs (dev/test/CI), so the start → ingest → SSE → durable-status
contract works without a cluster. `/actuator/info` publishes whether the launch is
real (`testReports.launchReal`). The prod-hygiene gate reads that signal, because a
manifest scan cannot see a Java stub.

### REAL event-ingest path

The runner POSTs per-`(suite,role)` events back to
`POST /bff/admin/test-reports/${RUN_ID}/ingest`. The endpoint is admin-gated and
takes the runner's own pre-minted token from the `test-runner-ingest-token` Secret.
The orchestrator upserts the durable `test_run_result` matrix **and** fans an SSE
event out to live subscribers. The run-terminal event closes the `test_run` row. The
SSE replay buffer is **bounded** (`testreports.sse.replay-buffer`, default 256). An
admin who reconnects, or lands on a different replica or a restarted pod, recovers
full state from the durable matrix.

### Report storage + download (secrets scrubbed)

The runner writes the artifact bundle (`junit.xml`, `summary.json`, sanitized
`logs/`) to the shared `hugmesh-test-reports` PVC under
`<tier>/run-<ts>-<commit>/` and reports that path back as the run's `report_ref`.
`GET /{id}/download` streams it as a `tar.gz`. It resolves `report_ref` **under** the
PVC root (a `../` traversal or an absolute ref is a 400) and **re-scrubs** every text
entry through `ReportScrubber` on read, on top of the runner's write-time scrub.

### Operator follow-up (documented, not auto-applied)

1. Apply `test-runner-rbac.yaml` (SA + Role + report PVC), build/publish the
   `test-runner` image (Playwright + `seed-accounts.sh`), and create the
   `test-runner-ingest-token` Secret (a Casdoor client-credentials token scoped to
   the ingest path).
2. Flip `testreports.launch.enabled=true` (+ `testreports.launch.namespace` if the
   deployment relocates) so `Fabric8JobLauncher` applies Jobs for real.
3. The cluster orchestrator (hugmesh-generator `specs/cluster/apps/99-test-runner.yaml`)
   is the automated trigger for the LEAN (fe/be/pki-ready) and HEAVY (x86-attach)
   runs. The admin `POST /run` is the on-demand path. Both write the same `test_run`
   rows.

## Image-gen Job (image-build console)

These resources back the admin image-build console (`/bff/admin/image-builds`,
`/bff/internal/image-builds/{id}/ingest` and `/progress`).
`ImageBuildOrchestrator.renderManifest` fills the template, one Job per build.

| File | Role |
|------|------|
| `image-gen-job.yaml`       | Job template for one build. The runner writes the image and a non-secret keys bundle to the `hugmesh-image-artifacts` PVC under `build-<id>/`, and POSTs its terminal event to the ingest endpoint. |
| `image-gen-rbac.yaml`      | ServiceAccount `image-gen`, the launcher Role and RoleBinding for the BFF's ServiceAccount (`admin-bff`; adjust to your deployment), and the artifacts PVC — **apply once**. |
| `image-gen-admission.yaml` | A native `ValidatingAdmissionPolicy` that pins the BFF's ConfigMap writes to the `hugmesh-image-spec-` name prefix. RBAC cannot express a prefix. Needs Kubernetes 1.30 or later — **apply once**, after the RBAC. |

The launch is off by default. With `imagegen.launch.enabled=false` (env
`IMAGEGEN_LAUNCH_ENABLED`) the no-op `NoopImageJobLauncher` only logs, so no build
runs. Set it to `true` (and `imagegen.launch.namespace` if the deployment moves)
after the RBAC and the PVC exist. The per-device dial private key never enters the
manifest or the BFF: the generator writes it to Vault, and an ESO-synced Secret
carries it into the Job pod only.
