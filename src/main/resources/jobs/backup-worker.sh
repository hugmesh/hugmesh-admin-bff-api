#!/usr/bin/env sh
# ---------------------------------------------------------------------------
# HugMesh admin backup/restore worker.
#
# Runs INSIDE the templated Kubernetes Job (jobs/backup-job.yaml /
# jobs/restore-job.yaml) launched by the admin BFF. It performs the actual data
# movement for the requested scopes and (optionally) AES-256 encryption.
#
# The BFF passes configuration via env (from the Job template) and — for an
# encrypted job — the password via the file $PASSWORD_FILE, mounted from an
# EPHEMERAL Kubernetes Secret that is garbage-collected with the Job (the
# password is NEVER an env var, NEVER an argv, NEVER logged).
#
# Encryption: openssl enc -aes-256-cbc -pbkdf2 -iter 210000 -salt, keyed from the
# password via PBKDF2 (matches the platform crypto direction: AES-256 + strong
# KDF, and the same iteration count as the BFF's PBKDF2 verifier). Decryption on
# restore is the symmetric `-d`.
#
# Env (set by the Job template):
#   JOB_ID        backup/restore id (used in the artifact name + log lines)
#   MODE          "backup" | "restore"
#   SCOPE         comma list: etcd,secrets,postgres,pvc,config
#   TARGET        "CLUSTER" | "USB"
#   ENCRYPTED     "true" | "false"
#   LOCATION_REF  restore source ref (restore mode) / output hint (backup mode)
#   USB_MOUNT     mount path of the connected USB device (TARGET=USB)
#   CLOUD_DIR     in-cluster/cloud staging dir (TARGET=CLUSTER)
#   PG_HOST/PG_USER/PGDATABASE  Postgres connection (scope=postgres)
#   PVC_SRC       mounted PVC path to rsync (scope=pvc)
#   PASSWORD_FILE path to the mounted password (ENCRYPTED=true) — read, never echoed
# ---------------------------------------------------------------------------
set -eu

log() { echo "[$(date -u +%FT%TZ)] [$JOB_ID] $*"; }
fail() { log "ERROR: $*"; exit 1; }

OUT_DIR="${CLOUD_DIR:-/work}"
[ "${TARGET:-CLUSTER}" = "USB" ] && OUT_DIR="${USB_MOUNT:?USB_MOUNT required for USB target}"
STAGE="$(mktemp -d)"
ART="hugmesh-backup-${JOB_ID}.tar"

read_password() {
  # Read the password from the mounted Secret file ONLY. Fail closed.
  [ -n "${PASSWORD_FILE:-}" ] && [ -f "$PASSWORD_FILE" ] || fail "encrypted job but no PASSWORD_FILE"
  cat "$PASSWORD_FILE"
}

backup_scope() {
  scope="$1"
  case "$scope" in
    etcd)
      log "phase=etcd snapshotting etcd"
      ETCDCTL_API=3 etcdctl snapshot save "$STAGE/etcd.db" \
        --endpoints="${ETCD_ENDPOINTS:-https://127.0.0.1:2379}" \
        --cacert="${ETCD_CACERT:-}" --cert="${ETCD_CERT:-}" --key="${ETCD_KEY:-}" \
        || fail "etcd snapshot failed" ;;
    secrets)
      log "phase=secrets exporting Kubernetes Secrets"
      kubectl get secrets --all-namespaces -o yaml > "$STAGE/secrets.yaml" || fail "secrets export failed" ;;
    config)
      log "phase=config exporting ConfigMaps"
      kubectl get configmaps --all-namespaces -o yaml > "$STAGE/config.yaml" || fail "config export failed" ;;
    postgres)
      log "phase=postgres pg_dump"
      pg_dump -h "${PG_HOST:?}" -U "${PG_USER:?}" "${PGDATABASE:?}" > "$STAGE/postgres.sql" || fail "pg_dump failed" ;;
    pvc)
      log "phase=pvc rsync PVC data"
      rsync -a "${PVC_SRC:?}/" "$STAGE/pvc/" || fail "pvc rsync failed" ;;
    *) fail "unknown scope: $scope" ;;
  esac
}

restore_scope() {
  scope="$1"
  case "$scope" in
    postgres) log "phase=postgres restoring"; psql -h "${PG_HOST:?}" -U "${PG_USER:?}" "${PGDATABASE:?}" < "$STAGE/postgres.sql" ;;
    pvc)      log "phase=pvc restoring";      rsync -a "$STAGE/pvc/" "${PVC_SRC:?}/" ;;
    secrets)  log "phase=secrets restoring";  kubectl apply -f "$STAGE/secrets.yaml" ;;
    config)   log "phase=config restoring";   kubectl apply -f "$STAGE/config.yaml" ;;
    etcd)     log "phase=etcd restore is operator-gated (control-plane); see jobs/README.md" ;;
    *) fail "unknown scope: $scope" ;;
  esac
}

do_backup() {
  IFS=','; for s in $SCOPE; do backup_scope "$s"; done; unset IFS
  log "phase=archive bundling artifact"
  tar -C "$STAGE" -cf "$STAGE/$ART" .
  if [ "${ENCRYPTED:-false}" = "true" ]; then
    log "phase=encrypt AES-256-CBC (PBKDF2, 210000 iters)"
    openssl enc -aes-256-cbc -pbkdf2 -iter 210000 -salt \
      -in "$STAGE/$ART" -out "$OUT_DIR/$ART.enc" -pass file:"$(read_password >/dev/null; echo "$PASSWORD_FILE")"
    rm -f "$STAGE/$ART"
    log "phase=complete wrote $OUT_DIR/$ART.enc"
  else
    cp "$STAGE/$ART" "$OUT_DIR/$ART"
    log "phase=complete wrote $OUT_DIR/$ART"
  fi
}

do_restore() {
  SRC="${LOCATION_REF:?restore needs LOCATION_REF}"
  if [ "${ENCRYPTED:-false}" = "true" ]; then
    log "phase=decrypt AES-256-CBC"
    openssl enc -d -aes-256-cbc -pbkdf2 -iter 210000 \
      -in "$SRC" -out "$STAGE/$ART" -pass file:"$PASSWORD_FILE" \
      || fail "decryption failed (wrong password?)"
  else
    cp "$SRC" "$STAGE/$ART"
  fi
  tar -C "$STAGE" -xf "$STAGE/$ART"
  IFS=','; for s in $SCOPE; do restore_scope "$s"; done; unset IFS
  log "phase=complete restore finished"
}

log "start mode=${MODE:?} scope=$SCOPE target=${TARGET:-CLUSTER} encrypted=${ENCRYPTED:-false}"
case "${MODE}" in
  backup)  do_backup ;;
  restore) do_restore ;;
  *) fail "MODE must be backup|restore" ;;
esac
log "done"
