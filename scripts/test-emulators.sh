#!/usr/bin/env bash
# Run the full test suite with the cloud adapters certified against local
# emulators: MinIO (S3 API), Azurite (Azure Blob), fake-gcs-server (GCS native).
# Requires Docker. `bun run test:emulators`.
set -euo pipefail
cd "$(dirname "$0")/.."

cleanup() { docker rm -f shlep-azurite shlep-minio shlep-fakegcs >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup

echo "starting emulators…"
docker run -d --name shlep-azurite -p 10000:10000 mcr.microsoft.com/azure-storage/azurite \
  azurite-blob --blobHost 0.0.0.0 --blobPort 10000 --skipApiVersionCheck >/dev/null
docker run -d --name shlep-minio -p 9000:9000 \
  -e MINIO_ROOT_USER=minioadmin -e MINIO_ROOT_PASSWORD=minioadmin \
  minio/minio server /data >/dev/null
docker run -d --name shlep-fakegcs -p 4443:4443 fsouza/fake-gcs-server \
  -scheme http -port 4443 -external-url http://127.0.0.1:4443 -backend memory >/dev/null

wait_for() { # url name
  for _ in $(seq 1 60); do
    [ "$(curl -s -o /dev/null -w '%{http_code}' "$1" 2>/dev/null || echo 000)" != "000" ] && { echo "  $2 ready"; return 0; }
    sleep 1
  done
  echo "  $2 did not become ready"; return 1
}
wait_for "http://127.0.0.1:9000/minio/health/live" minio
wait_for "http://127.0.0.1:10000/devstoreaccount1" azurite
wait_for "http://127.0.0.1:4443/storage/v1/b?project=test" fake-gcs

echo "running full suite against emulators…"
SHLEP_TEST_S3=1 SHLEP_TEST_AZURE=1 SHLEP_TEST_GCS=1 bun test
