#!/usr/bin/env bash
# unlock.sh: the nested harness's secrets (pveforge-harness-secrets-unlock).
#
#   unlock.sh run [--] <cmd> [args...]   exec <cmd> with the secrets in its env
#   unlock.sh seal | reseal | status
#
# The identity comes from exactly one of PVEFORGE_HARNESS_AGE_IDENTITY_FILE
# (a file, mode 0600 or 0400) and PVEFORGE_HARNESS_AGE_IDENTITY (its content).
# All the work is done by the Go helper cmd/pveforge-harness-secrets, built
# here and then exec'd (never `go run`, which loses the exit status). No
# secret passes through this script: not in a variable, a file or argv.
set -euo pipefail

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
root=$(cd -- "$here/../.." && pwd)
bin="${XDG_CACHE_HOME:-$HOME/.cache}/pveforge-harness/pveforge-harness-secrets"
mkdir -p -- "$(dirname -- "$bin")"
(cd -- "$root" && go build -o "$bin" ./cmd/pveforge-harness-secrets)
exec "$bin" --dir "$here" "$@"
