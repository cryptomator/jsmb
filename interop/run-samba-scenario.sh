#!/usr/bin/env bash
# Run an smbclient scenario against a running jSMB harness.
#
# Start jSMB first in another terminal:   ./mvnw verify -Psamba-harness
#
# Usage (from anywhere):
#   interop/run-samba-scenario.sh                      # read commands from stdin
#   interop/run-samba-scenario.sh smoke.txt            # resolved under interop/scenarios/
#   interop/run-samba-scenario.sh path/to/scenario.txt # absolute or relative-to-cwd path
#   interop/run-samba-scenario.sh <<'EOF'              # heredoc
#   ls
#   mkdir foo
#   exit
#   EOF
#
# Lines starting with `#` (optionally after whitespace) and blank lines are stripped before the
# input is piped to smbclient, so scenario files can carry comments.
#
# Tunables (env vars):
#   SAMBA_PORT   (default 4445)                         # port the jSMB harness listens on
#   SAMBA_SHARE  (default data)                         # share name registered by the harness
#   SAMBA_USER   (default DOMAIN/user%password)         # smbclient -U spec
#   SAMBA_DEBUG  (default 3)                            # smbclient -d level (0-10)
#   SAMBA_IMAGE  (default localhost/jsmb-smbclient)     # Podman image; auto-built if absent

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCENARIO_DIR="$SCRIPT_DIR/scenarios"
PORT="${SAMBA_PORT:-4445}"
SHARE="${SAMBA_SHARE:-data}"
USER_SPEC="${SAMBA_USER:-DOMAIN/user%password}"
DEBUG_LEVEL="${SAMBA_DEBUG:-3}"
IMAGE="${SAMBA_IMAGE:-localhost/jsmb-smbclient:latest}"

# Resolve the scenario input, if any, and redirect it onto our stdin.
if [[ $# -ge 1 && "$1" != "-" ]]; then
    scenario="$1"
    if [[ ! -f "$scenario" && -f "$SCENARIO_DIR/$scenario" ]]; then
        scenario="$SCENARIO_DIR/$scenario"
    fi
    if [[ ! -f "$scenario" ]]; then
        echo "scenario not found: $1 (looked at \$1 and $SCENARIO_DIR/$1)" >&2
        exit 2
    fi
    exec < "$scenario"
fi

# OS-specific Podman networking: Linux can use the host network stack directly; macOS/Windows run
# Podman inside a VM and reach the host via the auto-resolved host.containers.internal hostname.
case "$(uname -s)" in
    Linux*)
        NETWORK_ARGS=(--network host)
        HOST="localhost"
        ;;
    *)
        NETWORK_ARGS=()
        HOST="host.containers.internal"
        ;;
esac

# Build the smbclient image once, reuse thereafter.
if ! podman image exists "$IMAGE" >/dev/null 2>&1; then
    echo "building $IMAGE (one-time setup)..." >&2
    podman build -t "$IMAGE" - >&2 <<'DOCKERFILE'
FROM docker.io/library/alpine:latest
RUN apk add --no-cache samba-client
ENTRYPOINT ["smbclient"]
DOCKERFILE
fi

# Strip comment-only / blank lines, pipe to smbclient in the container.
# `${NETWORK_ARGS[@]+"${NETWORK_ARGS[@]}"}` expands to nothing on macOS where the array is empty,
# without tripping `set -u` (as bare `"${NETWORK_ARGS[@]}"` does on older bash).
grep -vE '^\s*(#|$)' | podman run --rm -i ${NETWORK_ARGS[@]+"${NETWORK_ARGS[@]}"} "$IMAGE" \
    -d "$DEBUG_LEVEL" -p "$PORT" -U "$USER_SPEC" "//$HOST/$SHARE"
