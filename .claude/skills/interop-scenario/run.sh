#!/usr/bin/env bash
#
# One-shot runner for the interop-scenario skill. Given one or more scenario names
# (e.g. `smoke`, `read`, `write`), this:
#
#   1. Boots the jSMB `run` harness on port 4446 in the background, if not already running.
#   2. Waits for the port to bind (up to 60 s cold build).
#   3. Runs each scenario via interop/run-samba-scenario.sh and emits its stdout/stderr verbatim.
#   4. Dumps the server-side log verbatim so the caller can correlate client and server output.
#   5. Tears the harness down cleanly (only if *we* started it; a pre-existing one is left alone).
#
# The output is a single stdout stream with `=== section: … ===` markers so the caller can split
# it and grep the parts it cares about. No filtering is performed here — premature filtering
# would drop lines the caller may want later (e.g. Wireshark decryption-keys dumps, stack traces
# without an obvious keyword, STATUS_SUCCESS handler lines, …).
#
# Exit code: 0 on normal completion, 1 if the harness failed to bind.
#
# Usage: run.sh <scenario>[.txt] [<scenario>[.txt] …]

set -u
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$REPO_ROOT"

PORT=4446
LOG=/tmp/jsmb-harness.log
SCENARIOS=("$@")
if [ ${#SCENARIOS[@]} -eq 0 ]; then
    SCENARIOS=(smoke)
fi

# --- start harness (or reuse an already-running one) ----------------------------
started_harness=0
if ! lsof -iTCP:$PORT -sTCP:LISTEN >/dev/null 2>&1; then
    echo "=== starting harness on port $PORT ==="
    ./mvnw -q verify -Prun -Djsmb.port=$PORT > "$LOG" 2>&1 &
    started_harness=1
    for _ in $(seq 1 60); do
        if lsof -iTCP:$PORT -sTCP:LISTEN >/dev/null 2>&1; then
            break
        fi
        sleep 1
    done
    if ! lsof -iTCP:$PORT -sTCP:LISTEN >/dev/null 2>&1; then
        echo "=== harness failed to bind port $PORT within 60 s ==="
        echo "--- full $LOG ---"
        cat "$LOG" 2>/dev/null || echo "(no log)"
        exit 1
    fi
else
    echo "=== reusing already-running harness on port $PORT ==="
fi

cleanup() {
    if [ "$started_harness" -eq 1 ]; then
        echo
        echo "=== teardown ==="
        pid="$(lsof -iTCP:$PORT -sTCP:LISTEN -t 2>/dev/null || true)"
        if [ -n "$pid" ]; then
            kill -TERM "$pid" 2>/dev/null || true
        fi
        sleep 2
        lsof -iTCP:$PORT -sTCP:LISTEN >/dev/null 2>&1 && echo "port $PORT still bound" || echo "port $PORT clear"
    fi
}
trap cleanup EXIT

# --- run scenarios (verbatim stdout, no filtering) ------------------------------
for name in "${SCENARIOS[@]}"; do
    stem="${name%.txt}"
    # run-samba-scenario.sh resolves scenario filenames verbatim against interop/scenarios/ — it
    # does NOT auto-append .txt. Normalise here so callers can pass either form.
    [ "${name%.txt}" = "$name" ] && name="$name.txt"
    echo
    echo "=== scenario: $stem ==="
    SAMBA_PORT=$PORT ./interop/run-samba-scenario.sh "$name" 2>&1
done

# Give the server a beat to flush the last log lines for the final scenario.
sleep 1

# --- server-side log (verbatim) -------------------------------------------------
echo
echo "=== server log ($LOG) ==="
cat "$LOG" 2>/dev/null || echo "(no log at $LOG)"
