#!/usr/bin/env bash
#
# Starts the jSMB `run` harness (unless one is listening already) and mounts its share with the macOS SMB client.
#
# Prints three lines the caller needs:
#
#   SERVER=started|reused
#   LOG=<absolute path of the server log>        (empty when the server was reused, as its log is wherever it got started)
#   MOUNT=<absolute path of the mount point>     (or MOUNT-FAILED, followed by the command to mount by hand)
#
# Server log and mount point live in /private/tmp/claude/jsmb-macos-client. That keeps the mount out of the reach of
# `mvn clean` and `git clean`, and it is a location sandboxed commands may write to (the user's own temp dir is not).
#
# Has to run outside the sandbox: the sandbox blocks mount_smbfs and hides the listening server from lsof.
#
# Exit code: 0 if the share is mounted, 1 if the server didn't come up, 2 if mounting failed.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$REPO_ROOT"

PORT=4446
STATE_DIR=/private/tmp/claude/jsmb-macos-client
LOG="$STATE_DIR/server.log"
MOUNT="$STATE_DIR/mount"
MARKER="$STATE_DIR/started-by-skill"
# the credentials and the share name are those of RunIT
URL="//DOMAIN;user:password@localhost:$PORT/data"

mkdir -p "$MOUNT"
MOUNT="$(cd "$MOUNT" && pwd -P)"

# --- server -----------------------------------------------------------------------
if lsof -iTCP:$PORT -sTCP:LISTEN >/dev/null 2>&1; then
    echo "SERVER=reused"
    [ -f "$MARKER" ] && echo "LOG=$LOG" || echo "LOG="
else
    nohup ./mvnw -q verify -Prun -Djsmb.port=$PORT > "$LOG" 2>&1 < /dev/null &
    disown
    touch "$MARKER"
    # the harness runs the test suite before it binds the port
    for _ in $(seq 1 180); do
        lsof -iTCP:$PORT -sTCP:LISTEN >/dev/null 2>&1 && break
        sleep 1
    done
    if ! lsof -iTCP:$PORT -sTCP:LISTEN >/dev/null 2>&1; then
        echo "SERVER=failed to bind port $PORT within 180 s"
        echo "--- last lines of $LOG ---"
        tail -n 40 "$LOG" 2>/dev/null || echo "(no log)"
        rm -f "$MARKER"
        exit 1
    fi
    echo "SERVER=started"
    echo "LOG=$LOG"
fi

# --- mount ------------------------------------------------------------------------
if mount | grep -F -q " on $MOUNT (smbfs"; then
    echo "MOUNT=$MOUNT"
    exit 0
fi
if mount_smbfs "$URL" "$MOUNT"; then
    echo "MOUNT=$MOUNT"
    exit 0
fi
echo "MOUNT-FAILED"
echo "Mount by hand with:"
echo "  mount_smbfs '$URL' '$MOUNT'"
exit 2
