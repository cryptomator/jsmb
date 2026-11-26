#!/usr/bin/env bash
#
# Counterpart of start.sh: unmounts the share and stops the jSMB harness, if start.sh was what started it.
#
# Has to run outside the sandbox, like start.sh.
#
# Usage: stop.sh [--force]    --force unmounts even while files are open, which the server sees as a lost connection
#
# Exit code: 0 if nothing is mounted any more, 1 if unmounting failed.

set -u

PORT=4446
STATE_DIR=/private/tmp/claude/jsmb-macos-client
MOUNT="$STATE_DIR/mount"
MARKER="$STATE_DIR/started-by-skill"

status=0
if [ -d "$MOUNT" ]; then
    MOUNT="$(cd "$MOUNT" && pwd -P)"
    if mount | grep -F -q " on $MOUNT (smbfs"; then
        if [ "${1:-}" = "--force" ]; then
            umount -f "$MOUNT"
        else
            umount "$MOUNT"
        fi
        if mount | grep -F -q " on $MOUNT (smbfs"; then
            echo "UNMOUNT=failed, $MOUNT is still mounted (retry with --force)"
            status=1
        else
            echo "UNMOUNT=done"
        fi
    else
        echo "UNMOUNT=not mounted"
    fi
fi

if [ "$status" -eq 0 ] && [ -f "$MARKER" ]; then
    pid="$(lsof -iTCP:$PORT -sTCP:LISTEN -t 2>/dev/null || true)"
    if [ -n "$pid" ]; then
        kill -TERM $pid 2>/dev/null || true
        sleep 2
    fi
    rm -f "$MARKER"
    lsof -iTCP:$PORT -sTCP:LISTEN >/dev/null 2>&1 && echo "SERVER=still listening on port $PORT" || echo "SERVER=stopped"
elif [ "$status" -eq 0 ]; then
    echo "SERVER=left alone (not started by start.sh)"
fi
exit $status
