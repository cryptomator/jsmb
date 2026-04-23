# Interop testing with Samba's `smbclient`

Manual, scriptable harness for driving jSMB from Samba's reference client. Designed to augment — not replace — the automated `smbj`-driven integration tests in `src/test/java/`. Gated on a Maven profile so a plain `mvn test` and CI both skip it.

## Layout

```
interop/
├── README.md                  # this file
├── run-samba-scenario.sh      # wrapper that pipes a scenario to smbclient in Podman
└── scenarios/
    ├── smoke.txt              # connect + disconnect smoke test
    ├── mkdir.txt              # directory creation round-trip (needs M5)
    └── ls.txt                 # forward-looking — returns NT_STATUS_NOT_SUPPORTED until M6 lands
```

## Prerequisites

- **Podman.** On macOS / Windows run `podman machine init && podman machine start` once. Linux users just need the `podman` binary.
- **Java 25 + Maven** to start the jSMB harness.

## One-time setup

The first invocation of `run-samba-scenario.sh` builds a small local image (alpine + `samba-client`) tagged `localhost/jsmb-smbclient:latest` and caches it. Subsequent runs reuse it.

## Running a scenario

1. **Start the harness** in a terminal (port 4446, encryption + signing + `DEBUG_ENCRYPTION` enabled, share `data` backed by a fresh `@TempDir`, blocks on `stdin`). Port 4446 avoids the usual 4445 collision with macOS's `upnotifyp`:
   ```bash
   mvn verify -Psamba-harness
   ```
2. **In another terminal, run a scenario against it.** The wrapper auto-selects Linux (`--network host`) vs. macOS/Windows (`host.containers.internal`) networking:
   ```bash
   # Run a named scenario from interop/scenarios/
   ./interop/run-samba-scenario.sh smoke.txt

   # Run an ad-hoc scenario from a heredoc (handy for quick regression probes)
   ./interop/run-samba-scenario.sh <<'EOF'
   mkdir quick-check
   mkdir quick-check\nested
   exit
   EOF

   # Or pipe from any file
   ./interop/run-samba-scenario.sh < /tmp/my-scenario.txt
   ```
3. **Inspect the output.** Pair `SAMBA_DEBUG=10` (Samba's max debug verbosity) with the server's `DEBUG_ENCRYPTION` log for end-to-end cross-referencing. Every command that hits a feature jSMB hasn't implemented yet surfaces as `NT_STATUS_NOT_SUPPORTED` (or a more specific code) — that's how you spot regressions in milestones that *are* supposed to work.
4. **Stop the server** by hitting Enter (or `Ctrl-D`) in the terminal running step 1.

## Authoring scenarios

Scenario files are plain text — one `smbclient` command per line. Lines starting with `#` (optionally after whitespace) and blank lines are stripped before being piped to `smbclient`, so scenarios can self-document:

```txt
# Exercises M5 (CREATE/CLOSE). `mkdir` uses FILE_DIRECTORY_FILE + FILE_CREATE internally.
mkdir foo
mkdir foo\nested
exit
```

The `smbclient` command set is documented in `man smbclient`; common commands are `ls`, `cd <path>`, `mkdir <dir>`, `rmdir <dir>`, `get <remote> [local]`, `put <local> [remote]`, `rm <file>`, `rename <old> <new>`, `exit` / `q`.

## Headless / agent usage (no second terminal)

`SambaClientIT` blocks on a `CountDownLatch` released by a JVM shutdown hook, so signalling the forked test JVM (SIGTERM / SIGINT) shuts the harness down cleanly.

```bash
# 1. Background the harness.
mvn -q verify -Psamba-harness > /tmp/jsmb-harness.log 2>&1 &

# 2. Wait until the server starts listening (usually ≤ 1–2 s on a warm build).
until lsof -iTCP:4446 -sTCP:LISTEN >/dev/null 2>&1; do sleep 1; done

# 3. Run a scenario and inspect the output.
./interop/run-samba-scenario.sh smoke.txt
# grep for NT_STATUS_* in stdout; expect at most NT_STATUS_INVALID_PARAMETER from
# smbclient's Kerberos pre-flight (we offer NTLM only — safe to ignore).

# 4. Optionally cross-check the server side.
grep -E 'TREE_CONNECT|CREATE|Session-' /tmp/jsmb-harness.log

# 5. Tear down. Signal the surefire-forked JVM directly (Maven's SIGTERM handler
#    doesn't cascade to the forked JVM; the fork is what owns the shutdown hook).
kill -TERM "$(lsof -iTCP:4446 -sTCP:LISTEN -t)"
```

Interactively, a terminal `Ctrl-C` works because it sends SIGINT to the whole process group — the forked JVM gets its own copy of the signal and its shutdown hook fires in parallel with Maven's own cleanup.

If `lsof` isn't available, `pkill -TERM -f 'surefirebooter.*jSMB'` matches the forked JVM by its booter jar path (scoped to our project so other concurrent Maven builds aren't affected).

## Tunables

All configurable via env vars; defaults match the `samba-harness` Maven profile:

| Variable      | Default                           | Purpose                                   |
|---------------|-----------------------------------|-------------------------------------------|
| `SAMBA_PORT`  | `4446`                            | Port the jSMB harness listens on          |
| `SAMBA_SHARE` | `data`                            | Share name registered by the harness      |
| `SAMBA_USER`  | `DOMAIN/user%password`            | `smbclient -U` spec                       |
| `SAMBA_DEBUG` | `3`                               | `smbclient -d` level (0–10; 10 = max)     |
| `SAMBA_IMAGE` | `localhost/jsmb-smbclient:latest` | Podman image; auto-built if absent        |

Example: `SAMBA_DEBUG=10 ./interop/run-samba-scenario.sh mkdir.txt` runs the scenario with full Samba debug logging.

## Expected failures by milestone

Some `smbclient` probes will error out until the corresponding server milestones land:

- Named-pipe RPC on `IPC$` (e.g. `SRVSVC`): requires a pipe dispatcher (not on the roadmap).
- Directory listing (`ls`): requires **M6** (`QUERY_DIRECTORY`).
- Write (`put`): requires **M9**.
- Rename / delete (`rename`, `rm`, `rmdir`): require **M10** (`SET_INFO`).
- Change notifications: returns `STATUS_NOT_SUPPORTED` by design.

None of these are regressions — they're the roadmap.
