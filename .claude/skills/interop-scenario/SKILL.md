---
name: interop-scenario
description: Run one or more interop scenarios against the jSMB `run` harness — boots the harness in the background, waits for port 4446, runs the scenario(s), emits the server log, and tears down cleanly. Use when the user asks to "run the interop", "run interop <name>", "verify with smbclient", or after implementing a new SMB command to exercise it through Samba's reference client.
---

# Run an interop scenario

Delegates the whole dance to `.claude/skills/interop-scenario/run.sh`. The script boots the harness, waits for the port, runs each scenario, dumps the server log, and tears down — emitting a single stdout stream with `=== section: … ===` markers so this assistant can split and analyze it.

## Inputs

- **`$scenario`** — one or more scenario names from `interop/scenarios/` (e.g. `smoke`, `read`, `query-info`). Default to `smoke` if the user didn't name one. The `.txt` extension is optional.

## Procedure

Invoke the runner with the scenario names as positional arguments. It produces everything you need in one stdout stream:

```bash
.claude/skills/interop-scenario/run.sh read write rm
```

The script emits (in order):

- `=== starting harness on port 4446 ===` (or `=== reusing already-running harness ===`)
- `=== scenario: <name> ===` followed by the **unfiltered** stdout/stderr of `interop/run-samba-scenario.sh <name>`, one block per scenario
- `=== server log (/tmp/jsmb-harness.log) ===` followed by the **full** server log (unfiltered)
- `=== teardown ===` with `port 4446 clear` (only if this invocation started the harness)

Output is verbatim by design — grep what you need in the analysis step rather than relying on the script to pre-filter. In particular:

- Client output (`smbclient`): `NT_STATUS_INVALID_PARAMETER` from `gensec_gse_client_start` is the Kerberos pre-flight failing (we offer NTLM only) and is always present; any other `NT_STATUS_*` code is what you care about.
- Server log: filter by handler class (e.g. `CreateHandler`, `WriteHandler`, `QueryDirectoryHandler`), by `ERROR` / `WARN`, or by `STATUS_` to find status codes emitted server-side.

Exit code: 0 on normal completion, 1 if the harness failed to bind the port within 60 s (the full log is dumped to stderr on that path).

## Reporting

Summarize for the user:

- **Client side**: what `smbclient` printed for each scenario — successful `get` / `put` lines, `NT_STATUS_*` codes, directory listings.
- **Server side**: the relevant handler / error lines that correspond to the client-side operations.
- **Result**: which scenario(s) ran, what jSMB observably handled, any unexpected status codes, any exceptions in the server log.

## Gotchas

- The `@TempDir` backing the share **persists for the harness's lifetime**, not per scenario. Subsequent scenarios see directories created by earlier ones — normal, occasionally surfaces as `NT_STATUS_OBJECT_NAME_COLLISION` on repeated `mkdir`.
- `smbclient` mixes stdout and stderr; debug messages (`dos_clean_name`, `unix_clean_name`) interleave unpredictably with command output. Trust the server log for authoritative ordering, use the client output for the final human-readable result of each command.
- Samba's `smbclient` rarely emits compound SMB2 requests on its own — interop coverage of compound-handling is limited to scenarios `interop/README.md` explicitly flags. For compound-specific regressions, prefer the smbj `*IT` tests or a captured-replay unit test.
- If port 4446 is already bound by something other than a previous harness, the script will treat it as "already running" and proceed; make sure nothing else on the box is listening there.

## When to skip this skill

- Pure unit-test verification → `./mvnw test` or `./mvnw test -Dtest=ClassName` directly.
- Pure smbj-driven integration-test verification → `./mvnw verify` directly.
- Reproducing a Finder/Explorer-specific bug → these clients produce compound SMB2 that `smbclient` doesn't; you need a captured replay or the real client, not this harness.
