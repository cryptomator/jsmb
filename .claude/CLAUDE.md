# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

A partial SMB server implementation in Java. Only SMB dialect **3.1.1** is supported; SMB1 is parsed solely to honor the initial multi-protocol negotiate handshake and hand off to SMB2. The project targets **Java 22 with preview features** and uses the Foreign Function & Memory API (`MemorySegment`) for zero-copy packet parsing.

## Build & Test

Maven project. Common commands:

```bash
./mvnw compile               # build
./mvnw test                  # unit tests only (*Test classes, via surefire)
./mvnw verify                # unit tests + integration tests (*IT classes, via failsafe)
./mvnw test -Dtest=ClassName                    # single unit test class
./mvnw test -Dtest=ClassName#methodName         # single unit test method
./mvnw verify -Dit.test=ClassName               # single integration test class
./mvnw package               # build jar (also runs javadoc + source jar)
```

Integration tests are named `*IT` and drive `smbj` against an in-process `TcpServer`. They run in the `integration-test` / `verify` phases via the failsafe plugin — **run `./mvnw verify` before declaring a milestone done, not just `./mvnw test`**.

A separate harness drives Samba's `smbclient` from a Podman container against the same `TcpServer`; scenarios live under [`../interop/scenarios/`](../interop/scenarios/) (one `.txt` file per command, e.g. `read.txt`, `mkdir.txt`). **When you implement a new SMB command, also run the relevant `interop/` scenarios (and add a new scenario if none covers the feature) before declaring the milestone done.** Run them via the `/interop-scenario` skill — don't hand-roll the harness invocation. See [`../interop/README.md`](../interop/README.md) for scenario authoring conventions.

Running main classes directly requires the same JVM flags surefire uses: `--enable-preview --add-reads org.cryptomator.jsmb=java.security.sasl`.

## Architecture

The project-root [`README.md`](../README.md) has a full "Architecture" section (request flow, state hierarchy, `MemorySegment` parsing, backend SPI, negotiate contexts, NTLMv2 auth, signing + encryption, contributor conventions). **Read it before making non-trivial changes** — its content is the source of truth for "why is it shaped this way?" and lists the invariants contributors need to preserve.

## Working rules

- **No new dependencies without approval.** If you believe a new dependency would be beneficial, ask first — do not add it to `pom.xml` unilaterally.
- **Small incremental commits.** For any non-trivial change, draft a plan first that breaks the work into small, individually committable steps and confirm it before implementing.
- **One SMB request/response at a time.** Implement the protocol incrementally, one command at a time. Always cross-reference the official spec at <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2> — especially for exact byte layouts, field offsets, and handling rules.
- **Integration-test with `smbj`.** The project leans on integration tests that drive a real SMB client (`com.hierynomus:smbj`) against an in-process `TcpServer`. Use JUnit 5 `@TestMethodOrder(OrderAnnotation.class)` with `@Order` on methods, and put connection setup and authentication in a `@BeforeAll` method so ordered tests share the same session.
- **Every `@Test` method carries a `@DisplayName`.** Use a short human-readable sentence that describes the behaviour under test (e.g. `@DisplayName("FSCTL_VALIDATE_NEGOTIATE_INFO is rejected with STATUS_FILE_CLOSED")`). This applies to unit tests and integration tests alike, including `@ParameterizedTest`.
- **Stop at milestone boundaries.** After finishing a milestone, stop and wait for human review. Do not start the next milestone without explicit consent.

## Conventions

- Specs are linked inline via `@see <a href="https://learn.microsoft.com/...">` Javadoc — preserve these when editing; they are the source of truth for behavior.
- **Wire-format types are records, usually `MemorySegment`-backed.** Every binary structure that travels on the SMB wire — packet headers, request/response bodies, create contexts, info-class payloads, etc. — lives as a record. The default shape is `record X(MemorySegment segment, ...)` with accessors that read and write through `util.Layouts`; parsed-field records (like `FileId`, `record X(long a, long b)` with a `writeTo(MemorySegment)` / `fromSegment(MemorySegment)` pair) are fine for small fixed-size values where structural equality or parsed ergonomics matter more than zero-copy. Construct instances via static factory methods on the record — not via utility classes with `static byte[] encode(...)` helpers or POJOs holding duplicated state. The record IS the wire format.
- Keep `Connection` / `Session` state field names aligned with MS-SMB2 (e.g. `preauthIntegrityHashValue`, `clientCapabilities`) so cross-referencing the spec stays trivial.
- Route every new SMB field accessor through `util.Layouts` — don't introduce ad-hoc `ByteOrder` plumbing.
