# jSMB

A basic SMB server implementation in Java, targeting SMB dialect **3.1.1**.

**Status:** work in progress — not yet production-ready.

## Build

Maven project, Java 25.

```bash
./mvnw verify           # run all unit + integration tests
./mvnw package        # build jar
```

## Embedding

Register shares via the public SPI (`org.cryptomator.jsmb.share`) before (or after) starting the server:

```java
try (var server = TcpServer.start(4445)) {
    server.registerShare("data", new MySmbShare());
    // server runs in background; close() shuts it down.
}
```

A minimal reference implementation over `java.nio.file.Path` lives in `src/test/java/org/cryptomator/jsmb/share/nio/NioShare.java`.
It is **test-only** and intentionally happy-path — production-grade backends are out of scope for this library.

## Architecture

### Request flow

1. `TcpServer` (entry point) accepts TCP connections and dispatches each to a **virtual thread** running `TcpConnection`.
2. `TcpConnection.run()` reads the 4-byte big-endian NetBIOS transport header (length), reads the message payload, and dispatches on the protocol ID:
   - If the bytes start with an SMB2 `TRANSFORM_HEADER` (`0xFD 'SMB'`), the payload is decrypted in place using the session's decryption key before dispatch.
   - `SMB1MessageParser.isSmb1` / `SMB2MessageParser.isSmb2` then discriminate the plaintext.
   - SMB1 only handles `SmbComNegotiateRequest` (multi-protocol negotiate → upgrade to SMB2) via `SMB1Negotiator`.
   - SMB2 loops over chained (`nextCommand`) commands, dispatched via a pattern-match switch to `Negotiator`, `Runtime`, `TreeConnectHandler`, `CreateHandler`, `IoctlHandler`, or — for not-yet-implemented commands — an `UnhandledRequest` that gets a `STATUS_NOT_SUPPORTED` reply (keeps the connection alive so clients can probe optional commands without a TCP reset).
3. Each response passes through `TcpConnection.sign(...)` (MS-SMB2 3.3.4.1.5 signing decision tree) and then `TcpConnection.maybeEncrypt(...)` (MS-SMB2 3.3.4.1.4 encryption decision — which also **mirrors the request's encryption state**, so a client-encrypted request gets an encrypted response even when `Session.EncryptData` is false).

### State hierarchy

Three layers of state mirror MS-SMB2's "Per …" sections:

- `smb2.Global` — server-wide. Holds the session table, the registered shares map (case-insensitive), and the behavioural toggles derived from `Config` (`encryptData`, `rejectUnencryptedAccess`, `requireMessageSigning`, `debugEncryption`). One instance per `TcpServer`.
- `smb2.Connection` — per TCP connection. Holds negotiated dialect, client/server capabilities, cipher ID, signing algorithm, preauth integrity hash chain, and its own `sessionTable`.
- `smb2.Session` — per authenticated SMB session. Holds `sessionKey` and the five keys derived from it via `NistSP800108KDF` (`signingKey`, `applicationKey`, `encryptionKey`, `decryptionKey`), NTLM session state, the preauth integrity hash snapshot, `openTable: Map<FileId, Open>`, `treeConnectTable: Map<Integer, TreeConnect>`, and a per-session `nextTreeId` allocator.

### Packet parsing via `MemorySegment`

SMB2 messages are **not** deserialised into POJOs. Records like `PacketHeader`, `NegotiateRequest`, `TreeConnectResponse`, `CreateResponse` wrap a `java.lang.foreign.MemorySegment` and expose typed accessors that read/write the backing bytes directly using `ValueLayout` constants from `util.Layouts` (`LE_UINT16`, `LE_INT32`, `LE_INT64`, `BE_INT32`, `BE_INT64`). Little-endian is SMB-on-the-wire; big-endian is only the NetBIOS transport header. Builders (e.g. `PacketHeaderBuilder`) assemble outgoing messages; `copy()` on a header returns a builder preloaded with existing fields for immutable-style modification.

### Backend SPI (`org.cryptomator.jsmb.share`)

Embedders plug a filesystem-like backend in via the `SmbShare` / `SmbOpen` interfaces, with value records `FileBasicInfo`, `FileStandardInfo`, `DirEntry`, `FsAttributes`, `FsSize`, and `OpenParams` (with a `Disposition` enum that mirrors MS-SMB2 2.2.13's `CreateDisposition`). The SPI talks about paths, bytes, and basic metadata only — it doesn't leak SMB concepts. SMB2 command handlers translate NT access masks / share modes / dispositions / options into SPI calls and map `java.nio.file` exceptions (`NoSuchFileException`, `FileAlreadyExistsException`, `AccessDeniedException`, generic `IOException`) to the appropriate `STATUS_*` codes.

### Negotiate contexts

`smb2.negotiate.*` holds the SMB 3.1.1 negotiate contexts (preauth integrity, encryption, compression, signing, RDMA, transport). `NegotiateRequest.negotiateContext(Class)` looks up a context by type; the server responds with matching contexts only if the client included them.

### Authentication (SPNEGO + NTLMv2)

- The GSS token in `SESSION_SETUP` is SPNEGO, parsed/built in the `asn1` package (`NegTokenInit2`, `NegTokenResp`, hand-rolled `ASN1Node` encoder/decoder).
- Only NTLM is offered (`NegTokenInit2.createNtlmOnly()`); Kerberos is not implemented.
- `ntlmv2.NtlmSession` is a sealed state machine: `Initial` → `AwaitingAuthentication` → `Authenticated`, advanced by `Negotiator.gssAuthenticate`.
- **Credentials are currently hardcoded** in `Negotiator.gssAuthenticate` as `user / password / DOMAIN` — see the `FIXME` there.
- `ntlmv2.LegacyCryptoProvider` is a custom `java.security.Provider` registered to provide MD4 (removed from modern JDKs but still required by NTLMv2). The module's `exports org.cryptomator.jsmb.ntlmv2 to java.base` lets `java.security` load `MD4` reflectively.

### Signing and encryption

- `smb2.crypto.MessageSigner` implements AES-CMAC and AES-GMAC signatures for dialect 3.1.1. The CMAC path currently uses BouncyCastle's `CMac` — this is **temporary**; see the `TODO` in `pom.xml` / `module-info.java` referencing [issue #4](https://github.com/cryptomator/jsmb/issues/4). GMAC uses the JDK's `AES/GCM/NoPadding` and extracts the authentication tag from an empty-plaintext encryption over the header+body as AAD.
- `smb2.crypto.MessageEncryptor` wraps SMB2 messages in an `SMB2 TRANSFORM_HEADER` via AES-GCM. The server advertises AES-256-GCM first and falls back to AES-128-GCM when the client only supports the latter (e.g. `smbj` 0.14). Session keys are derived from the session key via `NistSP800108KDF` with the MS-SMB2-specified labels (`SMBS2CCipherKey\0` for server→client, `SMBC2SCipherKey\0` for client→server).
- `TcpConnection.shouldSign` / `selectKey` / `maybeEncrypt` encode the MS-SMB2 decision trees. The current implementation deliberately simplifies: `Channel` is not modelled, so `channelSigningKey` always returns `Session.signingKey`. If channel binding (`SessionSetupRequest.FLAG_BINDING`) is added, revisit both `Negotiator.gssAuthenticate` and `channelSigningKey`.

## Testing and Debugging

### Running the server manually

`RunIT` launches a jSMB server on `smb://localhost:4445/data`.

```bash
./mvnw verify -Prun -Djsmb.config=DEBUG_ENCRYPTION
```

All `-Djsmb.*` system properties can be found in [`RunIT`'s javadoc](src/test/java/org/cryptomator/jsmb/RunIT.java).

`Ctrl-C` (or `kill -TERM`) shuts the server down cleanly via the JVM shutdown hook. On macOS the default port may collide with `upnotifyp`; override with `-Djsmb.port=4446` (and matching `SAMBA_PORT=4446` for the interop wrapper) if you hit a bind failure.

### Manual interop testing with Samba's `smbclient`

A Podman-hosted wrapper for driving jSMB from Samba's reference client lives under [`interop/`](interop/). Both the wrapper and the server default to port **4445**, so no extra flags are needed. See [`interop/README.md`](interop/README.md) for the full walk-through; the short form is:

```bash
# Terminal 1 — start jSMB
./mvnw verify -Prun

# Terminal 2 — run a scenario
./interop/run-samba-scenario.sh smoke.txt
```

### Mounting from Windows

Windows pins the SMB client to TCP port **445** by default and rejects any attempt to connect to an alternate port — mapping `\\localhost\data` when jSMB listens on 4445 will normally fail with *"The specified server cannot perform the requested operation"*.

Since **Windows 11 24H2 / Windows Server 2025** the `SmbShare` PowerShell module exposes a `-TcpPort` parameter on `New-SmbMapping` that opts the client into a non-default port. From an elevated PowerShell session:

```powershell
New-SmbMapping -LocalPath Z: `
               -RemotePath \\localhost\data `
               -TcpPort 4445 `
               -UserName DOMAIN\user `
               -Password password
```

On older Windows releases the `-TcpPort` parameter does not exist and there is no supported workaround — test from Linux (`smbclient`) or a Windows 11 24H2+ VM instead.

### Wireshark packet captures

jSMB listens on a configurable TCP port (e.g. `4445`).
Because Wireshark's NBSS/SMB dissector is bound to TCP port **445** by default, traffic on any other port is displayed as raw TCP until you tell Wireshark about the port:

1. Start a capture on the relevant interface (usually `loopback` / `lo0` for local testing).
2. Open **Edit → Preferences → Protocols → NBSS** and add jSMB's port to the **TCP Ports** field (comma-separated, e.g. `445,4445`). Click **OK**.
3. Past and future packets on that port now dissect as NBSS → SMB / SMB2.
4. Apply the display filter **`smb || smb2`** to hide TCP noise and surface just the protocol exchange.

### Decrypting encrypted sessions

Start the server with `Config.DEBUG_ENCRYPTION` in the flag set — omitted by default, so key material never touches the log unless you explicitly opt in:

```java
import org.cryptomator.jsmb.Config;

var flags = Config.create(
        Config.ENCRYPT_DATA,
        Config.REJECT_UNENCRYPTED_ACCESS,
        Config.REQUIRE_MESSAGE_SIGNING,
        Config.DEBUG_ENCRYPTION);
try (var server = TcpServer.start(4445, flags)) { … }
```

On every successful `SESSION_SETUP`, jSMB then logs the session id and derived key material at `INFO`:

```
INFO org.cryptomator.jsmb.smb2.Negotiator - SMB2 session 0x0000000000000002 established — derived keys (paste the Wireshark line into Preferences → Protocols → SMB2 → Decryption keys):
  SessionKey     = 7a9cc2bc866f982e0cc636d475365c32
  SigningKey     = 876f8ad7fc72a1be4e8b3126f8454835
  EncryptionKey  = 61b942feb5a7dbfeb19a66c1e76b97c9  (S2C, server→client)
  DecryptionKey  = 048ddf1d24f5f476417b3a885a33f5ed  (C2S, client→server)
  ApplicationKey = 9d2e1989d6efd35ae09338f042866448
  Wireshark line: 0200000000000000,7a9cc2bc…,048ddf1d…,61b942fe…
```

Paste the **`Wireshark line`** value into **Edit → Preferences → Protocols → SMB2 → Decryption keys**.
Wireshark will transparently decrypt the captured `TRANSFORM_HEADER` packets and dissect them as their plaintext SMB2 equivalents.
The line's four fields are `SessionId, SessionKey, ServerInKey, ServerOutKey`:
`ServerInKey` is the key the server uses to *decrypt* client-to-server traffic, `ServerOutKey` the key it uses to *encrypt* server-to-client responses.
The session id here is in **little-endian** wire order — that's what the Wireshark preference parses byte-for-byte.
The human-readable summary line just above uses the big-endian rendering that Wireshark's packet-details view shows for the same field.

> ⚠️ `Config.DEBUG_ENCRYPTION` leaks secret key material to the log by design. Only enable it in deployments you control, while actively analysing captures — never ship it to production.

## License

AGPL-3.0 — see [`LICENSE.txt`](LICENSE.txt).
