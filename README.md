# jSMB

A basic SMB server implementation in Java, targeting SMB dialect **3.1.1**.

**Status:** work in progress — not yet production-ready.

## Build

Maven project, Java 25.

```bash
mvn test           # run all unit + integration tests
mvn package        # build jar
```

## Embedding

Register shares via the public SPI (`org.cryptomator.jsmb.share`) before (or after) starting the server:

```java
try (var server = TcpServer.start(4445)) {
    server.registerShare("data", new MySmbShare());
    // server runs in background; close() shuts it down.
}
```

A minimal reference implementation over `java.nio.file.Path` lives in
`src/test/java/org/cryptomator/jsmb/share/nio/NioShare.java`. It is **test-only**
and intentionally happy-path — production-grade backends are out of scope
for this library.

## Debugging

### Wireshark packet captures

jSMB listens on a configurable TCP port (e.g. `4445`). Because Wireshark's
NBSS/SMB dissector is bound to TCP port **445** by default, traffic on any
other port is displayed as raw TCP until you tell Wireshark about the port:

1. Start a capture on the relevant interface (usually `loopback` / `lo0` for
   local testing).
2. Open **Edit → Preferences → Protocols → NBSS** and add jSMB's port to the
   **TCP Ports** field (comma-separated, e.g. `445,4445`). Click **OK**.
3. Past and future packets on that port now dissect as NBSS → SMB / SMB2.
4. Apply the display filter **`smb || smb2`** to hide TCP noise and surface
   just the protocol exchange.

### Decrypting encrypted sessions

Start the server with `Config.DEBUG_ENCRYPTION` in the flag set — omitted
by default, so key material never touches the log unless you explicitly
opt in:

```java
import org.cryptomator.jsmb.Config;

var flags = Config.create(
        Config.ENCRYPT_DATA,
        Config.REJECT_UNENCRYPTED_ACCESS,
        Config.REQUIRE_MESSAGE_SIGNING,
        Config.DEBUG_ENCRYPTION);
try (var server = TcpServer.start(4445, flags)) { … }
```

On every successful `SESSION_SETUP`, jSMB then logs the session id and
derived key material at `INFO`:

```
INFO org.cryptomator.jsmb.smb2.Negotiator - SMB2 session 0x0000000000000002 established — derived keys (paste the Wireshark line into Preferences → Protocols → SMB2 → Decryption keys):
  SessionKey     = 7a9cc2bc866f982e0cc636d475365c32
  SigningKey     = 876f8ad7fc72a1be4e8b3126f8454835
  EncryptionKey  = 61b942feb5a7dbfeb19a66c1e76b97c9  (S2C, server→client)
  DecryptionKey  = 048ddf1d24f5f476417b3a885a33f5ed  (C2S, client→server)
  ApplicationKey = 9d2e1989d6efd35ae09338f042866448
  Wireshark line: 0200000000000000,7a9cc2bc…,048ddf1d…,61b942fe…
```

Paste the **`Wireshark line`** value into **Edit → Preferences → Protocols →
SMB2 → Decryption keys**. Wireshark will transparently decrypt the captured
`TRANSFORM_HEADER` packets and dissect them as their plaintext SMB2
equivalents. The line's four fields are
`SessionId, SessionKey, ServerInKey, ServerOutKey`, where `ServerInKey` is
the key the server uses to *decrypt* client-to-server traffic and
`ServerOutKey` is the key it uses to *encrypt* server-to-client responses.
The session id here is in **little-endian** wire order — that's what the
Wireshark preference parses byte-for-byte; the human-readable summary line
just above uses the big-endian rendering that Wireshark's packet-details
view shows for the same field.

> ⚠️ `Config.DEBUG_ENCRYPTION` leaks secret key material to the log by design.
> Only enable it in deployments you control, while actively analysing
> captures — never ship it to production.

### Capturing plaintext instead

If you prefer to skip decryption entirely, start the server with a flag
set that omits both `Config.ENCRYPT_DATA` and `Config.REJECT_UNENCRYPTED_ACCESS`:

```java
import org.cryptomator.jsmb.Config;

try (var server = TcpServer.start(4445, Config.create(Config.REQUIRE_MESSAGE_SIGNING))) {
    server.registerShare("data", new MySmbShare());
}
```

Clients must also be configured to not require encryption (e.g. `smbj`
`SmbConfig.builder().withEncryptData(false)`). Note that this disables the
confidentiality guarantee for every connection and is only safe on a
loopback interface during development.

## License

AGPL-3.0 — see [`LICENSE.txt`](LICENSE.txt).
