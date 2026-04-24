package org.cryptomator.jsmb.smb2;

import org.cryptomator.jsmb.Config;
import org.cryptomator.jsmb.Credentials;
import org.cryptomator.jsmb.Server;
import org.cryptomator.jsmb.common.NTStatus;
import org.cryptomator.jsmb.smb2.negotiate.EncryptionCapabilities;
import org.cryptomator.jsmb.smb2.negotiate.PreauthIntegrityCapabilities;
import org.cryptomator.jsmb.util.Layouts;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.lang.foreign.MemorySegment;

/**
 * Regression guard for the Linux kernel cifs client (mount option {@code sec=ntlmssp}), which sends
 * a raw NTLMSSP blob in SMB2 {@code SESSION_SETUP} instead of the SPNEGO-wrapped token that smbj /
 * Windows use. Before the raw-NTLMSSP branch in {@link Negotiator#sessionSetup} the blob tripped
 * the SPNEGO ASN.1 parser and killed the connection-handling thread with an IOOBE. Accepting both
 * shapes isn't mandated by MS-SMB2 itself — it's an implementation behaviour of Windows SSPI / the
 * GSS stack that Linux cifs and Samba depend on.
 */
class NegotiatorRawNtlmTest {

	/**
	 * Exact 44-byte raw NTLMSSP NEGOTIATE_MESSAGE captured from a Linux cifs client. See
	 * {@code ~/Downloads/IOOB.json} (smb2.security_blob) — this is verbatim the bytes the client sent.
	 */
	private static final byte[] LINUX_CIFS_NEGOTIATE_BLOB = hex("""
			4e 54 4c 4d 53 53 50 00   \
			01 00 00 00               \
			35 82 08 e2               \
			00 00 00 00 28 00 00 00   \
			00 00 00 00 2a 00 00 00   \
			06 12 39 00 00 00 00 0f""");

	private Server server;
	private Connection connection;
	private Negotiator negotiator;

	@BeforeEach
	void setUp() throws IOException {
		server = Server.start(0, Config.create(), new Credentials("DOMAIN", "user", "password"));
		connection = new Connection(server.global);
		// Post-NEGOTIATE state — enough for the SESSION_SETUP branch that cares about preauth / cipher.
		connection.dialect = "3.1.1";
		connection.negotiateDialect = Dialects.SMB3_1_1;
		connection.preauthIntegrityHashId = PreauthIntegrityCapabilities.HASH_ALGORITHM_SHA512;
		connection.preauthIntegrityHashValue = new byte[64];
		connection.cipherId = EncryptionCapabilities.AES_128_GCM;
		negotiator = new Negotiator(server, connection);
	}

	@AfterEach
	void tearDown() throws IOException {
		if (server != null) server.close();
	}

	@Test
	@DisplayName("Raw NTLMSSP NEGOTIATE_MESSAGE (Linux cifs sec=ntlmssp) is answered with STATUS_MORE_PROCESSING_REQUIRED and an unwrapped NTLMSSP CHALLENGE_MESSAGE")
	void linuxCifsRawNtlm() {
		var request = buildSessionSetupRequest(LINUX_CIFS_NEGOTIATE_BLOB, 0L, 1L);

		var response = negotiator.sessionSetup(request);

		Assertions.assertInstanceOf(SessionSetupResponse.class, response);
		Assertions.assertEquals(NTStatus.STATUS_MORE_PROCESSING_REQUIRED, response.header().status());

		byte[] outbound = extractSecurityBuffer((SessionSetupResponse) response);
		Assertions.assertTrue(outbound.length >= 12, "Expected an NTLMSSP CHALLENGE_MESSAGE, got " + outbound.length + " bytes");
		Assertions.assertArrayEquals(
				new byte[]{'N', 'T', 'L', 'M', 'S', 'S', 'P', 0},
				java.util.Arrays.copyOfRange(outbound, 0, 8),
				"Response SecurityBuffer must start with the raw NTLMSSP signature — no SPNEGO wrap");
		Assertions.assertEquals(2, outbound[8], "MessageType = 2 (CHALLENGE_MESSAGE)");
	}

	private static byte[] extractSecurityBuffer(SessionSetupResponse response) {
		int offset = response.segment().get(Layouts.LE_UINT16, 4); // absolute from start of SMB2 header
		int length = response.segment().get(Layouts.LE_UINT16, 6);
		return response.segment().asSlice(offset - PacketHeader.STRUCTURE_SIZE, length).toArray(Layouts.BYTE);
	}

	private static SessionSetupRequest buildSessionSetupRequest(byte[] securityBlob, long sessionId, long messageId) {
		var headerSeg = MemorySegment.ofArray(new byte[PacketHeader.STRUCTURE_SIZE]);
		headerSeg.set(Layouts.LE_INT32, 0, SMB2Message.PROTOCOL_ID);
		headerSeg.set(Layouts.LE_UINT16, 4, PacketHeader.STRUCTURE_SIZE);
		headerSeg.set(Layouts.LE_UINT16, 12, Command.SESSION_SETUP.value());
		headerSeg.set(Layouts.LE_INT64, 24, messageId);
		headerSeg.set(Layouts.LE_INT64, 40, sessionId);

		// SessionSetupRequest body: 24-byte fixed portion + security blob.
		var bodySeg = MemorySegment.ofArray(new byte[24 + securityBlob.length]);
		bodySeg.set(Layouts.LE_UINT16, 0, (char) 25); // StructureSize (fixed=24 + dynamic bit)
		bodySeg.set(Layouts.BYTE, 2, (byte) 0);       // Flags
		bodySeg.set(Layouts.BYTE, 3, (byte) 0);       // SecurityMode
		bodySeg.set(Layouts.LE_INT32, 4, 0);          // Capabilities
		bodySeg.set(Layouts.LE_INT32, 8, 0);          // Channel
		bodySeg.set(Layouts.LE_UINT16, 12, (char) (PacketHeader.STRUCTURE_SIZE + 24)); // SecurityBufferOffset
		bodySeg.set(Layouts.LE_UINT16, 14, (char) securityBlob.length); // SecurityBufferLength
		bodySeg.set(Layouts.LE_INT64, 16, 0L);        // PreviousSessionId
		MemorySegment.copy(MemorySegment.ofArray(securityBlob), 0, bodySeg, 24, securityBlob.length);

		return new SessionSetupRequest(new PacketHeader(headerSeg), bodySeg);
	}

	/** Trim whitespace and parse a text-block hex dump into a byte array. */
	private static byte[] hex(String textBlock) {
		return java.util.HexFormat.of().parseHex(textBlock.replaceAll("\\s+", ""));
	}
}
