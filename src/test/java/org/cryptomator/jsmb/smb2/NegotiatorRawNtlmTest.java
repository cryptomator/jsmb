package org.cryptomator.jsmb.smb2;

import org.cryptomator.jsmb.Config;
import org.cryptomator.jsmb.Credentials;
import org.cryptomator.jsmb.Server;
import org.cryptomator.jsmb.common.NTStatus;
import org.cryptomator.jsmb.smb2.negotiate.EncryptionCapabilities;
import org.cryptomator.jsmb.smb2.negotiate.GlobalCapabilities;
import org.cryptomator.jsmb.smb2.negotiate.PreauthIntegrityCapabilities;
import org.cryptomator.jsmb.util.Layouts;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.RealmCallback;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;
import java.util.Map;

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
		connection = negotiatedConnection(server);
		negotiator = new Negotiator(server, connection);
	}

	private static Connection negotiatedConnection(Server server) {
		var connection = new Connection(server.global);
		// Post-NEGOTIATE state — enough for the SESSION_SETUP branch that cares about preauth / cipher.
		connection.dialect = "3.1.1";
		connection.negotiateDialect = Dialects.SMB3_1_1;
		connection.preauthIntegrityHashId = PreauthIntegrityCapabilities.HASH_ALGORITHM_SHA512;
		connection.preauthIntegrityHashValue = new byte[64];
		connection.cipherId = EncryptionCapabilities.AES_128_GCM;
		return connection;
	}

	@AfterEach
	void tearDown() throws IOException {
		if (server != null) server.close();
	}

	@Test
	@DisplayName("Raw NTLMSSP NEGOTIATE_MESSAGE (Linux cifs sec=ntlmssp) is answered with STATUS_MORE_PROCESSING_REQUIRED and an unwrapped NTLMSSP CHALLENGE_MESSAGE")
	void linuxCifsRawNtlm() {
		var request = buildSessionSetupRequest(LINUX_CIFS_NEGOTIATE_BLOB, 0L, 1L);

		var response = negotiator.sessionSetup(request, 1);

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

	@Test
	@DisplayName("A failed second SESSION_SETUP leg removes the session from the connection's and the global session table")
	void failedAuthenticationRemovesSession() {
		var challenge = negotiator.sessionSetup(buildSessionSetupRequest(LINUX_CIFS_NEGOTIATE_BLOB, 0L, 1L), 1);
		long sessionId = challenge.header().sessionId();
		Assertions.assertTrue(connection.sessionTable.containsKey(sessionId));
		// a NEGOTIATE_MESSAGE where the AUTHENTICATE_MESSAGE is due
		var secondLeg = buildSessionSetupRequest(LINUX_CIFS_NEGOTIATE_BLOB, sessionId, 2L);

		var response = negotiator.sessionSetup(secondLeg, 1);

		Assertions.assertInstanceOf(ErrorResponse.class, response);
		Assertions.assertEquals(NTStatus.STATUS_INVALID_PARAMETER, response.header().status());
		Assertions.assertFalse(connection.sessionTable.containsKey(sessionId));
		Assertions.assertFalse(server.global.sessionTable.containsKey(sessionId));
	}

	@Nested
	@DisplayName("Reauthentication")
	class Reauthentication {

		private Session session;

		@BeforeEach
		void authenticate() throws SaslException {
			var response = NegotiatorRawNtlmTest.authenticate(negotiator, 0L, 0L);
			Assertions.assertEquals(NTStatus.STATUS_SUCCESS, response.header().status());
			session = connection.sessionTable.get(response.header().sessionId());
			session.treeConnectTable.put(1, new TreeConnect(1, "data", null, 0));
		}

		@Test
		@DisplayName("Reauthenticating a valid session succeeds and leaves its keys and tree connects as they are")
		void reauthenticateValidSession() throws SaslException {
			byte[] sessionKey = session.sessionKey;
			byte[] signingKey = session.signingKey;
			byte[] encryptionKey = session.encryptionKey;
			byte[] decryptionKey = session.decryptionKey;
			byte[] preauthIntegrityHashValue = session.preauthIntegrityHashValue;

			var response = NegotiatorRawNtlmTest.authenticate(negotiator, session.sessionId, 0L);

			Assertions.assertEquals(NTStatus.STATUS_SUCCESS, response.header().status());
			Assertions.assertEquals(session.sessionId, response.header().sessionId());
			Assertions.assertSame(session, connection.sessionTable.get(session.sessionId));
			Assertions.assertEquals(Session.State.VALID, session.state);
			Assertions.assertSame(sessionKey, session.sessionKey);
			Assertions.assertSame(signingKey, session.signingKey);
			Assertions.assertSame(encryptionKey, session.encryptionKey);
			Assertions.assertSame(decryptionKey, session.decryptionKey);
			Assertions.assertSame(preauthIntegrityHashValue, session.preauthIntegrityHashValue);
			Assertions.assertEquals(1, session.treeConnectTable.size());
		}

		@Test
		@DisplayName("A session stays valid between the two legs of its reauthentication")
		void validWhileReauthenticating() {
			var response = negotiator.sessionSetup(buildSessionSetupRequest(LINUX_CIFS_NEGOTIATE_BLOB, session.sessionId, 0L, 3L), 1);

			Assertions.assertEquals(NTStatus.STATUS_MORE_PROCESSING_REQUIRED, response.header().status());
			Assertions.assertEquals(Session.State.VALID, session.state);
		}

		@Test
		@DisplayName("Reauthenticating an expired session makes it valid again and leaves its keys as they are")
		void reauthenticateExpiredSession() throws SaslException {
			byte[] sessionKey = session.sessionKey;
			session.state = Session.State.EXPIRED;

			var response = NegotiatorRawNtlmTest.authenticate(negotiator, session.sessionId, 0L);

			Assertions.assertEquals(NTStatus.STATUS_SUCCESS, response.header().status());
			Assertions.assertEquals(Session.State.VALID, session.state);
			Assertions.assertSame(sessionKey, session.sessionKey);
		}

		@Test
		@DisplayName("A failed reauthentication removes the session along with its tree connects")
		void failedReauthentication() {
			negotiator.sessionSetup(buildSessionSetupRequest(LINUX_CIFS_NEGOTIATE_BLOB, session.sessionId, 0L, 3L), 1);
			// a NEGOTIATE_MESSAGE where the AUTHENTICATE_MESSAGE is due
			var secondLeg = buildSessionSetupRequest(LINUX_CIFS_NEGOTIATE_BLOB, session.sessionId, 0L, 4L);

			var response = negotiator.sessionSetup(secondLeg, 1);

			Assertions.assertInstanceOf(ErrorResponse.class, response);
			Assertions.assertFalse(connection.sessionTable.containsKey(session.sessionId));
			Assertions.assertFalse(server.global.sessionTable.containsKey(session.sessionId));
			Assertions.assertTrue(session.treeConnectTable.isEmpty());
		}

		@Test
		@DisplayName("A PreviousSessionId that names the session being reauthenticated is ignored")
		void previousSessionIdNamingItself() throws SaslException {
			var response = NegotiatorRawNtlmTest.authenticate(negotiator, session.sessionId, session.sessionId);

			Assertions.assertEquals(NTStatus.STATUS_SUCCESS, response.header().status());
			Assertions.assertSame(session, server.global.sessionTable.get(session.sessionId));
			Assertions.assertEquals(1, session.treeConnectTable.size());
		}
	}

	@Nested
	@DisplayName("PreviousSessionId")
	class PreviousSessionId {

		private Connection newConnection;
		private Negotiator newNegotiator;

		@BeforeEach
		void reconnect() {
			newConnection = negotiatedConnection(server);
			newNegotiator = new Negotiator(server, newConnection);
		}

		@Test
		@DisplayName("A new session of the same user removes the previous session it names, along with its tree connects")
		void sameUser() throws SaslException {
			long previousSessionId = NegotiatorRawNtlmTest.authenticate(negotiator, 0L, 0L).header().sessionId();
			var previous = connection.sessionTable.get(previousSessionId);
			previous.treeConnectTable.put(1, new TreeConnect(1, "data", null, 0));

			var response = NegotiatorRawNtlmTest.authenticate(newNegotiator, 0L, previousSessionId);

			Assertions.assertEquals(NTStatus.STATUS_SUCCESS, response.header().status());
			Assertions.assertFalse(connection.sessionTable.containsKey(previousSessionId));
			Assertions.assertFalse(server.global.sessionTable.containsKey(previousSessionId));
			Assertions.assertTrue(previous.treeConnectTable.isEmpty());
			Assertions.assertEquals(Session.State.VALID, newConnection.sessionTable.get(response.header().sessionId()).state);
		}

		@Test
		@DisplayName("A previous session that never got authenticated is left alone")
		void unauthenticatedPreviousSession() throws SaslException {
			long previousSessionId = negotiator.sessionSetup(buildSessionSetupRequest(LINUX_CIFS_NEGOTIATE_BLOB, 0L, 1L), 1).header().sessionId();

			var response = NegotiatorRawNtlmTest.authenticate(newNegotiator, 0L, previousSessionId);

			Assertions.assertEquals(NTStatus.STATUS_SUCCESS, response.header().status());
			Assertions.assertTrue(connection.sessionTable.containsKey(previousSessionId));
			Assertions.assertTrue(server.global.sessionTable.containsKey(previousSessionId));
		}

		@Test
		@DisplayName("A previous session of another user is left alone")
		void otherUser() throws SaslException {
			long previousSessionId = NegotiatorRawNtlmTest.authenticate(negotiator, 0L, 0L).header().sessionId();
			connection.sessionTable.get(previousSessionId).securityContext = "DOMAIN\\someone-else";

			var response = NegotiatorRawNtlmTest.authenticate(newNegotiator, 0L, previousSessionId);

			Assertions.assertEquals(NTStatus.STATUS_SUCCESS, response.header().status());
			Assertions.assertTrue(server.global.sessionTable.containsKey(previousSessionId));
		}

		@Test
		@DisplayName("A PreviousSessionId that names no session is ignored")
		void unknownPreviousSession() throws SaslException {
			var response = NegotiatorRawNtlmTest.authenticate(newNegotiator, 0L, 0x7777L);

			Assertions.assertEquals(NTStatus.STATUS_SUCCESS, response.header().status());
		}
	}

	// Runs both legs of an NTLM authentication against the negotiator, with the JDK's SASL mechanism in the role of the client. Returns the response to the second leg.
	private static SMB2Message authenticate(Negotiator negotiator, long sessionId, long previousSessionId) throws SaslException {
		Map<String, ?> props = Map.of("com.sun.security.sasl.ntlm.version", "LMv2/NTLMv2", "com.sun.security.sasl.ntlm.domain", "DOMAIN");
		CallbackHandler callbackHandler = callbacks -> {
			for (Callback callback : callbacks) {
				switch (callback) {
					case PasswordCallback pc -> pc.setPassword("password".toCharArray());
					case NameCallback nc -> nc.setName("user");
					case RealmCallback rc -> rc.setText("DOMAIN");
					default -> throw new UnsupportedCallbackException(callback);
				}
			}
		};
		SaslClient client = Sasl.createSaslClient(new String[]{"NTLM"}, "user", "jsmb", "localhost", props, callbackHandler);
		byte[] negotiateMessage = client.evaluateChallenge(new byte[0]);
		var challenge = negotiator.sessionSetup(buildSessionSetupRequest(negotiateMessage, sessionId, previousSessionId, 1L), 1);
		Assertions.assertEquals(NTStatus.STATUS_MORE_PROCESSING_REQUIRED, challenge.header().status());
		byte[] authenticateMessage = client.evaluateChallenge(extractSecurityBuffer((SessionSetupResponse) challenge));
		return negotiator.sessionSetup(buildSessionSetupRequest(authenticateMessage, challenge.header().sessionId(), previousSessionId, 2L), 1);
	}

	@Test
	@DisplayName("With REJECT_UNENCRYPTED_ACCESS, SESSION_SETUP is rejected with STATUS_ACCESS_DENIED if no cipher was negotiated")
	void rejectUnencryptedAccessWithoutCipher() throws IOException {
		try (var strictServer = Server.start(0, Config.create(Config.REJECT_UNENCRYPTED_ACCESS), new Credentials("DOMAIN", "user", "password"))) {
			var strictConnection = negotiatedConnection(strictServer);
			strictConnection.clientCapabilities = GlobalCapabilities.SMB2_GLOBAL_CAP_ENCRYPTION;
			strictConnection.cipherId = EncryptionCapabilities.NO_COMMON_CIPHER;
			var request = buildSessionSetupRequest(LINUX_CIFS_NEGOTIATE_BLOB, 0L, 1L);

			var response = new Negotiator(strictServer, strictConnection).sessionSetup(request, 1);

			Assertions.assertEquals(NTStatus.STATUS_ACCESS_DENIED, response.header().status());
		}
	}

	@Test
	@DisplayName("With REJECT_UNENCRYPTED_ACCESS, SESSION_SETUP proceeds if a cipher was negotiated")
	void rejectUnencryptedAccessWithCipher() throws IOException {
		try (var strictServer = Server.start(0, Config.create(Config.REJECT_UNENCRYPTED_ACCESS), new Credentials("DOMAIN", "user", "password"))) {
			var strictConnection = negotiatedConnection(strictServer);
			strictConnection.clientCapabilities = GlobalCapabilities.SMB2_GLOBAL_CAP_ENCRYPTION;
			var request = buildSessionSetupRequest(LINUX_CIFS_NEGOTIATE_BLOB, 0L, 1L);

			var response = new Negotiator(strictServer, strictConnection).sessionSetup(request, 1);

			Assertions.assertEquals(NTStatus.STATUS_MORE_PROCESSING_REQUIRED, response.header().status());
		}
	}

	private static byte[] extractSecurityBuffer(SessionSetupResponse response) {
		int offset = response.segment().get(Layouts.LE_UINT16, 4); // absolute from start of SMB2 header
		int length = response.segment().get(Layouts.LE_UINT16, 6);
		return response.segment().asSlice(offset - PacketHeader.STRUCTURE_SIZE, length).toArray(Layouts.BYTE);
	}

	private static SessionSetupRequest buildSessionSetupRequest(byte[] securityBlob, long sessionId, long messageId) {
		return buildSessionSetupRequest(securityBlob, sessionId, 0L, messageId);
	}

	private static SessionSetupRequest buildSessionSetupRequest(byte[] securityBlob, long sessionId, long previousSessionId, long messageId) {
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
		bodySeg.set(Layouts.LE_INT64, 16, previousSessionId);
		MemorySegment.copy(MemorySegment.ofArray(securityBlob), 0, bodySeg, 24, securityBlob.length);

		return new SessionSetupRequest(new PacketHeader(headerSeg), bodySeg);
	}

	/** Trim whitespace and parse a text-block hex dump into a byte array. */
	private static byte[] hex(String textBlock) {
		return java.util.HexFormat.of().parseHex(textBlock.replaceAll("\\s+", ""));
	}
}
