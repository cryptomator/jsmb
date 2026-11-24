package org.cryptomator.jsmb.smb2;

import org.cryptomator.jsmb.Config;
import org.cryptomator.jsmb.Credentials;
import org.cryptomator.jsmb.common.NTStatus;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.lang.foreign.MemorySegment;
import java.util.HexFormat;

class RequestVerifierTest {

	private Connection connection;
	private RequestVerifier verifier;

	@BeforeEach
	void setUp() {
		var global = new Global(Config.DEFAULT, new Credentials("DOMAIN", "user", "password"));
		connection = new Connection(global);
		verifier = new RequestVerifier(connection);
	}

	@ParameterizedTest(name = "{0}")
	@DisplayName("Commands not bound to a session pass without one")
	@EnumSource(value = Command.class, names = {"NEGOTIATE", "SESSION_SETUP", "ECHO", "CANCEL"})
	void sessionlessCommands(Command command) {
		var request = request(command, 0L);

		var rejection = verifier.verify(request, null);

		Assertions.assertNull(rejection);
	}

	@Test
	@DisplayName("A request for an unknown SessionId is rejected with STATUS_USER_SESSION_DELETED")
	void unknownSession() {
		var request = request(Command.TREE_CONNECT, 0x1234L);

		var rejection = verifier.verify(request, null);

		Assertions.assertNotNull(rejection);
		Assertions.assertEquals(NTStatus.STATUS_USER_SESSION_DELETED, rejection.header().status());
	}

	@ParameterizedTest(name = "{0}")
	@DisplayName("A session that hasn't completed authentication is rejected with STATUS_ACCESS_DENIED")
	@EnumSource(value = Command.class, names = {"TREE_CONNECT", "TREE_DISCONNECT", "CREATE", "FLUSH", "READ", "WRITE", "IOCTL", "QUERY_DIRECTORY", "CHANGE_NOTIFY", "QUERY_INFO", "SET_INFO", "OPLOCK_BREAK"})
	void sessionInProgress(Command command) {
		var session = Session.create(connection);
		var request = request(command, session.sessionId);

		var rejection = verifier.verify(request, null);

		Assertions.assertNotNull(rejection);
		Assertions.assertEquals(NTStatus.STATUS_ACCESS_DENIED, rejection.header().status());
		Assertions.assertEquals(command.value(), rejection.header().command());
	}

	@ParameterizedTest(name = "{0}")
	@DisplayName("LOGOFF, CLOSE and LOCK pass on a session that hasn't completed authentication")
	@EnumSource(value = Command.class, names = {"LOGOFF", "CLOSE", "LOCK"})
	void sessionInProgressExemptCommands(Command command) {
		var session = Session.create(connection);
		var request = request(command, session.sessionId);

		var rejection = verifier.verify(request, null);

		Assertions.assertNull(rejection);
	}

	@ParameterizedTest(name = "{0}")
	@DisplayName("Every command passes on a valid session")
	@EnumSource(Command.class)
	void validSession(Command command) {
		var session = Session.create(connection);
		session.state = Session.State.VALID;
		var request = request(command, session.sessionId);

		var rejection = verifier.verify(request, null);

		Assertions.assertNull(rejection);
	}

	@Nested
	@DisplayName("Encryption enforcement")
	class Encryption {

		private Session session;

		@BeforeEach
		void setUp() {
			session = Session.create(connection);
			session.state = Session.State.VALID;
			session.encryptData = true;
		}

		@ParameterizedTest(name = "{0}")
		@DisplayName("An unencrypted request is rejected with STATUS_ACCESS_DENIED if the session encrypts data")
		@EnumSource(value = Command.class, names = {"TREE_CONNECT", "CREATE", "READ", "WRITE", "LOGOFF", "CLOSE", "LOCK"})
		void unencryptedRequestOnEncryptedSession(Command command) {
			var request = request(command, session.sessionId);

			var rejection = verifier.verify(request, null);

			Assertions.assertNotNull(rejection);
			Assertions.assertEquals(NTStatus.STATUS_ACCESS_DENIED, rejection.header().status());
		}

		@Test
		@DisplayName("An encrypted request passes if the session encrypts data")
		void encryptedRequestOnEncryptedSession() {
			var request = request(Command.TREE_CONNECT, session.sessionId);

			var rejection = verifier.verify(request, session.sessionId);

			Assertions.assertNull(rejection);
		}

		@ParameterizedTest(name = "{0}")
		@DisplayName("Commands not bound to a session pass unencrypted, even if they name a session that encrypts data")
		@EnumSource(value = Command.class, names = {"SESSION_SETUP", "ECHO", "CANCEL"})
		void unencryptedSessionlessCommands(Command command) {
			var request = request(command, session.sessionId);

			var rejection = verifier.verify(request, null);

			Assertions.assertNull(rejection);
		}

		@Test
		@DisplayName("A request wrapped in another session's transform is rejected with STATUS_ACCESS_DENIED even if its session doesn't encrypt data")
		void foreignTransformOnUnencryptedSession() {
			var otherSession = Session.create(connection);
			otherSession.state = Session.State.VALID;
			session.encryptData = false;
			var request = request(Command.TREE_CONNECT, session.sessionId);

			var rejection = verifier.verify(request, otherSession.sessionId);

			Assertions.assertNotNull(rejection);
			Assertions.assertEquals(NTStatus.STATUS_ACCESS_DENIED, rejection.header().status());
		}
	}

	@Nested
	@DisplayName("Signature verification")
	class Signature {

		private static final byte[] KEY = HexFormat.of().parseHex("23a69fff57bcb19502bb74e79ce760db");
		private static final byte[] OTHER_KEY = HexFormat.of().parseHex("e07aa62cc914810061e07ee1084fce1b");

		private Session session;

		@BeforeEach
		void setUp() {
			connection.dialect = "3.1.1"; // AES-CMAC, as no signing algorithm got negotiated
			session = Session.create(connection);
			session.state = Session.State.VALID;
			session.signingKey = KEY;
		}

		@Test
		@DisplayName("A correctly signed request passes")
		void validSignature() {
			var request = request(Command.TREE_CONNECT, session.sessionId).sign(KEY, connection);

			var rejection = verifier.verify(request, null);

			Assertions.assertNull(rejection);
		}

		@Test
		@DisplayName("A request with a wrong signature is rejected with STATUS_ACCESS_DENIED")
		void invalidSignature() {
			var request = request(Command.TREE_CONNECT, session.sessionId).sign(OTHER_KEY, connection);

			var rejection = verifier.verify(request, null);

			Assertions.assertNotNull(rejection);
			Assertions.assertEquals(NTStatus.STATUS_ACCESS_DENIED, rejection.header().status());
		}

		@Test
		@DisplayName("A signed NEGOTIATE is rejected with STATUS_INVALID_PARAMETER")
		void signedNegotiate() {
			var request = request(Command.NEGOTIATE, 0L, SMB2Message.Flags.SIGNED);

			var rejection = verifier.verify(request, null);

			Assertions.assertNotNull(rejection);
			Assertions.assertEquals(NTStatus.STATUS_INVALID_PARAMETER, rejection.header().status());
		}

		@Test
		@DisplayName("A signed request for an unknown SessionId is rejected with STATUS_USER_SESSION_DELETED, even if the command isn't bound to a session")
		void signedRequestForUnknownSession() {
			var request = request(Command.ECHO, 0x1234L, SMB2Message.Flags.SIGNED);

			var rejection = verifier.verify(request, null);

			Assertions.assertNotNull(rejection);
			Assertions.assertEquals(NTStatus.STATUS_USER_SESSION_DELETED, rejection.header().status());
		}

		@Test
		@DisplayName("A signed request on a session without signing key is rejected with STATUS_NOT_SUPPORTED")
		void signedRequestWithoutSigningKey() {
			session.signingKey = null;
			var request = request(Command.TREE_CONNECT, session.sessionId, SMB2Message.Flags.SIGNED);

			var rejection = verifier.verify(request, null);

			Assertions.assertNotNull(rejection);
			Assertions.assertEquals(NTStatus.STATUS_NOT_SUPPORTED, rejection.header().status());
		}

		@Test
		@DisplayName("An unsigned request is rejected with STATUS_ACCESS_DENIED if the session requires signing")
		void unsignedRequestOnSigningRequiredSession() {
			session.signingRequired = true;
			var request = request(Command.TREE_CONNECT, session.sessionId);

			var rejection = verifier.verify(request, null);

			Assertions.assertNotNull(rejection);
			Assertions.assertEquals(NTStatus.STATUS_ACCESS_DENIED, rejection.header().status());
		}

		@Test
		@DisplayName("An unsigned request passes if the session doesn't require signing")
		void unsignedRequestOnSigningOptionalSession() {
			session.signingRequired = false;
			var request = request(Command.TREE_CONNECT, session.sessionId);

			var rejection = verifier.verify(request, null);

			Assertions.assertNull(rejection);
		}

		@Test
		@DisplayName("An unsigned request that arrived encrypted passes even if the session requires signing")
		void unsignedEncryptedRequestOnSigningRequiredSession() {
			session.signingRequired = true;
			var request = request(Command.TREE_CONNECT, session.sessionId);

			var rejection = verifier.verify(request, session.sessionId);

			Assertions.assertNull(rejection);
		}

		@Test
		@DisplayName("The signature of a request that arrived encrypted is not verified")
		void signatureOfEncryptedRequestIsIgnored() {
			var request = request(Command.TREE_CONNECT, session.sessionId).sign(OTHER_KEY, connection);

			var rejection = verifier.verify(request, session.sessionId);

			Assertions.assertNull(rejection);
		}
	}

	private static SMB2Message request(Command command, long sessionId) {
		return request(command, sessionId, 0);
	}

	private static SMB2Message request(Command command, long sessionId, int flags) {
		var header = PacketHeader.builder().command(command.value()).sessionId(sessionId).flags(flags).build();
		return new UnhandledRequest(header, MemorySegment.ofArray(new byte[0]));
	}
}
