package org.cryptomator.jsmb.smb2;

import org.cryptomator.jsmb.Config;
import org.cryptomator.jsmb.Credentials;
import org.cryptomator.jsmb.common.NTStatus;
import org.cryptomator.jsmb.smb2.io.ReadRequest;
import org.cryptomator.jsmb.util.Layouts;
import org.jetbrains.annotations.Nullable;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;

import java.lang.foreign.MemorySegment;
import java.util.HexFormat;
import java.util.OptionalInt;

class RequestVerifierTest {

	private static final int TREE_ID = 1;

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

		var rejection = verify(request, null);

		Assertions.assertTrue(rejection.isEmpty());
	}

	@Test
	@DisplayName("A request for an unknown SessionId is rejected with STATUS_USER_SESSION_DELETED")
	void unknownSession() {
		var request = request(Command.TREE_CONNECT, 0x1234L);

		var rejection = verify(request, null);

		Assertions.assertEquals(OptionalInt.of(NTStatus.STATUS_USER_SESSION_DELETED), rejection);
	}

	@ParameterizedTest(name = "{0}")
	@DisplayName("A session that hasn't completed authentication is rejected with STATUS_ACCESS_DENIED")
	@EnumSource(value = Command.class, names = {"TREE_CONNECT", "TREE_DISCONNECT", "CREATE", "FLUSH", "READ", "WRITE", "IOCTL", "QUERY_DIRECTORY", "CHANGE_NOTIFY", "QUERY_INFO", "SET_INFO", "OPLOCK_BREAK"})
	void sessionInProgress(Command command) {
		var session = Session.create(connection);
		var request = request(command, session.sessionId);

		var rejection = verify(request, null);

		Assertions.assertEquals(OptionalInt.of(NTStatus.STATUS_ACCESS_DENIED), rejection);
	}

	@ParameterizedTest(name = "{0}")
	@DisplayName("LOGOFF, CLOSE and LOCK pass on a session that hasn't completed authentication")
	@EnumSource(value = Command.class, names = {"LOGOFF", "CLOSE", "LOCK"})
	void sessionInProgressExemptCommands(Command command) {
		var session = sessionWithTree(); // for its tree connect, which CLOSE and LOCK need to get past the checks following the one under test
		session.state = Session.State.IN_PROGRESS;
		var request = request(command, session.sessionId);

		var rejection = verify(request, null);

		Assertions.assertTrue(rejection.isEmpty());
	}

	@ParameterizedTest(name = "{0}")
	@DisplayName("Every command passes on a valid session with a tree connect")
	@EnumSource(Command.class)
	void validSession(Command command) {
		var session = sessionWithTree();
		var request = request(command, session.sessionId);

		var rejection = verify(request, null);

		Assertions.assertTrue(rejection.isEmpty());
	}

	@Test
	@DisplayName("A malformed request is rejected with STATUS_INVALID_PARAMETER")
	void malformedRequest() {
		var session = sessionWithTree();
		var header = PacketHeader.builder().command(Command.READ.value()).sessionId(session.sessionId).treeId(TREE_ID).build();
		var request = new ReadRequest(header, MemorySegment.ofArray(new byte[10])); // far too short for a READ request

		var rejection = verify(request, null);

		Assertions.assertEquals(OptionalInt.of(NTStatus.STATUS_INVALID_PARAMETER), rejection);
	}

	@Nested
	@DisplayName("Credit charge verification")
	class CreditCharge {

		private Session session;

		@BeforeEach
		void setUp() {
			connection.supportsMultiCredit = true;
			session = sessionWithTree();
		}

		@ParameterizedTest(name = "READ of {0} bytes with CreditCharge {1}")
		@DisplayName("A request whose CreditCharge doesn't cover its size is rejected with STATUS_INVALID_PARAMETER")
		@CsvSource({"65537, 0", "65537, 1", "131073, 2", "8388608, 127"})
		void insufficientCreditCharge(int length, int creditCharge) {
			var request = readRequest(length, creditCharge);

			var rejection = verify(request, null);

			Assertions.assertEquals(OptionalInt.of(NTStatus.STATUS_INVALID_PARAMETER), rejection);
		}

		@ParameterizedTest(name = "READ of {0} bytes with CreditCharge {1}")
		@DisplayName("A request whose CreditCharge covers its size passes")
		@CsvSource({"0, 0", "65536, 0", "65536, 1", "65537, 2", "131072, 2", "8388608, 128", "4096, 5"})
		void sufficientCreditCharge(int length, int creditCharge) {
			var request = readRequest(length, creditCharge);

			var rejection = verify(request, null);

			Assertions.assertTrue(rejection.isEmpty());
		}

		@Test
		@DisplayName("The CreditCharge is not verified if the connection doesn't support multi-credit requests")
		void multiCreditNotSupported() {
			connection.supportsMultiCredit = false;
			var request = readRequest(131072, 0);

			var rejection = verify(request, null);

			Assertions.assertTrue(rejection.isEmpty());
		}

		private ReadRequest readRequest(int length, int creditCharge) {
			var header = PacketHeader.builder().command(Command.READ.value()).creditCharge((char) creditCharge).sessionId(session.sessionId).treeId(TREE_ID).build();
			var body = MemorySegment.ofArray(new byte[49]);
			body.set(Layouts.LE_UINT16, 0, (char) 49); // StructureSize
			body.set(Layouts.LE_INT32, 4, length); // Length
			return new ReadRequest(header, body);
		}
	}

	@Nested
	@DisplayName("Tree connect verification")
	class Tree {

		private Session session;

		@BeforeEach
		void setUp() {
			session = sessionWithTree();
		}

		@ParameterizedTest(name = "{0}")
		@DisplayName("A request for an unknown TreeId is rejected with STATUS_NETWORK_NAME_DELETED")
		@EnumSource(value = Command.class, names = {"TREE_DISCONNECT", "CREATE", "CLOSE", "FLUSH", "READ", "WRITE", "LOCK", "IOCTL", "QUERY_DIRECTORY", "CHANGE_NOTIFY", "QUERY_INFO", "SET_INFO", "OPLOCK_BREAK"})
		void unknownTree(Command command) {
			var request = request(command, session.sessionId);

			var rejection = verifier.verify(request, session.sessionId, TREE_ID + 1, null);

			Assertions.assertEquals(OptionalInt.of(NTStatus.STATUS_NETWORK_NAME_DELETED), rejection);
		}

		@ParameterizedTest(name = "{0}")
		@DisplayName("Commands not bound to a tree connect pass with an unknown TreeId")
		@EnumSource(value = Command.class, names = {"LOGOFF", "TREE_CONNECT"})
		void treelessCommands(Command command) {
			var request = request(command, session.sessionId);

			var rejection = verifier.verify(request, session.sessionId, TREE_ID + 1, null);

			Assertions.assertTrue(rejection.isEmpty());
		}

		@Test
		@DisplayName("A request that needs a tree connect but has no TreeId is rejected with STATUS_INVALID_PARAMETER")
		void missingTreeId() {
			var request = request(Command.CREATE, session.sessionId);

			var rejection = verifier.verify(request, session.sessionId, null, null);

			Assertions.assertEquals(OptionalInt.of(NTStatus.STATUS_INVALID_PARAMETER), rejection);
		}

		@Test
		@DisplayName("A request that needs a session but has no SessionId is rejected with STATUS_INVALID_PARAMETER")
		void missingSessionId() {
			var request = request(Command.CREATE, session.sessionId);

			var rejection = verifier.verify(request, null, TREE_ID, null);

			Assertions.assertEquals(OptionalInt.of(NTStatus.STATUS_INVALID_PARAMETER), rejection);
		}

		@Test
		@DisplayName("The SessionId and TreeId passed in take precedence over those in the request's header")
		void inheritedIdentifiers() {
			var header = PacketHeader.builder().command(Command.CLOSE.value()).sessionId(-1L).treeId(-1).flags(SMB2Message.Flags.RELATED_OPERATIONS).build();
			var request = new UnhandledRequest(header, MemorySegment.ofArray(new byte[0]));

			var rejection = verifier.verify(request, session.sessionId, TREE_ID, null);

			Assertions.assertTrue(rejection.isEmpty());
		}
	}

	@Nested
	@DisplayName("Encryption enforcement")
	class Encryption {

		private Session session;

		@BeforeEach
		void setUp() {
			session = sessionWithTree();
			session.encryptData = true;
		}

		@ParameterizedTest(name = "{0}")
		@DisplayName("An unencrypted request is rejected with STATUS_ACCESS_DENIED if the session encrypts data")
		@EnumSource(value = Command.class, names = {"TREE_CONNECT", "CREATE", "READ", "WRITE", "LOGOFF", "CLOSE", "LOCK"})
		void unencryptedRequestOnEncryptedSession(Command command) {
			var request = request(command, session.sessionId);

			var rejection = verify(request, null);

			Assertions.assertEquals(OptionalInt.of(NTStatus.STATUS_ACCESS_DENIED), rejection);
		}

		@Test
		@DisplayName("An encrypted request passes if the session encrypts data")
		void encryptedRequestOnEncryptedSession() {
			var request = request(Command.TREE_CONNECT, session.sessionId);

			var rejection = verify(request, session.sessionId);

			Assertions.assertTrue(rejection.isEmpty());
		}

		@ParameterizedTest(name = "{0}")
		@DisplayName("Commands not bound to a session pass unencrypted, even if they name a session that encrypts data")
		@EnumSource(value = Command.class, names = {"SESSION_SETUP", "ECHO", "CANCEL"})
		void unencryptedSessionlessCommands(Command command) {
			var request = request(command, session.sessionId);

			var rejection = verify(request, null);

			Assertions.assertTrue(rejection.isEmpty());
		}

		@Test
		@DisplayName("A request wrapped in another session's transform is rejected with STATUS_ACCESS_DENIED even if its session doesn't encrypt data")
		void foreignTransformOnUnencryptedSession() {
			var otherSession = sessionWithTree();
			session.encryptData = false;
			var request = request(Command.TREE_CONNECT, session.sessionId);

			var rejection = verify(request, otherSession.sessionId);

			Assertions.assertEquals(OptionalInt.of(NTStatus.STATUS_ACCESS_DENIED), rejection);
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
			session = sessionWithTree();
			session.signingKey = KEY;
		}

		@Test
		@DisplayName("A correctly signed request passes")
		void validSignature() {
			var request = request(Command.TREE_CONNECT, session.sessionId).sign(KEY, connection);

			var rejection = verify(request, null);

			Assertions.assertTrue(rejection.isEmpty());
		}

		@Test
		@DisplayName("A request with a wrong signature is rejected with STATUS_ACCESS_DENIED")
		void invalidSignature() {
			var request = request(Command.TREE_CONNECT, session.sessionId).sign(OTHER_KEY, connection);

			var rejection = verify(request, null);

			Assertions.assertEquals(OptionalInt.of(NTStatus.STATUS_ACCESS_DENIED), rejection);
		}

		@Test
		@DisplayName("The signature of a related request is verified over its header as sent, with the key of the session it inherits")
		void signatureOfRelatedRequest() {
			var header = PacketHeader.builder().command(Command.CLOSE.value()).sessionId(-1L).treeId(-1).flags(SMB2Message.Flags.RELATED_OPERATIONS).build();
			var request = new UnhandledRequest(header, MemorySegment.ofArray(new byte[0])).sign(KEY, connection);

			var rejection = verifier.verify(request, session.sessionId, TREE_ID, null);

			Assertions.assertTrue(rejection.isEmpty());
		}

		@Test
		@DisplayName("A signed NEGOTIATE is rejected with STATUS_INVALID_PARAMETER")
		void signedNegotiate() {
			var request = request(Command.NEGOTIATE, 0L, SMB2Message.Flags.SIGNED);

			var rejection = verify(request, null);

			Assertions.assertEquals(OptionalInt.of(NTStatus.STATUS_INVALID_PARAMETER), rejection);
		}

		@Test
		@DisplayName("A signed request for an unknown SessionId is rejected with STATUS_USER_SESSION_DELETED, even if the command isn't bound to a session")
		void signedRequestForUnknownSession() {
			var request = request(Command.ECHO, 0x1234L, SMB2Message.Flags.SIGNED);

			var rejection = verify(request, null);

			Assertions.assertEquals(OptionalInt.of(NTStatus.STATUS_USER_SESSION_DELETED), rejection);
		}

		@Test
		@DisplayName("A signed request on a session without signing key is rejected with STATUS_NOT_SUPPORTED")
		void signedRequestWithoutSigningKey() {
			session.signingKey = null;
			var request = request(Command.TREE_CONNECT, session.sessionId, SMB2Message.Flags.SIGNED);

			var rejection = verify(request, null);

			Assertions.assertEquals(OptionalInt.of(NTStatus.STATUS_NOT_SUPPORTED), rejection);
		}

		@Test
		@DisplayName("An unsigned request is rejected with STATUS_ACCESS_DENIED if the session requires signing")
		void unsignedRequestOnSigningRequiredSession() {
			session.signingRequired = true;
			var request = request(Command.TREE_CONNECT, session.sessionId);

			var rejection = verify(request, null);

			Assertions.assertEquals(OptionalInt.of(NTStatus.STATUS_ACCESS_DENIED), rejection);
		}

		@Test
		@DisplayName("An unsigned request passes if the session doesn't require signing")
		void unsignedRequestOnSigningOptionalSession() {
			session.signingRequired = false;
			var request = request(Command.TREE_CONNECT, session.sessionId);

			var rejection = verify(request, null);

			Assertions.assertTrue(rejection.isEmpty());
		}

		@Test
		@DisplayName("An unsigned request that arrived encrypted passes even if the session requires signing")
		void unsignedEncryptedRequestOnSigningRequiredSession() {
			session.signingRequired = true;
			var request = request(Command.TREE_CONNECT, session.sessionId);

			var rejection = verify(request, session.sessionId);

			Assertions.assertTrue(rejection.isEmpty());
		}

		@Test
		@DisplayName("The signature of a request that arrived encrypted is not verified")
		void signatureOfEncryptedRequestIsIgnored() {
			var request = request(Command.TREE_CONNECT, session.sessionId).sign(OTHER_KEY, connection);

			var rejection = verify(request, session.sessionId);

			Assertions.assertTrue(rejection.isEmpty());
		}
	}

	// verifies a request that is processed with the identifiers of its own header, i.e. one that isn't a related operation
	private OptionalInt verify(SMB2Message request, @Nullable Long transformSessionId) {
		return verifier.verify(request, request.header().sessionId(), request.header().treeId(), transformSessionId);
	}

	// an authenticated session with a tree connect for TREE_ID
	private Session sessionWithTree() {
		var session = Session.create(connection);
		session.state = Session.State.VALID;
		session.treeConnectTable.put(TREE_ID, new TreeConnect(TREE_ID, "data", null, 0));
		return session;
	}

	private static SMB2Message request(Command command, long sessionId) {
		return request(command, sessionId, 0);
	}

	private static SMB2Message request(Command command, long sessionId, int flags) {
		var header = PacketHeader.builder().command(command.value()).sessionId(sessionId).treeId(TREE_ID).flags(flags).build();
		return new UnhandledRequest(header, MemorySegment.ofArray(new byte[0]));
	}
}
