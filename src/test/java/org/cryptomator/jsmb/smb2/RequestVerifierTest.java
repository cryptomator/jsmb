package org.cryptomator.jsmb.smb2;

import org.cryptomator.jsmb.Config;
import org.cryptomator.jsmb.Credentials;
import org.cryptomator.jsmb.common.NTStatus;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.lang.foreign.MemorySegment;

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

		var rejection = verifier.verify(request);

		Assertions.assertNull(rejection);
	}

	@Test
	@DisplayName("A request for an unknown SessionId is rejected with STATUS_USER_SESSION_DELETED")
	void unknownSession() {
		var request = request(Command.TREE_CONNECT, 0x1234L);

		var rejection = verifier.verify(request);

		Assertions.assertNotNull(rejection);
		Assertions.assertEquals(NTStatus.STATUS_USER_SESSION_DELETED, rejection.header().status());
	}

	@ParameterizedTest(name = "{0}")
	@DisplayName("A session that hasn't completed authentication is rejected with STATUS_ACCESS_DENIED")
	@EnumSource(value = Command.class, names = {"TREE_CONNECT", "TREE_DISCONNECT", "CREATE", "FLUSH", "READ", "WRITE", "IOCTL", "QUERY_DIRECTORY", "CHANGE_NOTIFY", "QUERY_INFO", "SET_INFO", "OPLOCK_BREAK"})
	void sessionInProgress(Command command) {
		var session = Session.create(connection);
		var request = request(command, session.sessionId);

		var rejection = verifier.verify(request);

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

		var rejection = verifier.verify(request);

		Assertions.assertNull(rejection);
	}

	@ParameterizedTest(name = "{0}")
	@DisplayName("Every command passes on a valid session")
	@EnumSource(Command.class)
	void validSession(Command command) {
		var session = Session.create(connection);
		session.state = Session.State.VALID;
		var request = request(command, session.sessionId);

		var rejection = verifier.verify(request);

		Assertions.assertNull(rejection);
	}

	private static SMB2Message request(Command command, long sessionId) {
		var header = PacketHeader.builder().command(command.value()).sessionId(sessionId).build();
		return new UnhandledRequest(header, MemorySegment.ofArray(new byte[0]));
	}
}
