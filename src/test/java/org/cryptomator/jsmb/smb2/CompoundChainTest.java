package org.cryptomator.jsmb.smb2;

import org.cryptomator.jsmb.common.NTStatus;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.lang.foreign.MemorySegment;

class CompoundChainTest {

	private static final int RELATED = SMB2Message.Flags.RELATED_OPERATIONS;

	private final CompoundChain chain = new CompoundChain();

	@Test
	@DisplayName("An unrelated operation is processed with the identifiers of its own header")
	void unrelatedOperation() {
		chain.processed(message(Command.CREATE, 0, 1L, 2), message(Command.CREATE, 0, 1L, 2));
		var request = message(Command.CREATE, 0, 3L, 4);

		Assertions.assertEquals(3L, chain.sessionId(request));
		Assertions.assertEquals(4, chain.treeId(request));
	}

	@Test
	@DisplayName("A related operation is processed with the identifiers of the previous operation, even if that one failed")
	void relatedOperation() {
		var create = message(Command.CREATE, 0, 1L, 2);
		chain.processed(create, ErrorResponse.create(create, NTStatus.STATUS_ACCESS_DENIED));
		var request = message(Command.CLOSE, RELATED, -1L, -1);

		Assertions.assertEquals(1L, chain.sessionId(request));
		Assertions.assertEquals(2, chain.treeId(request));
	}

	@Test
	@DisplayName("Identifiers are handed down along a chain of related operations")
	void chainOfRelatedOperations() {
		chain.processed(message(Command.CREATE, 0, 1L, 2), message(Command.CREATE, 0, 1L, 2));
		var second = message(Command.QUERY_INFO, RELATED, -1L, -1);
		chain.processed(second, message(Command.QUERY_INFO, 0, 1L, 2));
		var third = message(Command.CLOSE, RELATED, -1L, -1);

		Assertions.assertEquals(1L, chain.sessionId(third));
		Assertions.assertEquals(2, chain.treeId(third));
	}

	@Test
	@DisplayName("A related operation at the start of a chain has no identifiers")
	void relatedFirstOperation() {
		var request = message(Command.CLOSE, RELATED, 1L, 2);

		Assertions.assertNull(chain.sessionId(request));
		Assertions.assertNull(chain.treeId(request));
	}

	@Test
	@DisplayName("A related operation inherits the TreeId created by a preceding TREE_CONNECT")
	void treeConnectCreatesTreeId() {
		chain.processed(message(Command.TREE_CONNECT, 0, 1L, 0), message(Command.TREE_CONNECT, 0, 1L, 7));
		var request = message(Command.CREATE, RELATED, -1L, -1);

		Assertions.assertEquals(1L, chain.sessionId(request));
		Assertions.assertEquals(7, chain.treeId(request));
	}

	@Test
	@DisplayName("A related operation has no TreeId if the preceding TREE_CONNECT failed")
	void failedTreeConnect() {
		var treeConnect = message(Command.TREE_CONNECT, 0, 1L, 0);
		chain.processed(treeConnect, ErrorResponse.create(treeConnect, NTStatus.STATUS_BAD_NETWORK_NAME));
		var request = message(Command.CREATE, RELATED, -1L, -1);

		Assertions.assertEquals(1L, chain.sessionId(request));
		Assertions.assertNull(chain.treeId(request));
	}

	@Test
	@DisplayName("A related operation inherits the SessionId created by a preceding SESSION_SETUP")
	void sessionSetupCreatesSessionId() {
		chain.processed(message(Command.SESSION_SETUP, 0, 0L, 0), message(Command.SESSION_SETUP, 0, 5L, 0));
		var request = message(Command.TREE_CONNECT, RELATED, -1L, -1);

		Assertions.assertEquals(5L, chain.sessionId(request));
		Assertions.assertNull(chain.treeId(request));
	}

	@Test
	@DisplayName("A related operation has no SessionId if the preceding SESSION_SETUP failed")
	void failedSessionSetup() {
		var sessionSetup = message(Command.SESSION_SETUP, 0, 5L, 0);
		chain.processed(sessionSetup, ErrorResponse.create(sessionSetup, NTStatus.STATUS_LOGON_FAILURE));
		var request = message(Command.TREE_CONNECT, RELATED, -1L, -1);

		Assertions.assertNull(chain.sessionId(request));
	}

	@ParameterizedTest(name = "{0}")
	@DisplayName("A related operation has no identifiers if the previous operation isn't bound to a session")
	@EnumSource(value = Command.class, names = {"NEGOTIATE", "ECHO", "CANCEL"})
	void sessionlessPredecessor(Command command) {
		chain.processed(message(command, 0, 1L, 2), null);
		var request = message(Command.CLOSE, RELATED, -1L, -1);

		Assertions.assertNull(chain.sessionId(request));
		Assertions.assertNull(chain.treeId(request));
	}

	@Test
	@DisplayName("A related operation following a LOGOFF has a SessionId but no TreeId")
	void logoffPredecessor() {
		chain.processed(message(Command.LOGOFF, 0, 1L, 2), message(Command.LOGOFF, 0, 1L, 0));
		var request = message(Command.CLOSE, RELATED, -1L, -1);

		Assertions.assertEquals(1L, chain.sessionId(request));
		Assertions.assertNull(chain.treeId(request));
	}

	@Test
	@DisplayName("An operation with an async header has no TreeId")
	void asyncHeader() {
		var request = message(Command.CANCEL, SMB2Message.Flags.ASYNC_COMMAND, 1L, 2);

		Assertions.assertEquals(1L, chain.sessionId(request));
		Assertions.assertNull(chain.treeId(request));
	}

	// only the header matters, so one type stands in for requests and successful responses alike
	private static SMB2Message message(Command command, int flags, long sessionId, int treeId) {
		var header = PacketHeader.builder().command(command.value()).flags(flags).sessionId(sessionId).treeId(treeId).build();
		return new UnhandledRequest(header, MemorySegment.ofArray(new byte[0]));
	}
}
