package org.cryptomator.jsmb.smb2;

import org.cryptomator.jsmb.common.NTStatus;
import org.cryptomator.jsmb.share.FileId;
import org.cryptomator.jsmb.smb2.create.CloseRequest;
import org.cryptomator.jsmb.smb2.create.CreateResponse;
import org.cryptomator.jsmb.util.Layouts;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.lang.foreign.MemorySegment;
import java.util.OptionalInt;

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
	@Nested
	@DisplayName("FileId")
	class FileIds {

		private static final FileId OPENED = new FileId(0x11L, 0x22L);
		private static final FileId OTHER = new FileId(0x33L, 0x44L);

		@Test
		@DisplayName("A related operation works on the FileId that a preceding CREATE returned")
		void createdFileId() {
			chain.processed(message(Command.CREATE, 0, 1L, 2), created(OPENED));
			var request = close(RELATED, FileId.NONE);

			Assertions.assertTrue(chain.fileIdRejection(request).isEmpty());
			Assertions.assertEquals(OPENED, chain.fileId());
		}

		@Test
		@DisplayName("A related operation works on the FileId that the preceding operation stated itself")
		void usedFileId() {
			var first = close(0, OPENED);
			chain.processed(first, message(Command.CLOSE, 0, 1L, 2));
			var request = close(RELATED, FileId.NONE);

			Assertions.assertTrue(chain.fileIdRejection(request).isEmpty());
			Assertions.assertEquals(OPENED, chain.fileId());
		}

		@Test
		@DisplayName("A related operation works on the inherited FileId, whatever its own FileId field says")
		void ownFileIdOfRelatedOperationIsIgnored() {
			chain.processed(message(Command.CREATE, 0, 1L, 2), created(OPENED));
			var second = close(RELATED, OTHER);
			chain.processed(second, message(Command.CLOSE, 0, 1L, 2));
			var third = close(RELATED, FileId.NONE);

			Assertions.assertTrue(chain.fileIdRejection(third).isEmpty());
			Assertions.assertEquals(OPENED, chain.fileId());
		}

		@ParameterizedTest(name = "{0}")
		@DisplayName("A related operation works on the FileId of a preceding operation that isn't parsed any further")
		@EnumSource(value = Command.class, names = {"LOCK", "IOCTL", "OPLOCK_BREAK"})
		void fileIdOfUnparsedOperation(Command command) {
			var header = PacketHeader.builder().command(command.value()).sessionId(1L).treeId(2).build();
			var body = MemorySegment.ofArray(new byte[48]);
			OPENED.writeTo(body.asSlice(8, FileId.SIZE));
			var first = new UnhandledRequest(header, body);
			chain.processed(first, ErrorResponse.create(first, NTStatus.STATUS_NOT_SUPPORTED));
			var request = close(RELATED, FileId.NONE);

			Assertions.assertTrue(chain.fileIdRejection(request).isEmpty());
			Assertions.assertEquals(OPENED, chain.fileId());
		}

		@Test
		@DisplayName("Related operations following a failed CREATE fail with its status")
		void failedCreate() {
			var create = message(Command.CREATE, 0, 1L, 2);
			chain.processed(create, ErrorResponse.create(create, NTStatus.STATUS_OBJECT_NAME_NOT_FOUND));
			var second = close(RELATED, FileId.NONE);
			var secondRejection = chain.fileIdRejection(second);
			chain.processed(second, ErrorResponse.create(second, NTStatus.STATUS_OBJECT_NAME_NOT_FOUND));
			var third = close(RELATED, FileId.NONE);

			Assertions.assertEquals(OptionalInt.of(NTStatus.STATUS_OBJECT_NAME_NOT_FOUND), secondRejection);
			Assertions.assertEquals(OptionalInt.of(NTStatus.STATUS_OBJECT_NAME_NOT_FOUND), chain.fileIdRejection(third));
		}

		@Test
		@DisplayName("A related CREATE following a failed CREATE is processed, as it takes no FileId")
		void createAfterFailedCreate() {
			var create = message(Command.CREATE, 0, 1L, 2);
			chain.processed(create, ErrorResponse.create(create, NTStatus.STATUS_OBJECT_NAME_NOT_FOUND));
			var request = message(Command.CREATE, RELATED, -1L, -1);

			Assertions.assertTrue(chain.fileIdRejection(request).isEmpty());
		}

		@Test
		@DisplayName("An operation that failed on a valid FileId doesn't keep the following one from being processed with it")
		void failedOperationOnValidFileId() {
			chain.processed(message(Command.CREATE, 0, 1L, 2), created(OPENED));
			var second = close(RELATED, FileId.NONE);
			chain.processed(second, ErrorResponse.create(second, NTStatus.STATUS_INVALID_INFO_CLASS));
			var third = close(RELATED, FileId.NONE);

			Assertions.assertTrue(chain.fileIdRejection(third).isEmpty());
			Assertions.assertEquals(OPENED, chain.fileId());
		}

		@ParameterizedTest(name = "{0}")
		@DisplayName("A related operation fails with STATUS_INVALID_HANDLE if the preceding one neither contains nor generates a FileId")
		@EnumSource(value = Command.class, names = {"TREE_CONNECT", "ECHO", "LOGOFF"})
		void noFileIdToInherit(Command predecessor) {
			chain.processed(message(predecessor, 0, 1L, 2), message(predecessor, 0, 1L, 2));
			var request = close(RELATED, FileId.NONE);

			Assertions.assertEquals(OptionalInt.of(NTStatus.STATUS_INVALID_HANDLE), chain.fileIdRejection(request));
		}

		@Test
		@DisplayName("A related operation at the start of a chain has no FileId to work on")
		void relatedFirstOperation() {
			var request = close(RELATED, OPENED);

			Assertions.assertEquals(OptionalInt.of(NTStatus.STATUS_INVALID_HANDLE), chain.fileIdRejection(request));
		}

		@Test
		@DisplayName("Once a FileId was missing, all related operations after that fail with STATUS_INVALID_HANDLE, until an unrelated one starts over")
		void missingFileIdFailsRestOfChain() {
			chain.processed(message(Command.ECHO, 0, 1L, 2), message(Command.ECHO, 0, 1L, 2));
			var second = close(RELATED, FileId.NONE);
			chain.processed(second, ErrorResponse.create(second, NTStatus.STATUS_INVALID_HANDLE));
			var relatedCreate = message(Command.CREATE, RELATED, -1L, -1);
			var relatedCreateRejection = chain.fileIdRejection(relatedCreate);
			chain.processed(relatedCreate, ErrorResponse.create(relatedCreate, NTStatus.STATUS_INVALID_HANDLE));
			var unrelated = close(0, OPENED);
			var unrelatedRejection = chain.fileIdRejection(unrelated);
			chain.processed(unrelated, message(Command.CLOSE, 0, 1L, 2));
			var relatedAgain = close(RELATED, FileId.NONE);

			Assertions.assertEquals(OptionalInt.of(NTStatus.STATUS_INVALID_HANDLE), relatedCreateRejection);
			Assertions.assertTrue(unrelatedRejection.isEmpty());
			Assertions.assertTrue(chain.fileIdRejection(relatedAgain).isEmpty());
			Assertions.assertEquals(OPENED, chain.fileId());
		}

		@Test
		@DisplayName("A related operation following an unrelated one that is too short to hold a FileId fails with STATUS_INVALID_HANDLE")
		void malformedPredecessor() {
			var header = PacketHeader.builder().command(Command.CLOSE.value()).sessionId(1L).treeId(2).build();
			var first = new CloseRequest(header, MemorySegment.ofArray(new byte[4]));
			chain.processed(first, ErrorResponse.create(first, NTStatus.STATUS_INVALID_PARAMETER));
			var request = close(RELATED, FileId.NONE);

			Assertions.assertEquals(OptionalInt.of(NTStatus.STATUS_INVALID_HANDLE), chain.fileIdRejection(request));
		}

		private static CloseRequest close(int flags, FileId fileId) {
			var header = PacketHeader.builder().command(Command.CLOSE.value()).flags(flags).sessionId(1L).treeId(2).build();
			var body = MemorySegment.ofArray(new byte[24]);
			body.set(Layouts.LE_UINT16, 0, (char) 24);
			fileId.writeTo(body.asSlice(8, FileId.SIZE));
			return new CloseRequest(header, body);
		}

		private static CreateResponse created(FileId fileId) {
			var response = new CreateResponse(PacketHeader.builder().command(Command.CREATE.value()).build());
			response.fileId(fileId);
			return response;
		}
	}

	private static SMB2Message message(Command command, int flags, long sessionId, int treeId) {
		var header = PacketHeader.builder().command(command.value()).flags(flags).sessionId(sessionId).treeId(treeId).build();
		return new UnhandledRequest(header, MemorySegment.ofArray(new byte[0]));
	}
}
