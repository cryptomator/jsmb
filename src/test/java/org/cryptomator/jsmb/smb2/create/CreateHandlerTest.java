package org.cryptomator.jsmb.smb2.create;

import org.cryptomator.jsmb.Config;
import org.cryptomator.jsmb.common.NTStatus;
import org.cryptomator.jsmb.share.OpenParams;
import org.cryptomator.jsmb.share.nio.NioShare;
import org.cryptomator.jsmb.smb2.Command;
import org.cryptomator.jsmb.smb2.Connection;
import org.cryptomator.jsmb.smb2.ErrorResponse;
import org.cryptomator.jsmb.smb2.FileId;
import org.cryptomator.jsmb.smb2.Global;
import org.cryptomator.jsmb.smb2.PacketHeader;
import org.cryptomator.jsmb.smb2.Session;
import org.cryptomator.jsmb.smb2.TreeConnect;
import org.cryptomator.jsmb.util.Layouts;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

class CreateHandlerTest {

	@TempDir
	Path shareRoot;

	private Connection connection;
	private Session session;
	private NioShare share;
	private TreeConnect treeConnect;
	private CreateHandler handler;

	@BeforeEach
	void setUp() {
		var global = new Global(Config.DEFAULT);
		connection = new Connection(global);
		share = new NioShare(shareRoot);
		global.shares.put("data", share);
		session = Session.create(connection);
		session.signingRequired = true;
		int treeId = session.nextTreeId.getAndIncrement();
		treeConnect = new TreeConnect(treeId, "data", share, 0x001F01FF);
		session.treeConnectTable.put(treeId, treeConnect);
		handler = new CreateHandler(connection);
	}

	@Nested
	@DisplayName("create")
	class CreatePath {

		@Test
		@DisplayName("CREATE with CREATE disposition for a new file materializes it on disk")
		void createNewFile() {
			var response = handler.create(buildCreateRequest("new.txt", OpenParams.Disposition.CREATE, 0));

			Assertions.assertInstanceOf(CreateResponse.class, response);
			Assertions.assertEquals(NTStatus.STATUS_SUCCESS, response.header().status());
			Assertions.assertTrue(Files.isRegularFile(shareRoot.resolve("new.txt")));
			Assertions.assertEquals(CreateResponse.CREATE_ACTION_CREATED,
					response.segment().get(Layouts.LE_INT32, 4));
			Assertions.assertEquals(1, session.openTable.size());
		}

		@Test
		@DisplayName("CREATE with FILE_DIRECTORY_FILE + CREATE creates a directory (mkdir)")
		void createNewDirectory() {
			var response = handler.create(buildCreateRequest("newdir", OpenParams.Disposition.CREATE, OpenParams.OPTION_DIRECTORY_FILE));

			Assertions.assertInstanceOf(CreateResponse.class, response);
			Assertions.assertEquals(NTStatus.STATUS_SUCCESS, response.header().status());
			Assertions.assertTrue(Files.isDirectory(shareRoot.resolve("newdir")));
		}

		@Test
		@DisplayName("CREATE with OPEN on a missing path returns STATUS_OBJECT_NAME_NOT_FOUND")
		void openMissingFileFails() {
			var response = handler.create(buildCreateRequest("ghost.txt", OpenParams.Disposition.OPEN, 0));

			Assertions.assertInstanceOf(ErrorResponse.class, response);
			Assertions.assertEquals(NTStatus.STATUS_OBJECT_NAME_NOT_FOUND, response.header().status());
			Assertions.assertTrue(session.openTable.isEmpty());
		}

		@Test
		@DisplayName("CREATE with CREATE on an existing path returns STATUS_OBJECT_NAME_COLLISION")
		void createExistingFileFails() throws IOException {
			Files.createFile(shareRoot.resolve("existing.txt"));

			var response = handler.create(buildCreateRequest("existing.txt", OpenParams.Disposition.CREATE, 0));

			Assertions.assertInstanceOf(ErrorResponse.class, response);
			Assertions.assertEquals(NTStatus.STATUS_OBJECT_NAME_COLLISION, response.header().status());
		}

		@Test
		@DisplayName("CREATE translates NT backslash path separators to forward slashes")
		void backslashesInNameAreNormalized() throws IOException {
			Files.createDirectory(shareRoot.resolve("sub"));

			var response = handler.create(buildCreateRequest("sub\\file.txt", OpenParams.Disposition.CREATE, 0));

			Assertions.assertInstanceOf(CreateResponse.class, response);
			Assertions.assertTrue(Files.exists(shareRoot.resolve("sub/file.txt")));
		}

		@Test
		@DisplayName("CREATE against IPC$ (null-share tree) returns STATUS_OBJECT_NAME_NOT_FOUND")
		void ipcTreeRejects() {
			int ipcTreeId = session.nextTreeId.getAndIncrement();
			session.treeConnectTable.put(ipcTreeId, new TreeConnect(ipcTreeId, "IPC$", null, 0));
			var request = buildCreateRequestOn(ipcTreeId, "any-pipe", OpenParams.Disposition.OPEN, 0);

			var response = handler.create(request);

			Assertions.assertInstanceOf(ErrorResponse.class, response);
			Assertions.assertEquals(NTStatus.STATUS_OBJECT_NAME_NOT_FOUND, response.header().status());
		}

		@Test
		@DisplayName("CREATE with FILE_DELETE_ON_CLOSE marks the backend for deletion")
		void deleteOnCloseRemovesOnClose() {
			var createResp = handler.create(buildCreateRequest("doomed.txt", OpenParams.Disposition.CREATE, OpenParams.OPTION_DELETE_ON_CLOSE));
			Assertions.assertInstanceOf(CreateResponse.class, createResp);

			var fid = FileId.fromSegment(createResp.segment().asSlice(64, FileId.SIZE));
			handler.close(buildCloseRequest(fid, false));

			Assertions.assertFalse(Files.exists(shareRoot.resolve("doomed.txt")));
		}

		@Test
		@DisplayName("CREATE with unknown TreeId returns STATUS_NETWORK_NAME_DELETED")
		void unknownTreeId() {
			var request = buildCreateRequestOn(0xFEEDFACE, "foo.txt", OpenParams.Disposition.OPEN, 0);

			var response = handler.create(request);

			Assertions.assertInstanceOf(ErrorResponse.class, response);
			Assertions.assertEquals(NTStatus.STATUS_NETWORK_NAME_DELETED, response.header().status());
		}
	}

	@Nested
	@DisplayName("close")
	class ClosePath {

		@Test
		@DisplayName("CLOSE removes the Open from the session table and releases the backend")
		void closeRemovesOpen() {
			var createResp = handler.create(buildCreateRequest("file.txt", OpenParams.Disposition.CREATE, 0));
			var fid = FileId.fromSegment(createResp.segment().asSlice(64, FileId.SIZE));
			Assertions.assertEquals(1, session.openTable.size());

			var response = handler.close(buildCloseRequest(fid, false));

			Assertions.assertInstanceOf(CloseResponse.class, response);
			Assertions.assertEquals(NTStatus.STATUS_SUCCESS, response.header().status());
			Assertions.assertTrue(session.openTable.isEmpty());
		}

		@Test
		@DisplayName("CLOSE with POSTQUERY_ATTRIB populates the response timestamps + size")
		void postQueryAttrib() throws IOException {
			Files.writeString(shareRoot.resolve("info.txt"), "hello");
			var createResp = handler.create(buildCreateRequest("info.txt", OpenParams.Disposition.OPEN, 0));
			var fid = FileId.fromSegment(createResp.segment().asSlice(64, FileId.SIZE));

			var response = handler.close(buildCloseRequest(fid, true));

			Assertions.assertInstanceOf(CloseResponse.class, response);
			Assertions.assertEquals(CloseRequest.FLAG_POSTQUERY_ATTRIB,
					response.segment().get(Layouts.LE_UINT16, 2));
			Assertions.assertEquals(5L, response.segment().get(Layouts.LE_INT64, 48)); // endOfFile
		}

		@Test
		@DisplayName("CLOSE of a FileId not in the open table returns STATUS_FILE_CLOSED")
		void unknownFileIdReturnsFileClosed() {
			var response = handler.close(buildCloseRequest(new FileId(0x12, 0x34), false));

			Assertions.assertInstanceOf(ErrorResponse.class, response);
			Assertions.assertEquals(NTStatus.STATUS_FILE_CLOSED, response.header().status());
		}
	}

	private CreateRequest buildCreateRequest(String name, OpenParams.Disposition disposition, int createOptions) {
		return buildCreateRequestOn(treeConnect.treeId(), name, disposition, createOptions);
	}

	private CreateRequest buildCreateRequestOn(int treeId, String name, OpenParams.Disposition disposition, int createOptions) {
		byte[] nameBytes = name.getBytes(StandardCharsets.UTF_16LE);

		var headerSeg = MemorySegment.ofArray(new byte[PacketHeader.STRUCTURE_SIZE]);
		headerSeg.set(Layouts.LE_INT32, 0, 0x424D53FE);
		headerSeg.set(Layouts.LE_UINT16, 4, PacketHeader.STRUCTURE_SIZE);
		headerSeg.set(Layouts.LE_UINT16, 12, Command.CREATE.value());
		headerSeg.set(Layouts.LE_INT32, 36, treeId);
		headerSeg.set(Layouts.LE_INT64, 40, session.sessionId);

		var bodySeg = MemorySegment.ofArray(new byte[56 + nameBytes.length]);
		bodySeg.set(Layouts.LE_UINT16, 0, (char) 57);
		bodySeg.set(Layouts.LE_INT32, 24, 0x00120089); // DesiredAccess
		bodySeg.set(Layouts.LE_INT32, 32, 0x00000007); // ShareAccess
		bodySeg.set(Layouts.LE_INT32, 36, dispositionWireValue(disposition));
		bodySeg.set(Layouts.LE_INT32, 40, createOptions);
		bodySeg.set(Layouts.LE_UINT16, 44, (char) (PacketHeader.STRUCTURE_SIZE + 56));
		bodySeg.set(Layouts.LE_UINT16, 46, (char) nameBytes.length);
		bodySeg.asSlice(56, nameBytes.length).copyFrom(MemorySegment.ofArray(nameBytes));

		return new CreateRequest(new PacketHeader(headerSeg), bodySeg);
	}

	private CloseRequest buildCloseRequest(FileId fileId, boolean postQueryAttrib) {
		var headerSeg = MemorySegment.ofArray(new byte[PacketHeader.STRUCTURE_SIZE]);
		headerSeg.set(Layouts.LE_INT32, 0, 0x424D53FE);
		headerSeg.set(Layouts.LE_UINT16, 4, PacketHeader.STRUCTURE_SIZE);
		headerSeg.set(Layouts.LE_UINT16, 12, Command.CLOSE.value());
		headerSeg.set(Layouts.LE_INT32, 36, treeConnect.treeId());
		headerSeg.set(Layouts.LE_INT64, 40, session.sessionId);

		var bodySeg = MemorySegment.ofArray(new byte[24]);
		bodySeg.set(Layouts.LE_UINT16, 0, (char) 24);
		if (postQueryAttrib) {
			bodySeg.set(Layouts.LE_UINT16, 2, CloseRequest.FLAG_POSTQUERY_ATTRIB);
		}
		fileId.writeTo(bodySeg.asSlice(8, FileId.SIZE));
		return new CloseRequest(new PacketHeader(headerSeg), bodySeg);
	}

	private static int dispositionWireValue(OpenParams.Disposition d) {
		return switch (d) {
			case SUPERSEDE -> 0;
			case OPEN -> 1;
			case CREATE -> 2;
			case OPEN_IF -> 3;
			case OVERWRITE -> 4;
			case OVERWRITE_IF -> 5;
		};
	}
}
