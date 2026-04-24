package org.cryptomator.jsmb.smb2.io;

import org.cryptomator.jsmb.Config;
import org.cryptomator.jsmb.Credentials;
import org.cryptomator.jsmb.common.NTStatus;
import org.cryptomator.jsmb.share.OpenParams;
import org.cryptomator.jsmb.share.SmbOpen;
import org.cryptomator.jsmb.share.nio.NioShare;
import org.cryptomator.jsmb.smb2.Command;
import org.cryptomator.jsmb.smb2.Connection;
import org.cryptomator.jsmb.smb2.ErrorResponse;
import org.cryptomator.jsmb.share.FileId;
import org.cryptomator.jsmb.smb2.Global;
import org.cryptomator.jsmb.smb2.Open;
import org.cryptomator.jsmb.smb2.PacketHeader;
import org.cryptomator.jsmb.smb2.Session;
import org.cryptomator.jsmb.smb2.TreeConnect;
import org.cryptomator.jsmb.util.Layouts;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.nio.file.Files;
import java.nio.file.Path;

class WriteHandlerTest {

	@TempDir
	Path shareRoot;

	private Connection connection;
	private Session session;
	private TreeConnect treeConnect;
	private WriteHandler handler;
	private Open fileOpen;
	private Path targetFile;

	@BeforeEach
	void setUp() throws IOException {
		var global = new Global(Config.DEFAULT, new Credentials("DOMAIN", "user", "password"));
		connection = new Connection(global);
		var share = new NioShare(shareRoot);
		global.shares.put("data", share);
		session = Session.create(connection);
		int treeId = session.nextTreeId.getAndIncrement();
		treeConnect = new TreeConnect(treeId, "data", share, 0x001F01FF);
		session.treeConnectTable.put(treeId, treeConnect);
		handler = new WriteHandler(connection);

		targetFile = shareRoot.resolve("out.bin");
		Files.createFile(targetFile);
		// DesiredAccess FILE_WRITE_DATA (0x0002) | FILE_READ_DATA (0x0001); share all; OPEN disposition.
		SmbOpen backend = share.open("out.bin",
				new OpenParams(0x00120003, 0x00000007, OpenParams.Disposition.OPEN, 0));
		fileOpen = new Open(backend.fileId(), backend, session, treeConnect, "out.bin");
		session.openTable.put(fileOpen.fileId, fileOpen);
	}

	@Test
	@DisplayName("WRITE against an open handle writes the payload and reports Count=length")
	void writeToFile() throws IOException {
		byte[] payload = "hello-write".getBytes();
		var response = handler.write(buildWriteRequest(fileOpen.fileId, 0, payload));

		Assertions.assertInstanceOf(WriteResponse.class, response);
		Assertions.assertEquals(NTStatus.STATUS_SUCCESS, response.header().status());
		Assertions.assertEquals(payload.length, response.segment().get(Layouts.LE_INT32, 4));
		Assertions.assertArrayEquals(payload, Files.readAllBytes(targetFile));
	}

	@Test
	@DisplayName("WRITE at non-zero offset extends the file with a gap")
	void writeAtOffset() throws IOException {
		byte[] payload = "end".getBytes();
		var response = handler.write(buildWriteRequest(fileOpen.fileId, 5, payload));

		Assertions.assertInstanceOf(WriteResponse.class, response);
		Assertions.assertEquals(8, Files.size(targetFile));
		byte[] actual = Files.readAllBytes(targetFile);
		Assertions.assertArrayEquals("end".getBytes(), new byte[]{actual[5], actual[6], actual[7]});
	}

	@Test
	@DisplayName("WRITE with Length exceeding MaxWriteSize returns STATUS_INVALID_PARAMETER")
	void writeExceedsMaxWriteSize() {
		var body = new byte[48 + 1];
		var bodySeg = MemorySegment.ofArray(body);
		bodySeg.set(Layouts.LE_UINT16, 0, (char) 49);
		bodySeg.set(Layouts.LE_UINT16, 2, (char) (PacketHeader.STRUCTURE_SIZE + 48));
		bodySeg.set(Layouts.LE_INT32, 4, connection.maxWriteSize + 1);
		bodySeg.set(Layouts.LE_INT64, 8, 0);
		fileOpen.fileId.writeTo(bodySeg.asSlice(16, FileId.SIZE));

		var response = handler.write(new WriteRequest(buildHeader(Command.WRITE), bodySeg));

		Assertions.assertInstanceOf(ErrorResponse.class, response);
		Assertions.assertEquals(NTStatus.STATUS_INVALID_PARAMETER, response.header().status());
	}

	@Test
	@DisplayName("WRITE with unknown FileId returns STATUS_FILE_CLOSED")
	void unknownFileId() {
		var response = handler.write(buildWriteRequest(new FileId(0xAAL, 0xBBL), 0, "x".getBytes()));

		Assertions.assertInstanceOf(ErrorResponse.class, response);
		Assertions.assertEquals(NTStatus.STATUS_FILE_CLOSED, response.header().status());
	}

	@Test
	@DisplayName("WRITE with unknown SessionId returns STATUS_USER_SESSION_DELETED")
	void unknownSession() {
		var headerSeg = MemorySegment.ofArray(new byte[PacketHeader.STRUCTURE_SIZE]);
		headerSeg.set(Layouts.LE_INT32, 0, 0x424D53FE);
		headerSeg.set(Layouts.LE_UINT16, 4, PacketHeader.STRUCTURE_SIZE);
		headerSeg.set(Layouts.LE_UINT16, 12, Command.WRITE.value());
		headerSeg.set(Layouts.LE_INT32, 36, treeConnect.treeId());
		headerSeg.set(Layouts.LE_INT64, 40, 0xDEADBEEFL); // bogus session id

		var bodySeg = MemorySegment.ofArray(new byte[48 + 1]);
		bodySeg.set(Layouts.LE_UINT16, 0, (char) 49);
		bodySeg.set(Layouts.LE_UINT16, 2, (char) (PacketHeader.STRUCTURE_SIZE + 48));
		bodySeg.set(Layouts.LE_INT32, 4, 1);
		fileOpen.fileId.writeTo(bodySeg.asSlice(16, FileId.SIZE));

		var response = handler.write(new WriteRequest(new PacketHeader(headerSeg), bodySeg));

		Assertions.assertInstanceOf(ErrorResponse.class, response);
		Assertions.assertEquals(NTStatus.STATUS_USER_SESSION_DELETED, response.header().status());
	}

	@Test
	@DisplayName("FLUSH against an open handle returns a FlushResponse")
	void flushOpenHandle() {
		var response = handler.flush(buildFlushRequest(fileOpen.fileId));

		Assertions.assertInstanceOf(FlushResponse.class, response);
		Assertions.assertEquals(NTStatus.STATUS_SUCCESS, response.header().status());
	}

	@Test
	@DisplayName("FLUSH with unknown FileId returns STATUS_FILE_CLOSED")
	void flushUnknownFileId() {
		var response = handler.flush(buildFlushRequest(new FileId(0xAAL, 0xBBL)));

		Assertions.assertInstanceOf(ErrorResponse.class, response);
		Assertions.assertEquals(NTStatus.STATUS_FILE_CLOSED, response.header().status());
	}

	private WriteRequest buildWriteRequest(FileId fileId, long offset, byte[] data) {
		var bodySeg = MemorySegment.ofArray(new byte[48 + data.length]);
		bodySeg.set(Layouts.LE_UINT16, 0, (char) 49);
		bodySeg.set(Layouts.LE_UINT16, 2, (char) (PacketHeader.STRUCTURE_SIZE + 48));
		bodySeg.set(Layouts.LE_INT32, 4, data.length);
		bodySeg.set(Layouts.LE_INT64, 8, offset);
		fileId.writeTo(bodySeg.asSlice(16, FileId.SIZE));
		MemorySegment.copy(MemorySegment.ofArray(data), 0, bodySeg, 48, data.length);
		return new WriteRequest(buildHeader(Command.WRITE), bodySeg);
	}

	private FlushRequest buildFlushRequest(FileId fileId) {
		var bodySeg = MemorySegment.ofArray(new byte[24]);
		bodySeg.set(Layouts.LE_UINT16, 0, (char) 24);
		fileId.writeTo(bodySeg.asSlice(8, FileId.SIZE));
		return new FlushRequest(buildHeader(Command.FLUSH), bodySeg);
	}

	private PacketHeader buildHeader(Command command) {
		var headerSeg = MemorySegment.ofArray(new byte[PacketHeader.STRUCTURE_SIZE]);
		headerSeg.set(Layouts.LE_INT32, 0, 0x424D53FE);
		headerSeg.set(Layouts.LE_UINT16, 4, PacketHeader.STRUCTURE_SIZE);
		headerSeg.set(Layouts.LE_UINT16, 12, command.value());
		headerSeg.set(Layouts.LE_INT32, 36, treeConnect.treeId());
		headerSeg.set(Layouts.LE_INT64, 40, session.sessionId);
		return new PacketHeader(headerSeg);
	}
}
