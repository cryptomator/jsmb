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

class ReadHandlerTest {

	@TempDir
	Path shareRoot;

	private Connection connection;
	private Session session;
	private TreeConnect treeConnect;
	private ReadHandler handler;
	private Open fileOpen;

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
		handler = new ReadHandler(connection);

		Files.writeString(shareRoot.resolve("data.bin"), "hello-world-12345");
		SmbOpen backend = share.open("data.bin",
				new OpenParams(0x00120089, 0x00000007, OpenParams.Disposition.OPEN, 0));
		fileOpen = new Open(backend.fileId(), backend, session, treeConnect, "data.bin");
		session.openTable.put(fileOpen.fileId, fileOpen);
	}

	@Test
	@DisplayName("READ against an open handle returns the requested bytes at the requested offset")
	void readFromFile() {
		var response = handler.read(buildReadRequest(fileOpen.fileId, 0, 17, 0));

		Assertions.assertInstanceOf(ReadResponse.class, response);
		Assertions.assertEquals(NTStatus.STATUS_SUCCESS, response.header().status());
		byte[] data = response.segment().asSlice(ReadResponse.FIXED_PORTION_SIZE, 17).toArray(Layouts.BYTE);
		Assertions.assertEquals("hello-world-12345", new String(data));
	}

	@Test
	@DisplayName("READ past end-of-file returns STATUS_END_OF_FILE")
	void readPastEof() {
		var response = handler.read(buildReadRequest(fileOpen.fileId, 100, 10, 0));

		Assertions.assertInstanceOf(ErrorResponse.class, response);
		Assertions.assertEquals(NTStatus.STATUS_END_OF_FILE, response.header().status());
	}

	@Test
	@DisplayName("READ with Length exceeding MaxReadSize returns STATUS_INVALID_PARAMETER")
	void readExceedsMaxReadSize() {
		var response = handler.read(buildReadRequest(fileOpen.fileId, 0, connection.maxReadSize + 1, 0));

		Assertions.assertInstanceOf(ErrorResponse.class, response);
		Assertions.assertEquals(NTStatus.STATUS_INVALID_PARAMETER, response.header().status());
	}

	@Test
	@DisplayName("READ with unknown FileId returns STATUS_FILE_CLOSED")
	void unknownFileId() {
		var response = handler.read(buildReadRequest(new FileId(0xAAL, 0xBBL), 0, 1, 0));

		Assertions.assertInstanceOf(ErrorResponse.class, response);
		Assertions.assertEquals(NTStatus.STATUS_FILE_CLOSED, response.header().status());
	}

	@Test
	@DisplayName("READ returning fewer than MinimumCount bytes returns STATUS_END_OF_FILE")
	void belowMinimumCount() {
		// File is 17 bytes; read at offset 10 with MinimumCount 100 forces short-read → EOF.
		var response = handler.read(buildReadRequest(fileOpen.fileId, 10, 50, 100));

		Assertions.assertInstanceOf(ErrorResponse.class, response);
		Assertions.assertEquals(NTStatus.STATUS_END_OF_FILE, response.header().status());
	}

	@Test
	@DisplayName("READ partial (offset near EOF) returns the remaining bytes")
	void partialRead() {
		var response = handler.read(buildReadRequest(fileOpen.fileId, 12, 100, 0));

		Assertions.assertInstanceOf(ReadResponse.class, response);
		int length = response.segment().get(Layouts.LE_INT32, 4);
		Assertions.assertEquals(5, length);
		byte[] data = response.segment().asSlice(ReadResponse.FIXED_PORTION_SIZE, 5).toArray(Layouts.BYTE);
		Assertions.assertEquals("12345", new String(data));
	}

	private ReadRequest buildReadRequest(FileId fileId, long offset, int length, int minimumCount) {
		var headerSeg = MemorySegment.ofArray(new byte[PacketHeader.STRUCTURE_SIZE]);
		headerSeg.set(Layouts.LE_INT32, 0, 0x424D53FE);
		headerSeg.set(Layouts.LE_UINT16, 4, PacketHeader.STRUCTURE_SIZE);
		headerSeg.set(Layouts.LE_UINT16, 12, Command.READ.value());
		headerSeg.set(Layouts.LE_INT32, 36, treeConnect.treeId());
		headerSeg.set(Layouts.LE_INT64, 40, session.sessionId);

		var bodySeg = MemorySegment.ofArray(new byte[48]);
		bodySeg.set(Layouts.LE_UINT16, 0, (char) 49);
		bodySeg.set(Layouts.LE_INT32, 4, length);
		bodySeg.set(Layouts.LE_INT64, 8, offset);
		fileId.writeTo(bodySeg.asSlice(16, FileId.SIZE));
		bodySeg.set(Layouts.LE_INT32, 32, minimumCount);
		return new ReadRequest(new PacketHeader(headerSeg), bodySeg);
	}
}
