package org.cryptomator.jsmb.smb2.info;

import org.cryptomator.jsmb.Credentials;
import org.cryptomator.jsmb.TcpServer;
import org.cryptomator.jsmb.common.NTStatus;
import org.cryptomator.jsmb.share.OpenParams;
import org.cryptomator.jsmb.share.nio.NioShare;
import org.cryptomator.jsmb.smb2.Command;
import org.cryptomator.jsmb.smb2.Connection;
import org.cryptomator.jsmb.smb2.ErrorResponse;
import org.cryptomator.jsmb.smb2.FileId;
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
import java.lang.reflect.Constructor;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

class QueryInfoHandlerTest {

	@TempDir
	Path shareRoot;

	private TcpServer server;
	private Session session;
	private TreeConnect treeConnect;
	private QueryInfoHandler handler;
	private Open fileOpen;

	@BeforeEach
	void setUp() throws Exception {
		// spin up a real TcpServer so we have a populated startTime
		server = TcpServer.start(0, new Credentials("DOMAIN", "user", "password"));
		var global = server.global;
		var share = new NioShare(shareRoot);
		global.shares.put("data", share);

		var connection = constructConnection(global);
		session = Session.create(connection);
		int treeId = session.nextTreeId.getAndIncrement();
		treeConnect = new TreeConnect(treeId, "data", share, 0x001F01FF);
		session.treeConnectTable.put(treeId, treeConnect);
		handler = new QueryInfoHandler(server, connection);

		Files.writeString(shareRoot.resolve("demo.txt"), "hello");
		var backend = share.open("demo.txt",
				new OpenParams(0, 0, OpenParams.Disposition.OPEN, 0));
		fileOpen = new Open(backend.fileId(), backend, session, treeConnect, "demo.txt");
		session.openTable.put(fileOpen.fileId, fileOpen);
	}

	private static Connection constructConnection(Global global) throws Exception {
		// Connection's constructor is public; keeping reflection-free is easier but we need the same
		// instance that the server created, which is per-TcpConnection. For unit tests here a fresh one is fine.
		var ctor = Connection.class.getDeclaredConstructor(Global.class);
		Constructor<?> c = ctor;
		return (Connection) c.newInstance(global);
	}

	@org.junit.jupiter.api.AfterEach
	void tearDown() throws IOException {
		if (server != null) server.close();
	}

	@Test
	@DisplayName("FILE + FileStandardInformation returns sizes and flags")
	void fileStandardInformation() {
		var response = handler.query(buildRequest(
				QueryInfoRequest.INFO_TYPE_FILE,
				(byte) FileInfoClass.FILE_STANDARD_INFORMATION.value(),
				fileOpen.fileId, 4096));

		Assertions.assertInstanceOf(QueryInfoResponse.class, response);
		Assertions.assertEquals(NTStatus.STATUS_SUCCESS, response.header().status());
		var buffer = extractOutput(response);
		Assertions.assertEquals(24, buffer.length);
		var seg = MemorySegment.ofArray(buffer);
		Assertions.assertEquals(5L, seg.get(Layouts.LE_INT64, 8), "endOfFile = 5 (len of 'hello')");
	}

	@Test
	@DisplayName("FILE + FileNameInformation returns backslash-delimited absolute name from share root")
	void fileNameInformation() {
		var response = handler.query(buildRequest(
				QueryInfoRequest.INFO_TYPE_FILE,
				(byte) FileInfoClass.FILE_NAME_INFORMATION.value(),
				fileOpen.fileId, 4096));

		var buffer = extractOutput(response);
		int len = MemorySegment.ofArray(buffer).get(Layouts.LE_INT32, 0);
		Assertions.assertEquals("\\demo.txt", new String(buffer, 4, len, StandardCharsets.UTF_16LE));
	}

	@Test
	@DisplayName("FILE + FileAllInformation packs Basic + Standard + … + Name into a single composite")
	void fileAllInformation() {
		var response = handler.query(buildRequest(
				QueryInfoRequest.INFO_TYPE_FILE,
				(byte) FileInfoClass.FILE_ALL_INFORMATION.value(),
				fileOpen.fileId, 4096));

		Assertions.assertInstanceOf(QueryInfoResponse.class, response);
		var buffer = extractOutput(response);
		Assertions.assertTrue(buffer.length > 96, "composite output exceeds the 96-byte fixed prefix");
		var seg = MemorySegment.ofArray(buffer);
		Assertions.assertEquals(5L, seg.get(Layouts.LE_INT64, 48), "endOfFile inside the Standard section");
	}

	@Test
	@DisplayName("FILESYSTEM + FileFsFullSizeInformation returns the 32-byte full-size struct")
	void fsFullSizeInformation() {
		var response = handler.query(buildRequest(
				QueryInfoRequest.INFO_TYPE_FILESYSTEM,
				(byte) FsInfoClass.FILE_FS_FULL_SIZE_INFORMATION.value(),
				fileOpen.fileId, 4096));

		Assertions.assertInstanceOf(QueryInfoResponse.class, response);
		var buffer = extractOutput(response);
		Assertions.assertEquals(32, buffer.length);
		var seg = MemorySegment.ofArray(buffer);
		Assertions.assertTrue(seg.get(Layouts.LE_INT64, 0) > 0, "total allocation units > 0");
	}

	@Test
	@DisplayName("FILESYSTEM + FileFsAttributeInformation encodes the filesystem name as UTF-16LE")
	void fsAttributeInformation() {
		var response = handler.query(buildRequest(
				QueryInfoRequest.INFO_TYPE_FILESYSTEM,
				(byte) FsInfoClass.FILE_FS_ATTRIBUTE_INFORMATION.value(),
				fileOpen.fileId, 4096));

		var buffer = extractOutput(response);
		var seg = MemorySegment.ofArray(buffer);
		int nameLen = seg.get(Layouts.LE_INT32, 8);
		Assertions.assertEquals("NTFS", new String(buffer, 12, nameLen, StandardCharsets.UTF_16LE));
	}

	@Test
	@DisplayName("Unsupported FILE info class returns STATUS_INVALID_INFO_CLASS")
	void unsupportedFileClass() {
		var response = handler.query(buildRequest(
				QueryInfoRequest.INFO_TYPE_FILE, (byte) 99, fileOpen.fileId, 4096));

		Assertions.assertInstanceOf(ErrorResponse.class, response);
		Assertions.assertEquals(NTStatus.STATUS_INVALID_INFO_CLASS, response.header().status());
	}

	@Test
	@DisplayName("Unsupported FILESYSTEM info class returns STATUS_INVALID_INFO_CLASS")
	void unsupportedFsClass() {
		var response = handler.query(buildRequest(
				QueryInfoRequest.INFO_TYPE_FILESYSTEM, (byte) 99, fileOpen.fileId, 4096));

		Assertions.assertInstanceOf(ErrorResponse.class, response);
		Assertions.assertEquals(NTStatus.STATUS_INVALID_INFO_CLASS, response.header().status());
	}

	@Test
	@DisplayName("InfoType=SECURITY returns STATUS_NOT_SUPPORTED")
	void securityNotSupported() {
		var response = handler.query(buildRequest(
				QueryInfoRequest.INFO_TYPE_SECURITY, (byte) 0, fileOpen.fileId, 4096));

		Assertions.assertInstanceOf(ErrorResponse.class, response);
		Assertions.assertEquals(NTStatus.STATUS_NOT_SUPPORTED, response.header().status());
	}

	@Test
	@DisplayName("Unknown FileId returns STATUS_FILE_CLOSED")
	void unknownFileId() {
		var response = handler.query(buildRequest(
				QueryInfoRequest.INFO_TYPE_FILE,
				(byte) FileInfoClass.FILE_BASIC_INFORMATION.value(),
				new FileId(0xDEAD, 0xBEEF), 4096));

		Assertions.assertInstanceOf(ErrorResponse.class, response);
		Assertions.assertEquals(NTStatus.STATUS_FILE_CLOSED, response.header().status());
	}

	@Test
	@DisplayName("OutputBufferLength too small for the info class returns STATUS_INFO_LENGTH_MISMATCH")
	void outputBufferTooSmall() {
		// FileBasicInformation is 40 bytes; cap at 16.
		var response = handler.query(buildRequest(
				QueryInfoRequest.INFO_TYPE_FILE,
				(byte) FileInfoClass.FILE_BASIC_INFORMATION.value(),
				fileOpen.fileId, 16));

		Assertions.assertInstanceOf(ErrorResponse.class, response);
		Assertions.assertEquals(NTStatus.STATUS_INFO_LENGTH_MISMATCH, response.header().status());
	}

	private QueryInfoRequest buildRequest(byte infoType, byte fileInfoClass, FileId fileId, int outputBufferLength) {
		var headerSeg = MemorySegment.ofArray(new byte[PacketHeader.STRUCTURE_SIZE]);
		headerSeg.set(Layouts.LE_INT32, 0, 0x424D53FE);
		headerSeg.set(Layouts.LE_UINT16, 4, PacketHeader.STRUCTURE_SIZE);
		headerSeg.set(Layouts.LE_UINT16, 12, Command.QUERY_INFO.value());
		headerSeg.set(Layouts.LE_INT32, 36, treeConnect.treeId());
		headerSeg.set(Layouts.LE_INT64, 40, session.sessionId);

		var bodySeg = MemorySegment.ofArray(new byte[40]);
		bodySeg.set(Layouts.LE_UINT16, 0, (char) 41);
		bodySeg.set(Layouts.BYTE, 2, infoType);
		bodySeg.set(Layouts.BYTE, 3, fileInfoClass);
		bodySeg.set(Layouts.LE_INT32, 4, outputBufferLength);
		fileId.writeTo(bodySeg.asSlice(24, FileId.SIZE));
		return new QueryInfoRequest(new PacketHeader(headerSeg), bodySeg);
	}

	private static byte[] extractOutput(org.cryptomator.jsmb.smb2.SMB2Message response) {
		var seg = response.segment();
		int offsetFromHeader = seg.get(Layouts.LE_UINT16, 2);
		int length = seg.get(Layouts.LE_INT32, 4);
		return seg.asSlice(offsetFromHeader - PacketHeader.STRUCTURE_SIZE, length).toArray(Layouts.BYTE);
	}
}
