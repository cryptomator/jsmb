package org.cryptomator.jsmb.smb2.info;

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
import org.cryptomator.jsmb.util.WinFileTime;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

class SetInfoHandlerTest {

	@TempDir
	Path shareRoot;

	private Connection connection;
	private Session session;
	private TreeConnect treeConnect;
	private SetInfoHandler handler;
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
		handler = new SetInfoHandler(connection);

		targetFile = shareRoot.resolve("target.bin");
		Files.writeString(targetFile, "content");
		// DELETE | WRITE_DATA — needed for delete and rename
		SmbOpen backend = share.open("target.bin",
				new OpenParams(0x00130196, 0x00000007, OpenParams.Disposition.OPEN, 0));
		fileOpen = new Open(backend.fileId(), backend, session, treeConnect, "target.bin");
		session.openTable.put(fileOpen.fileId, fileOpen);
	}

	@Test
	@DisplayName("FileDispositionInformation with DeletePending=1 marks the open for deletion on close")
	void dispositionDelete() throws IOException {
		var response = handler.set(buildRequest(SetInfoRequest.INFO_TYPE_FILE, (byte) 13, new byte[]{1}));

		Assertions.assertInstanceOf(SetInfoResponse.class, response);
		Assertions.assertEquals(NTStatus.STATUS_SUCCESS, response.header().status());
		// markForDeletion is recorded on the backend; actually unlinking happens in CLOSE.
		Assertions.assertTrue(fileOpen.backend.queryStandard().deletePending());
		// file still exists until close
		Assertions.assertTrue(Files.exists(targetFile));

		fileOpen.backend.close();
		Assertions.assertFalse(Files.exists(targetFile));
	}

	@Test
	@DisplayName("FileRenameInformation moves the target and updates the backend's path")
	void renameFile() throws IOException {
		String newName = "renamed.bin";
		byte[] nameBytes = newName.getBytes(StandardCharsets.UTF_16LE);
		byte[] payload = new byte[20 + nameBytes.length];
		payload[0] = 1; // ReplaceIfExists
		// bytes 1-7 Reserved, 8-15 RootDirectory, 16-19 FileNameLength (LE int32)
		var seg = MemorySegment.ofArray(payload);
		seg.set(Layouts.LE_INT32, 16, nameBytes.length);
		System.arraycopy(nameBytes, 0, payload, 20, nameBytes.length);

		var response = handler.set(buildRequest(SetInfoRequest.INFO_TYPE_FILE, (byte) 10, payload));

		Assertions.assertInstanceOf(SetInfoResponse.class, response);
		Assertions.assertEquals(NTStatus.STATUS_SUCCESS, response.header().status());
		Assertions.assertFalse(Files.exists(targetFile));
		Assertions.assertTrue(Files.exists(shareRoot.resolve(newName)));
	}

	@Test
	@DisplayName("FileRenameInformation to an existing name without ReplaceIfExists returns STATUS_OBJECT_NAME_COLLISION")
	void renameCollision() throws IOException {
		Files.createFile(shareRoot.resolve("existing.bin"));
		String newName = "existing.bin";
		byte[] nameBytes = newName.getBytes(StandardCharsets.UTF_16LE);
		byte[] payload = new byte[20 + nameBytes.length];
		payload[0] = 0; // ReplaceIfExists = false
		var seg = MemorySegment.ofArray(payload);
		seg.set(Layouts.LE_INT32, 16, nameBytes.length);
		System.arraycopy(nameBytes, 0, payload, 20, nameBytes.length);

		var response = handler.set(buildRequest(SetInfoRequest.INFO_TYPE_FILE, (byte) 10, payload));

		Assertions.assertInstanceOf(ErrorResponse.class, response);
		Assertions.assertEquals(NTStatus.STATUS_OBJECT_NAME_COLLISION, response.header().status());
	}

	@Test
	@DisplayName("FileEndOfFileInformation truncates the file to the requested length")
	void truncateFile() throws IOException {
		byte[] payload = new byte[8];
		MemorySegment.ofArray(payload).set(Layouts.LE_INT64, 0, 3L);

		var response = handler.set(buildRequest(SetInfoRequest.INFO_TYPE_FILE, (byte) 20, payload));

		Assertions.assertInstanceOf(SetInfoResponse.class, response);
		Assertions.assertEquals(NTStatus.STATUS_SUCCESS, response.header().status());
		Assertions.assertEquals(3, Files.size(targetFile));
		Assertions.assertEquals("con", Files.readString(targetFile));
	}

	@Test
	@DisplayName("FileEndOfFileInformation extends the file to the requested length with zero padding")
	void extendFile() throws IOException {
		byte[] payload = new byte[8];
		MemorySegment.ofArray(payload).set(Layouts.LE_INT64, 0, 20L);

		var response = handler.set(buildRequest(SetInfoRequest.INFO_TYPE_FILE, (byte) 20, payload));

		Assertions.assertInstanceOf(SetInfoResponse.class, response);
		Assertions.assertEquals(NTStatus.STATUS_SUCCESS, response.header().status());
		Assertions.assertEquals(20, Files.size(targetFile));
	}

	@Test
	@DisplayName("FileBasicInformation updates lastWriteTime")
	void setBasicInformation() throws IOException {
		Instant newWriteTime = Instant.parse("2020-06-15T12:34:56Z").truncatedTo(ChronoUnit.SECONDS);
		byte[] payload = new byte[40];
		var seg = MemorySegment.ofArray(payload);
		// CreationTime=0 (unchanged), LastAccessTime=0, LastWriteTime set, ChangeTime=0
		seg.set(Layouts.LE_INT64, 16, WinFileTime.fromInstant(newWriteTime));

		var response = handler.set(buildRequest(SetInfoRequest.INFO_TYPE_FILE, (byte) 4, payload));

		Assertions.assertInstanceOf(SetInfoResponse.class, response);
		Assertions.assertEquals(NTStatus.STATUS_SUCCESS, response.header().status());
		var actual = Files.getLastModifiedTime(targetFile).toInstant().truncatedTo(ChronoUnit.SECONDS);
		Assertions.assertEquals(newWriteTime, actual);
	}

	@Test
	@DisplayName("SET_INFO with unknown FileInfoClass returns STATUS_INVALID_INFO_CLASS")
	void unknownClass() {
		var response = handler.set(buildRequest(SetInfoRequest.INFO_TYPE_FILE, (byte) 99, new byte[8]));

		Assertions.assertInstanceOf(ErrorResponse.class, response);
		Assertions.assertEquals(NTStatus.STATUS_INVALID_INFO_CLASS, response.header().status());
	}

	@Test
	@DisplayName("SET_INFO with InfoType=SECURITY returns STATUS_NOT_SUPPORTED")
	void securityInfoTypeNotSupported() {
		var response = handler.set(buildRequest(SetInfoRequest.INFO_TYPE_SECURITY, (byte) 0, new byte[4]));

		Assertions.assertInstanceOf(ErrorResponse.class, response);
		Assertions.assertEquals(NTStatus.STATUS_NOT_SUPPORTED, response.header().status());
	}

	@Test
	@DisplayName("SET_INFO with unknown FileId returns STATUS_FILE_CLOSED")
	void unknownFileId() {
		var bogus = new FileId(0xAAL, 0xBBL);
		var request = buildRequestForFileId(bogus, SetInfoRequest.INFO_TYPE_FILE, (byte) 13, new byte[]{1});

		var response = handler.set(request);

		Assertions.assertInstanceOf(ErrorResponse.class, response);
		Assertions.assertEquals(NTStatus.STATUS_FILE_CLOSED, response.header().status());
	}

	private SetInfoRequest buildRequest(byte infoType, byte fileInfoClass, byte[] payload) {
		return buildRequestForFileId(fileOpen.fileId, infoType, fileInfoClass, payload);
	}

	private SetInfoRequest buildRequestForFileId(FileId fileId, byte infoType, byte fileInfoClass, byte[] payload) {
		var headerSeg = MemorySegment.ofArray(new byte[PacketHeader.STRUCTURE_SIZE]);
		headerSeg.set(Layouts.LE_INT32, 0, 0x424D53FE);
		headerSeg.set(Layouts.LE_UINT16, 4, PacketHeader.STRUCTURE_SIZE);
		headerSeg.set(Layouts.LE_UINT16, 12, Command.SET_INFO.value());
		headerSeg.set(Layouts.LE_INT32, 36, treeConnect.treeId());
		headerSeg.set(Layouts.LE_INT64, 40, session.sessionId);

		var bodySeg = MemorySegment.ofArray(new byte[32 + payload.length]);
		bodySeg.set(Layouts.LE_UINT16, 0, (char) 33);
		bodySeg.set(Layouts.BYTE, 2, infoType);
		bodySeg.set(Layouts.BYTE, 3, fileInfoClass);
		bodySeg.set(Layouts.LE_INT32, 4, payload.length);
		bodySeg.set(Layouts.LE_UINT16, 8, (char) (PacketHeader.STRUCTURE_SIZE + 32));
		fileId.writeTo(bodySeg.asSlice(16, FileId.SIZE));
		MemorySegment.copy(MemorySegment.ofArray(payload), 0, bodySeg, 32, payload.length);
		return new SetInfoRequest(new PacketHeader(headerSeg), bodySeg);
	}
}
