package org.cryptomator.jsmb.smb2.query;

import org.cryptomator.jsmb.Config;
import org.cryptomator.jsmb.common.NTStatus;
import org.cryptomator.jsmb.share.FileBasicInfo;
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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

class QueryDirectoryHandlerTest {

	@TempDir
	Path shareRoot;

	private Session session;
	private TreeConnect treeConnect;
	private QueryDirectoryHandler handler;
	private Open rootOpen;

	@BeforeEach
	void setUp() throws IOException {
		var global = new Global(Config.DEFAULT);
		var connection = new Connection(global);
		var share = new NioShare(shareRoot);
		global.shares.put("data", share);
		session = Session.create(connection);
		int treeId = session.nextTreeId.getAndIncrement();
		treeConnect = new TreeConnect(treeId, "data", share, 0x001F01FF);
		session.treeConnectTable.put(treeId, treeConnect);
		handler = new QueryDirectoryHandler(connection);

		// Open the share root as a directory so queries have somewhere to target.
		var backend = share.open("",
				new org.cryptomator.jsmb.share.OpenParams(0, 0,
						org.cryptomator.jsmb.share.OpenParams.Disposition.OPEN,
						org.cryptomator.jsmb.share.OpenParams.OPTION_DIRECTORY_FILE));
		rootOpen = new Open(backend.fileId(), backend, session, treeConnect, "");
		session.openTable.put(rootOpen.fileId, rootOpen);
	}

	@Test
	@DisplayName("Populated directory returns entries via FILE_ID_BOTH_DIRECTORY_INFORMATION")
	void populatedDirectory() throws IOException {
		Files.writeString(shareRoot.resolve("a.txt"), "one");
		Files.writeString(shareRoot.resolve("b.md"), "two");

		var response = handler.query(buildRequest(rootOpen.fileId,
				FileInformationClass.FILE_ID_BOTH_DIRECTORY_INFORMATION,
				QueryDirectoryRequest.FLAG_RESTART_SCAN, "*", 65536));

		Assertions.assertInstanceOf(QueryDirectoryResponse.class, response);
		Assertions.assertEquals(NTStatus.STATUS_SUCCESS, response.header().status());
		var buffer = extractOutputBuffer(response);
		var names = extractNamesIdBoth(buffer);
		java.util.Collections.sort(names);
		Assertions.assertEquals(java.util.List.of("a.txt", "b.md"), names);
	}

	@Test
	@DisplayName("Second call after a drained cursor returns STATUS_NO_MORE_FILES")
	void noMoreFilesAfterDrained() throws IOException {
		Files.createFile(shareRoot.resolve("one.txt"));

		// Drain on first call
		var first = handler.query(buildRequest(rootOpen.fileId,
				FileInformationClass.FILE_ID_BOTH_DIRECTORY_INFORMATION,
				QueryDirectoryRequest.FLAG_RESTART_SCAN, "*", 65536));
		Assertions.assertEquals(NTStatus.STATUS_SUCCESS, first.header().status());

		// Second call without RESTART → drained
		var second = handler.query(buildRequest(rootOpen.fileId,
				FileInformationClass.FILE_ID_BOTH_DIRECTORY_INFORMATION,
				(byte) 0, "*", 65536));

		Assertions.assertInstanceOf(ErrorResponse.class, second);
		Assertions.assertEquals(NTStatus.STATUS_NO_MORE_FILES, second.header().status());
	}

	@Test
	@DisplayName("Empty directory on the first call returns STATUS_NO_SUCH_FILE")
	void noSuchFileWhenEmpty() {
		var response = handler.query(buildRequest(rootOpen.fileId,
				FileInformationClass.FILE_ID_BOTH_DIRECTORY_INFORMATION,
				QueryDirectoryRequest.FLAG_RESTART_SCAN, "*", 65536));

		Assertions.assertInstanceOf(ErrorResponse.class, response);
		Assertions.assertEquals(NTStatus.STATUS_NO_SUCH_FILE, response.header().status());
	}

	@Test
	@DisplayName("Glob pattern restricts the returned entries")
	void globFilter() throws IOException {
		Files.createFile(shareRoot.resolve("first.txt"));
		Files.createFile(shareRoot.resolve("second.md"));
		Files.createFile(shareRoot.resolve("third.txt"));

		var response = handler.query(buildRequest(rootOpen.fileId,
				FileInformationClass.FILE_ID_BOTH_DIRECTORY_INFORMATION,
				QueryDirectoryRequest.FLAG_RESTART_SCAN, "*.txt", 65536));

		var names = extractNamesIdBoth(extractOutputBuffer(response));
		java.util.Collections.sort(names);
		Assertions.assertEquals(java.util.List.of("first.txt", "third.txt"), names);
	}

	@Test
	@DisplayName("Unknown FileInformationClass is rejected with STATUS_INVALID_INFO_CLASS")
	void unknownInfoClass() {
		var response = handler.query(buildRequestRaw(rootOpen.fileId, (byte) 99,
				QueryDirectoryRequest.FLAG_RESTART_SCAN, "*", 65536));

		Assertions.assertInstanceOf(ErrorResponse.class, response);
		Assertions.assertEquals(NTStatus.STATUS_INVALID_INFO_CLASS, response.header().status());
	}

	@Test
	@DisplayName("Unknown FileId returns STATUS_FILE_CLOSED")
	void unknownFileId() {
		var response = handler.query(buildRequest(new FileId(0xDEAD, 0xBEEF),
				FileInformationClass.FILE_ID_BOTH_DIRECTORY_INFORMATION,
				QueryDirectoryRequest.FLAG_RESTART_SCAN, "*", 65536));

		Assertions.assertInstanceOf(ErrorResponse.class, response);
		Assertions.assertEquals(NTStatus.STATUS_FILE_CLOSED, response.header().status());
	}

	@Test
	@DisplayName("Output buffer too small for even one entry returns STATUS_INFO_LENGTH_MISMATCH")
	void infoLengthMismatch() throws IOException {
		Files.createFile(shareRoot.resolve("file-with-a-fairly-long-name.txt"));

		var response = handler.query(buildRequest(rootOpen.fileId,
				FileInformationClass.FILE_ID_BOTH_DIRECTORY_INFORMATION,
				QueryDirectoryRequest.FLAG_RESTART_SCAN, "*", 32));

		Assertions.assertInstanceOf(ErrorResponse.class, response);
		Assertions.assertEquals(NTStatus.STATUS_INFO_LENGTH_MISMATCH, response.header().status());
	}

	@Test
	@DisplayName("SL_RETURN_SINGLE_ENTRY caps at one entry even when more would fit")
	void singleEntryFlag() throws IOException {
		Files.createFile(shareRoot.resolve("a"));
		Files.createFile(shareRoot.resolve("b"));
		Files.createFile(shareRoot.resolve("c"));

		var response = handler.query(buildRequest(rootOpen.fileId,
				FileInformationClass.FILE_ID_BOTH_DIRECTORY_INFORMATION,
				(byte) (QueryDirectoryRequest.FLAG_RESTART_SCAN | QueryDirectoryRequest.FLAG_RETURN_SINGLE_ENTRY),
				"*", 65536));

		Assertions.assertInstanceOf(QueryDirectoryResponse.class, response);
		Assertions.assertEquals(1, extractNamesIdBoth(extractOutputBuffer(response)).size());
	}

	@Test
	@DisplayName("Paginated enumeration resumes from the previous cursor")
	void pagination() throws IOException {
		// Create 3 entries, each ~104 + 2*N bytes in FILE_ID_BOTH. Size the buffer for one at a time.
		for (int i = 1; i <= 3; i++) {
			Files.createFile(shareRoot.resolve("f" + i));
		}
		// one entry of name "f1" (2 UTF-16 bytes ×? nope: "f1" = 2 chars = 4 bytes UTF-16LE)
		int nameBytes = 4;
		int oneEntry = ((104 + nameBytes) + 7) & ~7; // aligned

		var page1 = handler.query(buildRequest(rootOpen.fileId,
				FileInformationClass.FILE_ID_BOTH_DIRECTORY_INFORMATION,
				QueryDirectoryRequest.FLAG_RESTART_SCAN, "*", oneEntry));
		Assertions.assertInstanceOf(QueryDirectoryResponse.class, page1);
		var page1Names = extractNamesIdBoth(extractOutputBuffer(page1));
		Assertions.assertEquals(1, page1Names.size());

		var page2 = handler.query(buildRequest(rootOpen.fileId,
				FileInformationClass.FILE_ID_BOTH_DIRECTORY_INFORMATION,
				(byte) 0, "*", oneEntry));
		Assertions.assertInstanceOf(QueryDirectoryResponse.class, page2);
		var page2Names = extractNamesIdBoth(extractOutputBuffer(page2));
		Assertions.assertEquals(1, page2Names.size());

		var page3 = handler.query(buildRequest(rootOpen.fileId,
				FileInformationClass.FILE_ID_BOTH_DIRECTORY_INFORMATION,
				(byte) 0, "*", oneEntry));
		var page3Names = extractNamesIdBoth(extractOutputBuffer(page3));
		Assertions.assertEquals(1, page3Names.size());

		// All drained — next call is STATUS_NO_MORE_FILES.
		var done = handler.query(buildRequest(rootOpen.fileId,
				FileInformationClass.FILE_ID_BOTH_DIRECTORY_INFORMATION,
				(byte) 0, "*", oneEntry));
		Assertions.assertInstanceOf(ErrorResponse.class, done);
		Assertions.assertEquals(NTStatus.STATUS_NO_MORE_FILES, done.header().status());

		var seen = new java.util.TreeSet<String>();
		seen.addAll(page1Names);
		seen.addAll(page2Names);
		seen.addAll(page3Names);
		Assertions.assertEquals(java.util.Set.of("f1", "f2", "f3"), seen);
	}

	@Test
	@DisplayName("FILE_NAMES_INFORMATION writes the 12-byte compact records")
	void filenameInformationFormat() throws IOException {
		Files.createFile(shareRoot.resolve("just-a-name"));

		var response = handler.query(buildRequest(rootOpen.fileId,
				FileInformationClass.FILE_NAMES_INFORMATION,
				QueryDirectoryRequest.FLAG_RESTART_SCAN, "*", 65536));

		Assertions.assertInstanceOf(QueryDirectoryResponse.class, response);
		var buffer = extractOutputBuffer(response);
		var seg = MemorySegment.ofArray(buffer);
		int nameLen = seg.get(Layouts.LE_INT32, 8);
		var name = new String(buffer, 12, nameLen, StandardCharsets.UTF_16LE);
		Assertions.assertEquals("just-a-name", name);
	}

	@Test
	@DisplayName("Directory attribute bit is set for subdirectories")
	void directoryAttributeForSubdirs() throws IOException {
		Files.createDirectory(shareRoot.resolve("sub"));
		Files.createFile(shareRoot.resolve("file"));

		var response = handler.query(buildRequest(rootOpen.fileId,
				FileInformationClass.FILE_ID_BOTH_DIRECTORY_INFORMATION,
				QueryDirectoryRequest.FLAG_RESTART_SCAN, "*", 65536));

		var buffer = extractOutputBuffer(response);
		// iterate entries via NextEntryOffset chain; check each name → attributes
		int offset = 0;
		var seg = MemorySegment.ofArray(buffer);
		while (offset < buffer.length) {
			int next = seg.get(Layouts.LE_INT32, offset);
			int nameLen = seg.get(Layouts.LE_INT32, offset + 60);
			int attrs = seg.get(Layouts.LE_INT32, offset + 56);
			var name = new String(buffer, offset + 104, nameLen, StandardCharsets.UTF_16LE);
			if (name.equals("sub")) {
				Assertions.assertNotEquals(0, attrs & FileBasicInfo.ATTR_DIRECTORY, "directory bit set on 'sub'");
			} else if (name.equals("file")) {
				Assertions.assertEquals(0, attrs & FileBasicInfo.ATTR_DIRECTORY, "directory bit clear on 'file'");
			}
			if (next == 0) break;
			offset += next;
		}
	}

	private QueryDirectoryRequest buildRequest(FileId fileId, FileInformationClass cls, byte flags, String pattern, int outputBufferLength) {
		return buildRequestRaw(fileId, (byte) cls.value(), flags, pattern, outputBufferLength);
	}

	private QueryDirectoryRequest buildRequestRaw(FileId fileId, byte infoClassValue, byte flags, String pattern, int outputBufferLength) {
		byte[] patternBytes = pattern == null ? new byte[0] : pattern.getBytes(StandardCharsets.UTF_16LE);

		var headerSeg = MemorySegment.ofArray(new byte[PacketHeader.STRUCTURE_SIZE]);
		headerSeg.set(Layouts.LE_INT32, 0, 0x424D53FE);
		headerSeg.set(Layouts.LE_UINT16, 4, PacketHeader.STRUCTURE_SIZE);
		headerSeg.set(Layouts.LE_UINT16, 12, Command.QUERY_DIRECTORY.value());
		headerSeg.set(Layouts.LE_INT32, 36, treeConnect.treeId());
		headerSeg.set(Layouts.LE_INT64, 40, session.sessionId);

		var bodySeg = MemorySegment.ofArray(new byte[32 + patternBytes.length]);
		bodySeg.set(Layouts.LE_UINT16, 0, (char) 33);
		bodySeg.set(Layouts.BYTE, 2, infoClassValue);
		bodySeg.set(Layouts.BYTE, 3, flags);
		bodySeg.set(Layouts.LE_INT32, 4, 0);
		fileId.writeTo(bodySeg.asSlice(8, FileId.SIZE));
		bodySeg.set(Layouts.LE_UINT16, 24, (char) (PacketHeader.STRUCTURE_SIZE + 32));
		bodySeg.set(Layouts.LE_UINT16, 26, (char) patternBytes.length);
		bodySeg.set(Layouts.LE_INT32, 28, outputBufferLength);
		if (patternBytes.length > 0) {
			bodySeg.asSlice(32, patternBytes.length).copyFrom(MemorySegment.ofArray(patternBytes));
		}
		return new QueryDirectoryRequest(new PacketHeader(headerSeg), bodySeg);
	}

	private static byte[] extractOutputBuffer(org.cryptomator.jsmb.smb2.SMB2Message response) {
		var seg = response.segment();
		// OutputBufferOffset is relative to the SMB2 header; body segment starts right after the header.
		int offsetFromHeader = seg.get(Layouts.LE_UINT16, 2);
		int offsetInBody = offsetFromHeader - PacketHeader.STRUCTURE_SIZE;
		int length = seg.get(Layouts.LE_INT32, 4);
		return seg.asSlice(offsetInBody, length).toArray(Layouts.BYTE);
	}

	private static java.util.List<String> extractNamesIdBoth(byte[] buffer) {
		var seg = MemorySegment.ofArray(buffer);
		var names = new java.util.ArrayList<String>();
		int offset = 0;
		while (offset < buffer.length) {
			int next = seg.get(Layouts.LE_INT32, offset);
			int nameLen = seg.get(Layouts.LE_INT32, offset + 60);
			names.add(new String(buffer, offset + 104, nameLen, StandardCharsets.UTF_16LE));
			if (next == 0) break;
			offset += next;
		}
		return names;
	}
}
