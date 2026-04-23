package org.cryptomator.jsmb.smb2.query;

import org.cryptomator.jsmb.Config;
import org.cryptomator.jsmb.Credentials;
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
		var global = new Global(Config.DEFAULT, new Credentials("DOMAIN", "user", "password"));
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
	@DisplayName("Populated share root returns entries via FILE_ID_BOTH_DIRECTORY_INFORMATION with the synthetic '.' prepended")
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
		Assertions.assertEquals(java.util.List.of(".", "a.txt", "b.md"), names);
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
	@DisplayName("First call whose pattern matches nothing returns STATUS_NO_SUCH_FILE")
	void noSuchFileWhenNoMatches() throws IOException {
		Files.createFile(shareRoot.resolve("unmatched.txt"));
		// "*.nope" matches neither the real child nor the synthetic "." pseudo-entry.
		var response = handler.query(buildRequest(rootOpen.fileId,
				FileInformationClass.FILE_ID_BOTH_DIRECTORY_INFORMATION,
				QueryDirectoryRequest.FLAG_RESTART_SCAN, "*.nope", 65536));

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
	@DisplayName("Paginated enumeration resumes from the previous cursor across each page and then reports STATUS_NO_MORE_FILES")
	void pagination() throws IOException {
		// 3 real entries + 1 synthetic "." at the share root = 4 entries. Size the buffer for one at a time.
		for (int i = 1; i <= 3; i++) {
			Files.createFile(shareRoot.resolve("f" + i));
		}
		// One FILE_ID_BOTH entry is 104 bytes fixed + UTF-16LE name, 8-byte aligned. Names "f1"/"." are ≤ 4 bytes.
		int oneEntry = ((104 + 4) + 7) & ~7;

		var collected = new java.util.TreeSet<String>();
		byte flags = QueryDirectoryRequest.FLAG_RESTART_SCAN;
		for (int page = 1; page <= 4; page++) {
			var response = handler.query(buildRequest(rootOpen.fileId,
					FileInformationClass.FILE_ID_BOTH_DIRECTORY_INFORMATION, flags, "*", oneEntry));
			Assertions.assertInstanceOf(QueryDirectoryResponse.class, response, "page " + page + " should succeed");
			var names = extractNamesIdBoth(extractOutputBuffer(response));
			Assertions.assertEquals(1, names.size(), "page " + page + " should carry exactly one entry");
			collected.addAll(names);
			flags = 0;
		}

		// All four entries drained — the next call reports end-of-enumeration.
		var done = handler.query(buildRequest(rootOpen.fileId,
				FileInformationClass.FILE_ID_BOTH_DIRECTORY_INFORMATION, (byte) 0, "*", oneEntry));
		Assertions.assertInstanceOf(ErrorResponse.class, done);
		Assertions.assertEquals(NTStatus.STATUS_NO_MORE_FILES, done.header().status());

		Assertions.assertEquals(java.util.Set.of(".", "f1", "f2", "f3"), collected);
	}

	@Test
	@DisplayName("FILE_NAMES_INFORMATION writes the 12-byte compact records")
	void filenameInformationFormat() throws IOException {
		Files.createFile(shareRoot.resolve("just-a-name"));

		// Narrow the pattern so the synthetic "." entry doesn't land first and we can assert the fixed
		// header layout (12-byte base + UTF-16LE name) directly against the single surviving entry.
		var response = handler.query(buildRequest(rootOpen.fileId,
				FileInformationClass.FILE_NAMES_INFORMATION,
				QueryDirectoryRequest.FLAG_RESTART_SCAN, "just-a-name", 65536));

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
