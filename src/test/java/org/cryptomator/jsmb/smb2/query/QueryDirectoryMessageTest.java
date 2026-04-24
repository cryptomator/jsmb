package org.cryptomator.jsmb.smb2.query;

import org.cryptomator.jsmb.share.FileId;
import org.cryptomator.jsmb.smb2.PacketHeader;
import org.cryptomator.jsmb.util.Layouts;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.lang.foreign.MemorySegment;
import java.nio.charset.StandardCharsets;

class QueryDirectoryMessageTest {

	@Nested
	@DisplayName("QueryDirectoryRequest")
	class QueryReq {

		@Test
		@DisplayName("Fixed-field accessors read StructureSize / FileInfoClass / Flags / FileIndex / FileId / OutputBufferLength")
		void fixedFieldAccessors() {
			var body = new byte[32];
			var seg = MemorySegment.ofArray(body);
			seg.set(Layouts.LE_UINT16, 0, (char) 33);
			seg.set(Layouts.BYTE, 2, (byte) 0x25); // FileIdBothDirectoryInformation
			seg.set(Layouts.BYTE, 3, QueryDirectoryRequest.FLAG_RESTART_SCAN);
			seg.set(Layouts.LE_INT32, 4, 0);
			seg.set(Layouts.LE_INT64, 8, 0x1122334455667788L);
			seg.set(Layouts.LE_INT64, 16, 0x99AABBCCDDEEFF00L);
			seg.set(Layouts.LE_UINT16, 24, (char) (PacketHeader.STRUCTURE_SIZE + 32));
			seg.set(Layouts.LE_UINT16, 26, (char) 0);
			seg.set(Layouts.LE_INT32, 28, 0x10000);

			var request = new QueryDirectoryRequest(null, seg);

			Assertions.assertEquals(33, request.structureSize());
			Assertions.assertEquals(0x25, request.fileInformationClass());
			Assertions.assertEquals(QueryDirectoryRequest.FLAG_RESTART_SCAN, request.flags());
			Assertions.assertTrue(request.hasFlag(QueryDirectoryRequest.FLAG_RESTART_SCAN));
			Assertions.assertFalse(request.hasFlag(QueryDirectoryRequest.FLAG_RETURN_SINGLE_ENTRY));
			Assertions.assertEquals(0, request.fileIndex());
			Assertions.assertEquals(0x1122334455667788L, request.fileId().persistentHandle());
			Assertions.assertEquals(0x99AABBCCDDEEFF00L, request.fileId().volatileHandle());
			Assertions.assertEquals(0x10000, request.outputBufferLength());
		}

		@Test
		@DisplayName("fileId(FileId) writes the FileId back at offset 8 for sentinel substitution in compound chains")
		void fileIdSetter() {
			var body = new byte[32];
			var seg = MemorySegment.ofArray(body);
			seg.set(Layouts.LE_UINT16, 0, (char) 33);
			var request = new QueryDirectoryRequest(null, seg);

			request.fileId(new FileId(0x1234L, 0x5678L));

			Assertions.assertEquals(0x1234L, seg.get(Layouts.LE_INT64, 8));
			Assertions.assertEquals(0x5678L, seg.get(Layouts.LE_INT64, 16));
		}

		@Test
		@DisplayName("fileName() decodes the UTF-16LE search pattern")
		void fileNameDecoding() {
			var pattern = "*.txt";
			var patternBytes = pattern.getBytes(StandardCharsets.UTF_16LE);
			var body = new byte[32 + patternBytes.length];
			var seg = MemorySegment.ofArray(body);
			seg.set(Layouts.LE_UINT16, 0, (char) 33);
			seg.set(Layouts.LE_UINT16, 24, (char) (PacketHeader.STRUCTURE_SIZE + 32));
			seg.set(Layouts.LE_UINT16, 26, (char) patternBytes.length);
			seg.asSlice(32, patternBytes.length).copyFrom(MemorySegment.ofArray(patternBytes));

			Assertions.assertEquals(pattern, new QueryDirectoryRequest(null, seg).fileName());
		}

		@Test
		@DisplayName("fileName() returns empty string when FileNameLength is zero")
		void emptyFileName() {
			var body = new byte[32];
			MemorySegment.ofArray(body).set(Layouts.LE_UINT16, 0, (char) 33);
			Assertions.assertEquals("", new QueryDirectoryRequest(null, MemorySegment.ofArray(body)).fileName());
		}

		@Test
		@DisplayName("Multiple flag bits can be decoded independently")
		void combinedFlags() {
			var body = new byte[32];
			var seg = MemorySegment.ofArray(body);
			seg.set(Layouts.LE_UINT16, 0, (char) 33);
			seg.set(Layouts.BYTE, 3, (byte) (QueryDirectoryRequest.FLAG_RESTART_SCAN | QueryDirectoryRequest.FLAG_RETURN_SINGLE_ENTRY));
			var request = new QueryDirectoryRequest(null, seg);

			Assertions.assertTrue(request.hasFlag(QueryDirectoryRequest.FLAG_RESTART_SCAN));
			Assertions.assertTrue(request.hasFlag(QueryDirectoryRequest.FLAG_RETURN_SINGLE_ENTRY));
			Assertions.assertFalse(request.hasFlag(QueryDirectoryRequest.FLAG_INDEX_SPECIFIED));
		}
	}

	@Nested
	@DisplayName("QueryDirectoryResponse")
	class QueryResp {

		@Test
		@DisplayName("StructureSize is stamped to 9 by the canonical constructor")
		void structureSizeStamped() {
			var response = new QueryDirectoryResponse(PacketHeader.builder().build());
			Assertions.assertEquals(QueryDirectoryResponse.STRUCTURE_SIZE, response.segment().get(Layouts.LE_UINT16, 0));
		}

		@Test
		@DisplayName("withOutputBuffer appends the buffer and sets OutputBufferOffset / Length")
		void withBufferSetsOffsetAndLength() {
			byte[] payload = new byte[123];
			for (int i = 0; i < payload.length; i++) payload[i] = (byte) i;

			var response = new QueryDirectoryResponse(PacketHeader.builder().build()).withOutputBuffer(payload);

			var seg = response.segment();
			Assertions.assertEquals(PacketHeader.STRUCTURE_SIZE + QueryDirectoryResponse.FIXED_PORTION_SIZE, seg.get(Layouts.LE_UINT16, 2));
			Assertions.assertEquals(payload.length, seg.get(Layouts.LE_INT32, 4));
			Assertions.assertArrayEquals(payload, seg.asSlice(QueryDirectoryResponse.FIXED_PORTION_SIZE, payload.length).toArray(Layouts.BYTE));
		}
	}
}
