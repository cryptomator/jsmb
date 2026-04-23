package org.cryptomator.jsmb.smb2.info;

import org.cryptomator.jsmb.smb2.PacketHeader;
import org.cryptomator.jsmb.util.Layouts;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.lang.foreign.MemorySegment;

class QueryInfoMessageTest {

	@Nested
	@DisplayName("QueryInfoRequest")
	class Req {

		@Test
		@DisplayName("Accessors read the 40-byte fixed portion (InfoType / FileInfoClass / OutputBufferLength / FileId)")
		void fixedFieldAccessors() {
			var body = new byte[40];
			var seg = MemorySegment.ofArray(body);
			seg.set(Layouts.LE_UINT16, 0, (char) 41);
			seg.set(Layouts.BYTE, 2, QueryInfoRequest.INFO_TYPE_FILESYSTEM);
			seg.set(Layouts.BYTE, 3, (byte) 0x07);        // FileFsFullSizeInformation
			seg.set(Layouts.LE_INT32, 4, 0x10000);        // OutputBufferLength
			seg.set(Layouts.LE_UINT16, 8, (char) 0);      // InputBufferOffset
			seg.set(Layouts.LE_INT32, 12, 0);             // InputBufferLength
			seg.set(Layouts.LE_INT32, 16, 0);             // AdditionalInformation
			seg.set(Layouts.LE_INT32, 20, 0);             // Flags
			seg.set(Layouts.LE_INT64, 24, 0x1122334455667788L);
			seg.set(Layouts.LE_INT64, 32, 0x99AABBCCDDEEFF00L);

			var request = new QueryInfoRequest(null, seg);

			Assertions.assertEquals(41, request.structureSize());
			Assertions.assertEquals(QueryInfoRequest.INFO_TYPE_FILESYSTEM, request.infoType());
			Assertions.assertEquals(0x07, request.fileInfoClass());
			Assertions.assertEquals(0x10000, request.outputBufferLength());
			Assertions.assertEquals(0x1122334455667788L, request.fileId().persistentHandle());
			Assertions.assertEquals(0x99AABBCCDDEEFF00L, request.fileId().volatileHandle());
		}
	}

	@Nested
	@DisplayName("QueryInfoResponse")
	class Resp {

		@Test
		@DisplayName("Canonical constructor stamps StructureSize=9")
		void structureSizeStamped() {
			var response = new QueryInfoResponse(PacketHeader.builder().build());
			Assertions.assertEquals(QueryInfoResponse.STRUCTURE_SIZE, response.segment().get(Layouts.LE_UINT16, 0));
		}

		@Test
		@DisplayName("withOutputBuffer appends the buffer and sets OutputBufferOffset / Length")
		void outputBuffer() {
			byte[] payload = new byte[32];
			for (int i = 0; i < payload.length; i++) payload[i] = (byte) i;

			var response = new QueryInfoResponse(PacketHeader.builder().build()).withOutputBuffer(payload);

			var seg = response.segment();
			Assertions.assertEquals(PacketHeader.STRUCTURE_SIZE + QueryInfoResponse.FIXED_PORTION_SIZE, seg.get(Layouts.LE_UINT16, 2));
			Assertions.assertEquals(payload.length, seg.get(Layouts.LE_INT32, 4));
			Assertions.assertArrayEquals(payload, seg.asSlice(QueryInfoResponse.FIXED_PORTION_SIZE, payload.length).toArray(Layouts.BYTE));
		}
	}
}
