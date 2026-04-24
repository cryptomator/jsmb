package org.cryptomator.jsmb.smb2.info;

import org.cryptomator.jsmb.share.FileId;
import org.cryptomator.jsmb.smb2.PacketHeader;
import org.cryptomator.jsmb.util.Layouts;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.lang.foreign.MemorySegment;

class SetInfoMessageTest {

	@Nested
	@DisplayName("SetInfoRequest")
	class Req {

		@Test
		@DisplayName("Accessors read the 32-byte fixed portion (InfoType / FileInfoClass / BufferOffset / BufferLength / FileId)")
		void fixedFieldAccessors() {
			var body = new byte[32];
			var seg = MemorySegment.ofArray(body);
			seg.set(Layouts.LE_UINT16, 0, (char) 33);
			seg.set(Layouts.BYTE, 2, SetInfoRequest.INFO_TYPE_FILE);
			seg.set(Layouts.BYTE, 3, (byte) FileInfoClass.FILE_BASIC_INFORMATION.value());
			seg.set(Layouts.LE_INT32, 4, 40);                                       // BufferLength
			seg.set(Layouts.LE_UINT16, 8, (char) (PacketHeader.STRUCTURE_SIZE + 32)); // BufferOffset
			seg.set(Layouts.LE_INT32, 12, 0);                                        // AdditionalInformation
			seg.set(Layouts.LE_INT64, 16, 0x1122334455667788L);                      // FileId persistent
			seg.set(Layouts.LE_INT64, 24, 0x99AABBCCDDEEFF00L);                      // FileId volatile

			var request = new SetInfoRequest(null, seg);

			Assertions.assertEquals(33, request.structureSize());
			Assertions.assertEquals(SetInfoRequest.INFO_TYPE_FILE, request.infoType());
			Assertions.assertEquals(FileInfoClass.FILE_BASIC_INFORMATION.value(), request.fileInfoClass());
			Assertions.assertEquals(40, request.bufferLength());
			Assertions.assertEquals(PacketHeader.STRUCTURE_SIZE + 32, request.bufferOffset());
			Assertions.assertEquals(0, request.additionalInformation());
			Assertions.assertEquals(0x1122334455667788L, request.fileId().persistentHandle());
			Assertions.assertEquals(0x99AABBCCDDEEFF00L, request.fileId().volatileHandle());
		}

		@Test
		@DisplayName("buffer() slices the payload from BufferOffset with BufferLength bytes")
		void bufferSlice() {
			byte[] payload = new byte[]{1, 2, 3, 4, 5};
			var body = new byte[32 + payload.length];
			var seg = MemorySegment.ofArray(body);
			seg.set(Layouts.LE_UINT16, 0, (char) 33);
			seg.set(Layouts.LE_INT32, 4, payload.length);
			seg.set(Layouts.LE_UINT16, 8, (char) (PacketHeader.STRUCTURE_SIZE + 32));
			MemorySegment.copy(MemorySegment.ofArray(payload), 0, seg, 32, payload.length);

			var request = new SetInfoRequest(null, seg);

			Assertions.assertArrayEquals(payload, request.buffer().toArray(Layouts.BYTE));
		}

		@Test
		@DisplayName("fileId(FileId) writes the FileId back at offset 16 for sentinel substitution in compound chains")
		void fileIdSetter() {
			var body = new byte[32];
			var seg = MemorySegment.ofArray(body);
			seg.set(Layouts.LE_UINT16, 0, (char) 33);
			var request = new SetInfoRequest(null, seg);

			request.fileId(new FileId(0xFACEL, 0xFEEDL));

			Assertions.assertEquals(0xFACEL, seg.get(Layouts.LE_INT64, 16));
			Assertions.assertEquals(0xFEEDL, seg.get(Layouts.LE_INT64, 24));
		}
	}

	@Nested
	@DisplayName("SetInfoResponse")
	class Resp {

		@Test
		@DisplayName("Canonical constructor stamps StructureSize=2")
		void structureSizeStamped() {
			var response = new SetInfoResponse(PacketHeader.builder().build());
			Assertions.assertEquals(SetInfoResponse.STRUCTURE_SIZE, response.segment().get(Layouts.LE_UINT16, 0));
			Assertions.assertEquals(SetInfoResponse.FIXED_PORTION_SIZE, response.segment().byteSize());
		}
	}
}
