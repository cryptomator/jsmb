package org.cryptomator.jsmb.smb2.io;

import org.cryptomator.jsmb.share.FileId;
import org.cryptomator.jsmb.smb2.PacketHeader;
import org.cryptomator.jsmb.util.Layouts;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.lang.foreign.MemorySegment;

class WriteMessageTest {

	@Nested
	@DisplayName("WriteRequest")
	class Req {

		@Test
		@DisplayName("Accessors read the 48-byte fixed portion (Length / Offset / FileId / Channel / RemainingBytes / Flags)")
		void fixedFieldAccessors() {
			var body = new byte[48];
			var seg = MemorySegment.ofArray(body);
			seg.set(Layouts.LE_UINT16, 0, (char) 49);
			seg.set(Layouts.LE_UINT16, 2, (char) (PacketHeader.STRUCTURE_SIZE + 48)); // DataOffset
			seg.set(Layouts.LE_INT32, 4, 0x1000);                                      // Length
			seg.set(Layouts.LE_INT64, 8, 0x200L);                                      // Offset
			seg.set(Layouts.LE_INT64, 16, 0x1122334455667788L);                        // FileId persistent
			seg.set(Layouts.LE_INT64, 24, 0x99AABBCCDDEEFF00L);                        // FileId volatile
			seg.set(Layouts.LE_INT32, 32, 0);                                          // Channel
			seg.set(Layouts.LE_INT32, 36, 0x4242);                                     // RemainingBytes
			seg.set(Layouts.LE_UINT16, 40, (char) 0);                                  // WriteChannelInfoOffset
			seg.set(Layouts.LE_UINT16, 42, (char) 0);                                  // WriteChannelInfoLength
			seg.set(Layouts.LE_INT32, 44, 0x00000001);                                 // Flags = WRITE_THROUGH

			var request = new WriteRequest(null, seg);

			Assertions.assertEquals(49, request.structureSize());
			Assertions.assertEquals(PacketHeader.STRUCTURE_SIZE + 48, request.dataOffset());
			Assertions.assertEquals(0x1000, request.length());
			Assertions.assertEquals(0x200L, request.offset());
			Assertions.assertEquals(0x1122334455667788L, request.fileId().persistentHandle());
			Assertions.assertEquals(0x99AABBCCDDEEFF00L, request.fileId().volatileHandle());
			Assertions.assertEquals(0, request.channel());
			Assertions.assertEquals(0x4242, request.remainingBytes());
			Assertions.assertEquals(0, request.writeChannelInfoOffset());
			Assertions.assertEquals(0, request.writeChannelInfoLength());
			Assertions.assertEquals(0x00000001, request.flags());
		}

		@Test
		@DisplayName("data() slices the payload from DataOffset with Length bytes")
		void dataSlice() {
			byte[] payload = "hello write".getBytes();
			var body = new byte[48 + payload.length];
			var seg = MemorySegment.ofArray(body);
			seg.set(Layouts.LE_UINT16, 0, (char) 49);
			seg.set(Layouts.LE_UINT16, 2, (char) (PacketHeader.STRUCTURE_SIZE + 48));
			seg.set(Layouts.LE_INT32, 4, payload.length);
			MemorySegment.copy(MemorySegment.ofArray(payload), 0, seg, 48, payload.length);

			var request = new WriteRequest(null, seg);

			byte[] extracted = request.data().toArray(Layouts.BYTE);
			Assertions.assertArrayEquals(payload, extracted);
		}

		@Test
		@DisplayName("fileId(FileId) writes the FileId back at offset 16 for sentinel substitution in compound chains")
		void fileIdSetter() {
			var body = new byte[48];
			var seg = MemorySegment.ofArray(body);
			seg.set(Layouts.LE_UINT16, 0, (char) 49);
			var request = new WriteRequest(null, seg);

			request.fileId(new FileId(0xFACEL, 0xFEEDL));

			Assertions.assertEquals(0xFACEL, seg.get(Layouts.LE_INT64, 16));
			Assertions.assertEquals(0xFEEDL, seg.get(Layouts.LE_INT64, 24));
		}
	}

	@Nested
	@DisplayName("WriteResponse")
	class Resp {

		@Test
		@DisplayName("Canonical constructor stamps StructureSize=17")
		void structureSizeStamped() {
			var response = new WriteResponse(PacketHeader.builder().build());
			Assertions.assertEquals(WriteResponse.STRUCTURE_SIZE, response.segment().get(Layouts.LE_UINT16, 0));
		}

		@Test
		@DisplayName("count setter stamps offset 4")
		void countSetter() {
			var response = new WriteResponse(PacketHeader.builder().build());
			response.count(0x1234);
			Assertions.assertEquals(0x1234, response.segment().get(Layouts.LE_INT32, 4));
		}

		@Test
		@DisplayName("remaining setter stamps offset 8")
		void remainingSetter() {
			var response = new WriteResponse(PacketHeader.builder().build());
			response.remaining(0x4242);
			Assertions.assertEquals(0x4242, response.segment().get(Layouts.LE_INT32, 8));
		}
	}
}
