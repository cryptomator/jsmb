package org.cryptomator.jsmb.smb2.io;

import org.cryptomator.jsmb.share.FileId;
import org.cryptomator.jsmb.smb2.PacketHeader;
import org.cryptomator.jsmb.util.Layouts;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.lang.foreign.MemorySegment;

class ReadMessageTest {

	@Nested
	@DisplayName("ReadRequest")
	class Req {

		@Test
		@DisplayName("Accessors read the 48-byte fixed portion (Length / Offset / FileId / MinimumCount / Channel / RemainingBytes)")
		void fixedFieldAccessors() {
			var body = new byte[48];
			var seg = MemorySegment.ofArray(body);
			seg.set(Layouts.LE_UINT16, 0, (char) 49);
			seg.set(Layouts.BYTE, 3, (byte) 0x00);                 // Flags
			seg.set(Layouts.LE_INT32, 4, 0x10000);                 // Length
			seg.set(Layouts.LE_INT64, 8, 0x1000L);                 // Offset
			seg.set(Layouts.LE_INT64, 16, 0x1122334455667788L);    // FileId persistent
			seg.set(Layouts.LE_INT64, 24, 0x99AABBCCDDEEFF00L);    // FileId volatile
			seg.set(Layouts.LE_INT32, 32, 1);                      // MinimumCount
			seg.set(Layouts.LE_INT32, 36, 0);                      // Channel
			seg.set(Layouts.LE_INT32, 40, 0);                      // RemainingBytes

			var request = new ReadRequest(null, seg);

			Assertions.assertEquals(49, request.structureSize());
			Assertions.assertEquals(0x10000, request.length());
			Assertions.assertEquals(0x1000L, request.offset());
			Assertions.assertEquals(0x1122334455667788L, request.fileId().persistentHandle());
			Assertions.assertEquals(0x99AABBCCDDEEFF00L, request.fileId().volatileHandle());
			Assertions.assertEquals(1, request.minimumCount());
			Assertions.assertEquals(0, request.channel());
			Assertions.assertEquals(0, request.remainingBytes());
		}

		@Test
		@DisplayName("fileId(FileId) writes the FileId back at offset 16 for sentinel substitution in compound chains")
		void fileIdSetter() {
			var body = new byte[48];
			var seg = MemorySegment.ofArray(body);
			seg.set(Layouts.LE_UINT16, 0, (char) 49);
			var request = new ReadRequest(null, seg);

			request.fileId(new FileId(0xFACEL, 0xFEEDL));

			Assertions.assertEquals(0xFACEL, seg.get(Layouts.LE_INT64, 16));
			Assertions.assertEquals(0xFEEDL, seg.get(Layouts.LE_INT64, 24));
		}
	}

	@Nested
	@DisplayName("ReadResponse")
	class Resp {

		@Test
		@DisplayName("Canonical constructor stamps StructureSize=17")
		void structureSizeStamped() {
			var response = new ReadResponse(PacketHeader.builder().build());
			Assertions.assertEquals(ReadResponse.STRUCTURE_SIZE, response.segment().get(Layouts.LE_UINT16, 0));
		}

		@Test
		@DisplayName("withData appends the buffer and sets DataOffset (SMB2 header + fixed portion) / DataLength")
		void withData() {
			byte[] payload = new byte[123];
			for (int i = 0; i < payload.length; i++) payload[i] = (byte) (i * 7);

			var response = new ReadResponse(PacketHeader.builder().build()).withData(payload);

			var seg = response.segment();
			Assertions.assertEquals(ReadResponse.FIXED_PORTION_SIZE + payload.length, seg.byteSize());
			Assertions.assertEquals((byte) (PacketHeader.STRUCTURE_SIZE + ReadResponse.FIXED_PORTION_SIZE),
					seg.get(Layouts.BYTE, 2));
			Assertions.assertEquals(payload.length, seg.get(Layouts.LE_INT32, 4));
			for (int i = 0; i < payload.length; i++) {
				Assertions.assertEquals(payload[i], seg.get(Layouts.BYTE, ReadResponse.FIXED_PORTION_SIZE + i));
			}
		}

		@Test
		@DisplayName("dataRemaining setter stamps offset 8")
		void dataRemainingSetter() {
			var response = new ReadResponse(PacketHeader.builder().build());
			response.dataRemaining(0x4242);
			Assertions.assertEquals(0x4242, response.segment().get(Layouts.LE_INT32, 8));
		}
	}
}
