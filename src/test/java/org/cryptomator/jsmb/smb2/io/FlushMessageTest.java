package org.cryptomator.jsmb.smb2.io;

import org.cryptomator.jsmb.share.FileId;
import org.cryptomator.jsmb.smb2.PacketHeader;
import org.cryptomator.jsmb.util.Layouts;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.lang.foreign.MemorySegment;

class FlushMessageTest {

	@Nested
	@DisplayName("FlushRequest")
	class Req {

		@Test
		@DisplayName("Accessors read StructureSize and FileId from the 24-byte fixed structure")
		void accessors() {
			var body = new byte[24];
			var seg = MemorySegment.ofArray(body);
			seg.set(Layouts.LE_UINT16, 0, (char) 24);
			seg.set(Layouts.LE_INT64, 8, 0x1122334455667788L);
			seg.set(Layouts.LE_INT64, 16, 0x99AABBCCDDEEFF00L);

			var request = new FlushRequest(null, seg);

			Assertions.assertEquals(24, request.structureSize());
			Assertions.assertEquals(0x1122334455667788L, request.fileId().persistentHandle());
			Assertions.assertEquals(0x99AABBCCDDEEFF00L, request.fileId().volatileHandle());
		}

		@Test
		@DisplayName("fileId(FileId) writes the FileId back at offset 8 for sentinel substitution in compound chains")
		void fileIdSetter() {
			var body = new byte[24];
			var seg = MemorySegment.ofArray(body);
			seg.set(Layouts.LE_UINT16, 0, (char) 24);
			var request = new FlushRequest(null, seg);

			request.fileId(new FileId(0xFACEL, 0xFEEDL));

			Assertions.assertEquals(0xFACEL, seg.get(Layouts.LE_INT64, 8));
			Assertions.assertEquals(0xFEEDL, seg.get(Layouts.LE_INT64, 16));
		}
	}

	@Nested
	@DisplayName("FlushResponse")
	class Resp {

		@Test
		@DisplayName("Canonical constructor stamps StructureSize=4")
		void structureSizeStamped() {
			var response = new FlushResponse(PacketHeader.builder().build());
			Assertions.assertEquals(FlushResponse.STRUCTURE_SIZE, response.segment().get(Layouts.LE_UINT16, 0));
			Assertions.assertEquals(FlushResponse.FIXED_PORTION_SIZE, response.segment().byteSize());
		}
	}
}
