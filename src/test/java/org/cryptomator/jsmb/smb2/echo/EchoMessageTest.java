package org.cryptomator.jsmb.smb2.echo;

import org.cryptomator.jsmb.smb2.PacketHeader;
import org.cryptomator.jsmb.util.Layouts;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.lang.foreign.MemorySegment;

class EchoMessageTest {

	@Nested
	@DisplayName("EchoRequest")
	class Req {

		@Test
		@DisplayName("structureSize() reads the 2-byte StructureSize from offset 0")
		void structureSize() {
			var seg = MemorySegment.ofArray(new byte[4]);
			seg.set(Layouts.LE_UINT16, 0, (char) 4);

			var request = new EchoRequest(null, seg);

			Assertions.assertEquals(4, request.structureSize());
		}
	}

	@Nested
	@DisplayName("EchoResponse")
	class Resp {

		@Test
		@DisplayName("Canonical constructor stamps StructureSize=4 and allocates a 4-byte body")
		void structureSizeStamped() {
			var response = new EchoResponse(PacketHeader.builder().build());

			Assertions.assertEquals(EchoResponse.STRUCTURE_SIZE, response.segment().get(Layouts.LE_UINT16, 0));
			Assertions.assertEquals(EchoResponse.FIXED_PORTION_SIZE, response.segment().byteSize());
		}
	}

	@Nested
	@DisplayName("CancelRequest")
	class Cancel {

		@Test
		@DisplayName("structureSize() reads the 2-byte StructureSize from offset 0")
		void structureSize() {
			var seg = MemorySegment.ofArray(new byte[4]);
			seg.set(Layouts.LE_UINT16, 0, (char) 4);

			var request = new CancelRequest(null, seg);

			Assertions.assertEquals(4, request.structureSize());
		}
	}
}
