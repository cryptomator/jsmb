package org.cryptomator.jsmb.smb2;

import org.cryptomator.jsmb.common.NTStatus;
import org.cryptomator.jsmb.util.Layouts;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.foreign.MemorySegment;
import java.util.HexFormat;

class ErrorResponseTest {

	@Test
	@DisplayName("Wire body of a fresh ERROR response is exactly 9 bytes with StructureSize=9 at offset 0")
	void wireLayoutIsSpecCompliant() {
		var stubRequest = new StubRequest(PacketHeader.builder().command(Command.CREATE.value()).messageId(42L).build());

		var response = ErrorResponse.create(stubRequest, NTStatus.STATUS_OBJECT_NAME_NOT_FOUND);

		var body = response.segment();
		Assertions.assertEquals(9, body.byteSize(), "fixed portion(8) + 1 stub ErrorData byte");
		Assertions.assertEquals(9, body.get(Layouts.LE_UINT16, 0), "StructureSize field MUST be 9 per MS-SMB2 2.2.2");
		Assertions.assertEquals(0, body.get(Layouts.BYTE, 2), "ErrorContextCount = 0");
		Assertions.assertEquals(0, body.get(Layouts.BYTE, 3), "Reserved = 0");
		Assertions.assertEquals(0, body.get(Layouts.LE_INT32, 4), "ByteCount = 0");
		Assertions.assertEquals(0, body.get(Layouts.BYTE, 8), "ErrorData stub byte = 0");
	}

	@Test
	@DisplayName("ERROR response header preserves status, command, and messageId from the request")
	void headerFieldsPreserved() {
		var requestHeader = PacketHeader.builder()
				.command(Command.CREATE.value())
				.messageId(42L)
				.sessionId(0x1234L)
				.treeId(0x5678)
				.build();
		var stubRequest = new StubRequest(requestHeader);

		var response = ErrorResponse.create(stubRequest, NTStatus.STATUS_OBJECT_NAME_NOT_FOUND);

		Assertions.assertEquals(NTStatus.STATUS_OBJECT_NAME_NOT_FOUND, response.header().status());
		Assertions.assertEquals(Command.CREATE.value(), response.header().command());
		Assertions.assertEquals(42L, response.header().messageId());
		Assertions.assertEquals(0x1234L, response.header().sessionId());
		Assertions.assertEquals(0x5678, response.header().treeId());
	}

	@Test
	@DisplayName("Full on-the-wire bytes match the expected layout for STATUS_OBJECT_NAME_NOT_FOUND")
	void serializedBytesMatchSpec() {
		var requestHeader = PacketHeader.builder()
				.command(Command.CREATE.value())
				.messageId(3L)
				.sessionId(2L)
				.treeId(1)
				.build();
		var stubRequest = new StubRequest(requestHeader);

		var response = ErrorResponse.create(stubRequest, NTStatus.STATUS_OBJECT_NAME_NOT_FOUND);
		byte[] wire = response.serialize();

		Assertions.assertEquals(64 + 9, wire.length);
		String bodyHex = HexFormat.of().formatHex(wire, 64, wire.length);
		Assertions.assertEquals("090000000000000000", bodyHex,
				"body = StructureSize(0900) + ErrorContextCount+Reserved(0000) + ByteCount(00000000) + ErrorData(00)");
	}

	private record StubRequest(PacketHeader header) implements SMB2Message {
		@Override
		public MemorySegment segment() {
			return MemorySegment.ofArray(new byte[0]);
		}
	}
}
