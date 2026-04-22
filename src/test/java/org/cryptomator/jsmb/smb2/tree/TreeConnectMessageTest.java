package org.cryptomator.jsmb.smb2.tree;

import org.cryptomator.jsmb.smb2.PacketHeader;
import org.cryptomator.jsmb.util.Layouts;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.lang.foreign.MemorySegment;
import java.nio.charset.StandardCharsets;

class TreeConnectMessageTest {

	@Nested
	@DisplayName("TreeConnectRequest")
	class ConnectRequest {

		@Test
		@DisplayName("Accessors return StructureSize, Flags, PathOffset and PathLength from the wire bytes")
		void fixedFieldAccessors() {
			var body = new byte[8];
			var seg = MemorySegment.ofArray(body);
			seg.set(Layouts.LE_UINT16, 0, (char) 9);
			seg.set(Layouts.LE_UINT16, 2, (char) 0x0004);
			seg.set(Layouts.LE_UINT16, 4, (char) (PacketHeader.STRUCTURE_SIZE + 8));
			seg.set(Layouts.LE_UINT16, 6, (char) 0);

			var request = new TreeConnectRequest(null, seg);

			Assertions.assertEquals(9, request.structureSize());
			Assertions.assertEquals(0x0004, request.flags());
			Assertions.assertEquals(PacketHeader.STRUCTURE_SIZE + 8, request.pathOffset());
			Assertions.assertEquals(0, request.pathLength());
		}

		@Test
		@DisplayName("path() decodes the UTF-16LE buffer at PathOffset")
		void pathDecoding() {
			var path = "\\\\localhost\\data";
			var pathBytes = path.getBytes(StandardCharsets.UTF_16LE);
			var body = new byte[8 + pathBytes.length];
			var seg = MemorySegment.ofArray(body);
			seg.set(Layouts.LE_UINT16, 0, (char) 9);
			seg.set(Layouts.LE_UINT16, 4, (char) (PacketHeader.STRUCTURE_SIZE + 8));
			seg.set(Layouts.LE_UINT16, 6, (char) pathBytes.length);
			seg.asSlice(8, pathBytes.length).copyFrom(MemorySegment.ofArray(pathBytes));

			var request = new TreeConnectRequest(null, seg);

			Assertions.assertEquals(path, request.path());
		}

		@Test
		@DisplayName("path() returns empty string when PathLength is zero")
		void emptyPath() {
			var body = new byte[8];
			MemorySegment.ofArray(body).set(Layouts.LE_UINT16, 0, (char) 9);
			var request = new TreeConnectRequest(null, MemorySegment.ofArray(body));
			Assertions.assertEquals("", request.path());
		}
	}

	@Nested
	@DisplayName("TreeConnectResponse")
	class ConnectResponse {

		@Test
		@DisplayName("Setters write ShareType / ShareFlags / Capabilities / MaximalAccess at correct offsets")
		void settersAtCorrectOffsets() {
			var header = PacketHeader.builder().build();
			var response = new TreeConnectResponse(header);
			response.shareType(TreeConnectResponse.SHARE_TYPE_DISK);
			response.shareFlags(0x00000000);
			response.capabilities(0x00000008);
			response.maximalAccess(0x001F01FF);

			var seg = response.segment();
			Assertions.assertEquals(TreeConnectResponse.STRUCTURE_SIZE, seg.get(Layouts.LE_UINT16, 0));
			Assertions.assertEquals(TreeConnectResponse.SHARE_TYPE_DISK, seg.get(Layouts.BYTE, 2));
			Assertions.assertEquals(0, seg.get(Layouts.LE_INT32, 4));
			Assertions.assertEquals(0x00000008, seg.get(Layouts.LE_INT32, 8));
			Assertions.assertEquals(0x001F01FF, seg.get(Layouts.LE_INT32, 12));
		}
	}

	@Nested
	@DisplayName("TreeDisconnectRequest")
	class DisconnectRequest {

		@Test
		@DisplayName("structureSize() reads the wire value")
		void structureSize() {
			var body = new byte[4];
			MemorySegment.ofArray(body).set(Layouts.LE_UINT16, 0, (char) 4);
			var request = new TreeDisconnectRequest(null, MemorySegment.ofArray(body));
			Assertions.assertEquals(4, request.structureSize());
		}
	}

	@Nested
	@DisplayName("TreeDisconnectResponse")
	class DisconnectResponse {

		@Test
		@DisplayName("Fresh response has StructureSize=4 with the 2 reserved bytes zeroed")
		void freshResponse() {
			var response = new TreeDisconnectResponse(PacketHeader.builder().build());
			Assertions.assertEquals(TreeDisconnectResponse.STRUCTURE_SIZE, response.segment().get(Layouts.LE_UINT16, 0));
			Assertions.assertEquals(0, response.segment().get(Layouts.LE_UINT16, 2));
		}
	}
}
