package org.cryptomator.jsmb.smb2.ioctl;

import org.cryptomator.jsmb.smb2.PacketHeader;
import org.cryptomator.jsmb.util.Layouts;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.foreign.MemorySegment;

class IoctlMessageTest {

	@Test
	@DisplayName("IoctlRequest accessors return the values encoded in the backing segment")
	public void testRequestAccessors() {
		byte[] fileId = new byte[16];
		for (int i = 0; i < 16; i++) {
			fileId[i] = (byte) (0x10 + i);
		}
		byte[] input = new byte[]{1, 2, 3, 4};

		// assemble a 56-byte fixed portion + 4-byte input buffer
		byte[] bytes = new byte[56 + input.length];
		var seg = MemorySegment.ofArray(bytes);
		seg.set(Layouts.LE_UINT16, 0, (char) 57); // StructureSize
		seg.set(Layouts.LE_INT32, 4, 0x00140204); // CtlCode (FSCTL_VALIDATE_NEGOTIATE_INFO)
		seg.asSlice(8, 16).copyFrom(MemorySegment.ofArray(fileId));
		seg.set(Layouts.LE_INT32, 24, PacketHeader.STRUCTURE_SIZE + 56); // InputOffset
		seg.set(Layouts.LE_INT32, 28, input.length); // InputCount
		seg.set(Layouts.LE_INT32, 32, 0); // MaxInputResponse
		seg.set(Layouts.LE_INT32, 36, 0); // OutputOffset
		seg.set(Layouts.LE_INT32, 40, 0); // OutputCount
		seg.set(Layouts.LE_INT32, 44, 256); // MaxOutputResponse
		seg.set(Layouts.LE_INT32, 48, IoctlRequest.FLAG_IS_FSCTL); // Flags
		seg.asSlice(56, input.length).copyFrom(MemorySegment.ofArray(input));

		var request = new IoctlRequest(null, seg);

		Assertions.assertEquals(57, request.structureSize());
		Assertions.assertEquals(0x00140204, request.ctlCode());
		Assertions.assertArrayEquals(fileId, request.fileId());
		Assertions.assertEquals(PacketHeader.STRUCTURE_SIZE + 56, request.inputOffset());
		Assertions.assertEquals(input.length, request.inputCount());
		Assertions.assertEquals(256, request.maxOutputResponse());
		Assertions.assertTrue(request.isFsctl());
		Assertions.assertArrayEquals(input, request.inputBuffer());
	}

	@Test
	@DisplayName("IoctlRequest with InputCount=0 returns an empty input buffer")
	public void testRequestEmptyInputBuffer() {
		byte[] bytes = new byte[56];
		var seg = MemorySegment.ofArray(bytes);
		seg.set(Layouts.LE_UINT16, 0, (char) 57);
		seg.set(Layouts.LE_INT32, 28, 0); // InputCount = 0

		var request = new IoctlRequest(null, seg);

		Assertions.assertArrayEquals(new byte[0], request.inputBuffer());
		Assertions.assertFalse(request.isFsctl());
	}

	@Test
	@DisplayName("IoctlResponse setters write StructureSize, CtlCode and FileId at the correct offsets")
	public void testResponseBuild() {
		var header = PacketHeader.builder().build();
		var response = new IoctlResponse(header);

		response.ctlCode(0x00140204);
		byte[] fid = new byte[16];
		for (int i = 0; i < 16; i++) fid[i] = (byte) i;
		response.fileId(fid);

		Assertions.assertEquals(IoctlResponse.STRUCTURE_SIZE, response.segment().get(Layouts.LE_UINT16, 0));
		Assertions.assertEquals(0x00140204, response.segment().get(Layouts.LE_INT32, 4));
		Assertions.assertArrayEquals(fid, response.segment().asSlice(8, 16).toArray(Layouts.BYTE));
	}

	@Test
	@DisplayName("IoctlResponse.withOutputBuffer appends the buffer and updates OutputOffset/OutputCount")
	public void testResponseWithOutputBuffer() {
		var header = PacketHeader.builder().build();
		var response = new IoctlResponse(header);
		byte[] output = new byte[]{9, 8, 7, 6, 5};

		var updated = response.withOutputBuffer(output);

		Assertions.assertEquals(PacketHeader.STRUCTURE_SIZE + IoctlResponse.FIXED_PORTION_SIZE,
				updated.segment().get(Layouts.LE_INT32, 32)); // OutputOffset
		Assertions.assertEquals(output.length, updated.segment().get(Layouts.LE_INT32, 36)); // OutputCount
		Assertions.assertArrayEquals(output,
				updated.segment().asSlice(IoctlResponse.FIXED_PORTION_SIZE, output.length).toArray(Layouts.BYTE));
	}

	@Test
	@DisplayName("IoctlResponse.fileId rejects a byte array that is not exactly 16 bytes")
	public void testResponseFileIdLengthValidation() {
		var response = new IoctlResponse(PacketHeader.builder().build());
		Assertions.assertThrows(IllegalArgumentException.class, () -> response.fileId(new byte[15]));
	}
}
