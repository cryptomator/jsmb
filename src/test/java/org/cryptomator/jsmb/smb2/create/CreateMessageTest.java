package org.cryptomator.jsmb.smb2.create;

import org.cryptomator.jsmb.share.FileId;
import org.cryptomator.jsmb.smb2.PacketHeader;
import org.cryptomator.jsmb.util.Layouts;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.lang.foreign.MemorySegment;
import java.nio.charset.StandardCharsets;

class CreateMessageTest {

	@Nested
	@DisplayName("CreateRequest")
	class CreateReq {

		@Test
		@DisplayName("Accessors return DesiredAccess / CreateDisposition / CreateOptions / FileAttributes / ShareAccess from the wire bytes")
		void fixedFieldAccessors() {
			var body = new byte[56];
			var seg = MemorySegment.ofArray(body);
			seg.set(Layouts.LE_UINT16, 0, (char) 57);
			seg.set(Layouts.BYTE, 3, (byte) 0x09); // RequestedOplockLevel = LEASE
			seg.set(Layouts.LE_INT32, 4, 2); // Impersonation = Impersonation
			seg.set(Layouts.LE_INT32, 24, 0x00120089); // DesiredAccess (file-generic-read-ish)
			seg.set(Layouts.LE_INT32, 28, 0x00000080); // FileAttributes = NORMAL
			seg.set(Layouts.LE_INT32, 32, 0x00000007); // ShareAccess = R|W|D
			seg.set(Layouts.LE_INT32, 36, 1); // Disposition = OPEN
			seg.set(Layouts.LE_INT32, 40, 0x00000020); // CreateOptions = FILE_SYNCHRONOUS_IO_NONALERT

			var request = new CreateRequest(null, seg);

			Assertions.assertEquals(57, request.structureSize());
			Assertions.assertEquals(0x09, request.requestedOplockLevel());
			Assertions.assertEquals(2, request.impersonationLevel());
			Assertions.assertEquals(0x00120089, request.desiredAccess());
			Assertions.assertEquals(0x00000080, request.fileAttributes());
			Assertions.assertEquals(0x00000007, request.shareAccess());
			Assertions.assertEquals(1, request.createDisposition());
			Assertions.assertEquals(0x00000020, request.createOptions());
		}

		@Test
		@DisplayName("name() decodes the UTF-16LE Name buffer")
		void nameDecoding() {
			var name = "sub\\file.txt";
			var nameBytes = name.getBytes(StandardCharsets.UTF_16LE);

			var body = new byte[56 + nameBytes.length];
			var seg = MemorySegment.ofArray(body);
			seg.set(Layouts.LE_UINT16, 0, (char) 57);
			seg.set(Layouts.LE_UINT16, 44, (char) (PacketHeader.STRUCTURE_SIZE + 56));
			seg.set(Layouts.LE_UINT16, 46, (char) nameBytes.length);
			seg.asSlice(56, nameBytes.length).copyFrom(MemorySegment.ofArray(nameBytes));

			Assertions.assertEquals(name, new CreateRequest(null, seg).name());
		}

		@Test
		@DisplayName("name() is the empty string when NameLength is zero (open share root)")
		void emptyName() {
			var body = new byte[56];
			MemorySegment.ofArray(body).set(Layouts.LE_UINT16, 0, (char) 57);
			Assertions.assertEquals("", new CreateRequest(null, MemorySegment.ofArray(body)).name());
		}
	}

	@Nested
	@DisplayName("CloseRequest")
	class CloseReq {

		@Test
		@DisplayName("fileId() reads the 16-byte FileId at offset 8")
		void fileIdAccessor() {
			var body = new byte[24];
			var seg = MemorySegment.ofArray(body);
			seg.set(Layouts.LE_UINT16, 0, (char) 24);
			seg.set(Layouts.LE_INT64, 8, 0x1122334455667788L);
			seg.set(Layouts.LE_INT64, 16, 0xAABBCCDDEEFF0011L);

			var request = new CloseRequest(null, seg);

			Assertions.assertEquals(24, request.structureSize());
			Assertions.assertEquals(0x1122334455667788L, request.fileId().persistentHandle());
			Assertions.assertEquals(0xAABBCCDDEEFF0011L, request.fileId().volatileHandle());
		}

		@Test
		@DisplayName("fileId(FileId) writes the FileId back at offset 8 for sentinel substitution in compound chains")
		void fileIdSetter() {
			var body = new byte[24];
			var seg = MemorySegment.ofArray(body);
			seg.set(Layouts.LE_UINT16, 0, (char) 24);
			var request = new CloseRequest(null, seg);

			request.fileId(new FileId(0xCAFEL, 0xBABEL));

			Assertions.assertEquals(0xCAFEL, seg.get(Layouts.LE_INT64, 8));
			Assertions.assertEquals(0xBABEL, seg.get(Layouts.LE_INT64, 16));
		}

		@Test
		@DisplayName("postQueryAttrib() reflects the SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB bit")
		void postQueryAttribBit() {
			var body = new byte[24];
			var seg = MemorySegment.ofArray(body);
			seg.set(Layouts.LE_UINT16, 0, (char) 24);
			seg.set(Layouts.LE_UINT16, 2, CloseRequest.FLAG_POSTQUERY_ATTRIB);
			Assertions.assertTrue(new CloseRequest(null, seg).postQueryAttrib());

			seg.set(Layouts.LE_UINT16, 2, (char) 0);
			Assertions.assertFalse(new CloseRequest(null, seg).postQueryAttrib());
		}
	}

	@Nested
	@DisplayName("CreateResponse")
	class CreateResp {

		@Test
		@DisplayName("Setters write CreateAction / timestamps / sizes / attributes / FileId at correct offsets")
		void settersAtCorrectOffsets() {
			var response = new CreateResponse(PacketHeader.builder().build());
			response.oplockLevel((byte) 0);
			response.flags((byte) 0);
			response.createAction(CreateResponse.CREATE_ACTION_CREATED);
			response.creationTime(0x1111_1111_1111_1111L);
			response.lastAccessTime(0x2222_2222_2222_2222L);
			response.lastWriteTime(0x3333_3333_3333_3333L);
			response.changeTime(0x4444_4444_4444_4444L);
			response.allocationSize(0x1000);
			response.endOfFile(0x0FFF);
			response.fileAttributes(0x00000080);
			response.fileId(new FileId(0xDEADL, 0xBEEFL));

			var seg = response.segment();
			Assertions.assertEquals(CreateResponse.STRUCTURE_SIZE, seg.get(Layouts.LE_UINT16, 0));
			Assertions.assertEquals(CreateResponse.CREATE_ACTION_CREATED, seg.get(Layouts.LE_INT32, 4));
			Assertions.assertEquals(0x1111_1111_1111_1111L, seg.get(Layouts.LE_INT64, 8));
			Assertions.assertEquals(0x4444_4444_4444_4444L, seg.get(Layouts.LE_INT64, 32));
			Assertions.assertEquals(0x0FFF, seg.get(Layouts.LE_INT64, 48));
			Assertions.assertEquals(0x00000080, seg.get(Layouts.LE_INT32, 56));
			Assertions.assertEquals(0xDEADL, seg.get(Layouts.LE_INT64, 64));
			Assertions.assertEquals(0xBEEFL, seg.get(Layouts.LE_INT64, 72));
		}

		@Test
		@DisplayName("fileId() reads back the FileId written by fileId(FileId), so the compound loop can propagate it to related operations")
		void fileIdRoundTrip() {
			var response = new CreateResponse(PacketHeader.builder().build());
			response.fileId(new FileId(0xA1A1_A1A1L, 0xB2B2_B2B2L));

			Assertions.assertEquals(new FileId(0xA1A1_A1A1L, 0xB2B2_B2B2L), response.fileId());
		}
	}

	@Nested
	@DisplayName("CloseResponse")
	class CloseResp {

		@Test
		@DisplayName("Setters write PostQueryAttrib timestamps / sizes / attributes at correct offsets")
		void settersAtCorrectOffsets() {
			var response = new CloseResponse(PacketHeader.builder().build());
			response.flags(CloseRequest.FLAG_POSTQUERY_ATTRIB);
			response.creationTime(0x1000);
			response.lastWriteTime(0x3000);
			response.endOfFile(1234L);
			response.fileAttributes(0x00000020);

			var seg = response.segment();
			Assertions.assertEquals(CloseResponse.STRUCTURE_SIZE, seg.get(Layouts.LE_UINT16, 0));
			Assertions.assertEquals(CloseRequest.FLAG_POSTQUERY_ATTRIB, seg.get(Layouts.LE_UINT16, 2));
			Assertions.assertEquals(0x1000, seg.get(Layouts.LE_INT64, 8));
			Assertions.assertEquals(0x3000, seg.get(Layouts.LE_INT64, 24));
			Assertions.assertEquals(1234L, seg.get(Layouts.LE_INT64, 48));
			Assertions.assertEquals(0x00000020, seg.get(Layouts.LE_INT32, 56));
		}
	}
}
