package org.cryptomator.jsmb.smb2.create;

import org.cryptomator.jsmb.smb2.PacketHeader;
import org.cryptomator.jsmb.util.Layouts;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.lang.foreign.MemorySegment;

class CreateContextTest {

	@Nested
	@DisplayName("mxAcResponse")
	class MxAcResponse {

		@Test
		@DisplayName("Builds a 32-byte SMB2_CREATE_QUERY_MAXIMAL_ACCESS_RESPONSE with the MxAc tag at the right offsets")
		void encodeLayout() {
			CreateContext ctx = CreateContext.mxAcResponse(0, 0x001F01FF);

			Assertions.assertEquals(32, ctx.segment().byteSize());
			Assertions.assertEquals(0, ctx.next());
			Assertions.assertEquals(16, ctx.nameOffset());
			Assertions.assertEquals(4, ctx.nameLength());
			Assertions.assertEquals(24, ctx.dataOffset());
			Assertions.assertEquals(8, ctx.dataLength());
			Assertions.assertTrue(ctx.nameEquals(CreateContext.NAME_MXAC));
			var data = ctx.data();
			Assertions.assertEquals(0, data.get(Layouts.LE_INT32, 0));          // QueryStatus
			Assertions.assertEquals(0x001F01FF, data.get(Layouts.LE_INT32, 4)); // MaximalAccess
		}
	}

	@Nested
	@DisplayName("CreateRequest.createContexts / hasCreateContext")
	class Iteration {

		@Test
		@DisplayName("empty list when the request has no CreateContexts")
		void noContexts() {
			var body = new byte[56];
			var seg = MemorySegment.ofArray(body);
			seg.set(Layouts.LE_UINT16, 0, (char) 57);

			var request = new CreateRequest(null, seg);
			Assertions.assertTrue(request.createContexts().isEmpty());
			Assertions.assertFalse(request.hasCreateContext(CreateContext.NAME_MXAC));
		}

		@Test
		@DisplayName("yields one CreateContext and hasCreateContext(MxAc) is true when a lone MxAc context is present")
		void singleMxAc() {
			byte[] contextBytes = CreateContext.mxAcResponse(0, 0x001F01FF).segment().toArray(Layouts.BYTE);
			var body = new byte[56 + contextBytes.length];
			var seg = MemorySegment.ofArray(body);
			seg.set(Layouts.LE_UINT16, 0, (char) 57);
			seg.set(Layouts.LE_INT32, 48, PacketHeader.STRUCTURE_SIZE + 56);
			seg.set(Layouts.LE_INT32, 52, contextBytes.length);
			seg.asSlice(56, contextBytes.length).copyFrom(MemorySegment.ofArray(contextBytes));

			var request = new CreateRequest(null, seg);
			var contexts = request.createContexts();
			Assertions.assertEquals(1, contexts.size());
			Assertions.assertTrue(contexts.getFirst().nameEquals(CreateContext.NAME_MXAC));
			Assertions.assertTrue(request.hasCreateContext(CreateContext.NAME_MXAC));
		}

		@Test
		@DisplayName("hasCreateContext(MxAc) is false when the only context tag is something else")
		void otherTag() {
			byte[] contextBytes = new byte[24]; // 16 header + 4 name + 4 pad
			var ctxSeg = MemorySegment.ofArray(contextBytes);
			ctxSeg.set(Layouts.LE_UINT16, 4, (char) 16);
			ctxSeg.set(Layouts.LE_UINT16, 6, (char) 4);
			ctxSeg.asSlice(16, 4).copyFrom(MemorySegment.ofArray(new byte[]{'D', 'H', 'n', 'Q'}));

			var body = new byte[56 + contextBytes.length];
			var seg = MemorySegment.ofArray(body);
			seg.set(Layouts.LE_UINT16, 0, (char) 57);
			seg.set(Layouts.LE_INT32, 48, PacketHeader.STRUCTURE_SIZE + 56);
			seg.set(Layouts.LE_INT32, 52, contextBytes.length);
			seg.asSlice(56, contextBytes.length).copyFrom(MemorySegment.ofArray(contextBytes));

			Assertions.assertFalse(new CreateRequest(null, seg).hasCreateContext(CreateContext.NAME_MXAC));
		}
	}

	@Nested
	@DisplayName("CreateResponse.withCreateContext")
	class WithCreateContext {

		@Test
		@DisplayName("Returns a new response with the context appended past the fixed portion and CreateContexts{Offset,Length} set")
		void appendsAndStampsOffsets() {
			var base = new CreateResponse(PacketHeader.builder().build());
			base.fileAttributes(0x00000080);
			CreateContext mxAc = CreateContext.mxAcResponse(0, 0x001F01FF);
			int ctxSize = (int) mxAc.segment().byteSize();

			CreateResponse withCtx = base.withCreateContext(mxAc);

			var seg = withCtx.segment();
			Assertions.assertEquals(CreateResponse.FIXED_PORTION_SIZE + ctxSize, seg.byteSize());
			Assertions.assertEquals(0x00000080, seg.get(Layouts.LE_INT32, 56));                           // preserved
			Assertions.assertEquals(PacketHeader.STRUCTURE_SIZE + CreateResponse.FIXED_PORTION_SIZE,
					seg.get(Layouts.LE_INT32, 80));                                                        // CreateContextsOffset
			Assertions.assertEquals(ctxSize, seg.get(Layouts.LE_INT32, 84));                              // CreateContextsLength
			byte[] expected = mxAc.segment().toArray(Layouts.BYTE);
			for (int i = 0; i < expected.length; i++) {
				Assertions.assertEquals(expected[i], seg.get(Layouts.BYTE, CreateResponse.FIXED_PORTION_SIZE + i));
			}
		}
	}
}
