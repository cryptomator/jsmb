package org.cryptomator.jsmb.smb2.create;

import org.cryptomator.jsmb.smb2.PacketHeader;
import org.cryptomator.jsmb.util.Layouts;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.lang.foreign.MemorySegment;
import java.util.List;

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
	@DisplayName("CreateResponse.withCreateContexts")
	class WithCreateContexts {

		@Test
		@DisplayName("An empty list returns the receiver unchanged (no contexts appended, offset/length stay zero)")
		void emptyList() {
			var base = new CreateResponse(PacketHeader.builder().build());

			CreateResponse result = base.withCreateContexts(List.of());

			Assertions.assertSame(base, result);
			Assertions.assertEquals(0, result.segment().get(Layouts.LE_INT32, 80));
			Assertions.assertEquals(0, result.segment().get(Layouts.LE_INT32, 84));
		}

		@Test
		@DisplayName("A single context is appended past the fixed portion with CreateContexts{Offset,Length} stamped and Next=0")
		void singleContext() {
			var base = new CreateResponse(PacketHeader.builder().build());
			base.fileAttributes(0x00000080);
			CreateContext mxAc = CreateContext.mxAcResponse(0, 0x001F01FF);
			int ctxSize = (int) mxAc.segment().byteSize();

			CreateResponse withCtx = base.withCreateContexts(List.of(mxAc));

			var seg = withCtx.segment();
			Assertions.assertEquals(CreateResponse.FIXED_PORTION_SIZE + ctxSize, seg.byteSize());
			Assertions.assertEquals(0x00000080, seg.get(Layouts.LE_INT32, 56));                           // fixed portion preserved
			Assertions.assertEquals(PacketHeader.STRUCTURE_SIZE + CreateResponse.FIXED_PORTION_SIZE,
					seg.get(Layouts.LE_INT32, 80));                                                        // CreateContextsOffset
			Assertions.assertEquals(ctxSize, seg.get(Layouts.LE_INT32, 84));                              // CreateContextsLength
			Assertions.assertEquals(0, seg.get(Layouts.LE_INT32, CreateResponse.FIXED_PORTION_SIZE));     // Next=0 on the only context
			byte[] expected = mxAc.segment().toArray(Layouts.BYTE);
			for (int i = 4; i < expected.length; i++) { // skip Next (0..3), the rest must match byte-for-byte
				Assertions.assertEquals(expected[i], seg.get(Layouts.BYTE, CreateResponse.FIXED_PORTION_SIZE + i));
			}
		}

		@Test
		@DisplayName("Two 8-byte-aligned contexts chain back-to-back: Next on the first = 32, Next on the second = 0, no inter-context padding")
		void twoAlignedContexts() {
			var base = new CreateResponse(PacketHeader.builder().build());
			CreateContext a = CreateContext.mxAcResponse(0, 0x001F01FF);
			CreateContext b = CreateContext.mxAcResponse(0, 0x00000001);

			CreateResponse withCtx = base.withCreateContexts(List.of(a, b));

			var seg = withCtx.segment();
			int off1 = CreateResponse.FIXED_PORTION_SIZE;
			int off2 = off1 + 32;
			Assertions.assertEquals(CreateResponse.FIXED_PORTION_SIZE + 64, seg.byteSize());
			Assertions.assertEquals(64, seg.get(Layouts.LE_INT32, 84));                                   // CreateContextsLength
			Assertions.assertEquals(32, seg.get(Layouts.LE_INT32, off1));                                 // Next stride = 32
			Assertions.assertEquals(0, seg.get(Layouts.LE_INT32, off2));                                  // Next = 0 on last
			Assertions.assertEquals(0x001F01FF, seg.get(Layouts.LE_INT32, off1 + 28));                    // MaximalAccess of first
			Assertions.assertEquals(0x00000001, seg.get(Layouts.LE_INT32, off2 + 28));                    // MaximalAccess of second
		}

		@Test
		@DisplayName("A 20-byte context followed by a 32-byte context pads to the next 8-byte boundary: Next=24, 4 zero-padding bytes, then the second context")
		void padsInterContextTo8ByteBoundary() {
			CreateContext small = syntheticContext(20, new byte[]{'D', 'H', 'n', 'Q'});
			CreateContext mxAc = CreateContext.mxAcResponse(0, 0x001F01FF);
			var base = new CreateResponse(PacketHeader.builder().build());

			CreateResponse withCtx = base.withCreateContexts(List.of(small, mxAc));

			var seg = withCtx.segment();
			int off1 = CreateResponse.FIXED_PORTION_SIZE;
			int off2 = off1 + 24;                                                                         // 20 + 4 pad
			Assertions.assertEquals(CreateResponse.FIXED_PORTION_SIZE + 24 + 32, seg.byteSize());
			Assertions.assertEquals(56, seg.get(Layouts.LE_INT32, 84));                                   // CreateContextsLength = 24 + 32
			Assertions.assertEquals(24, seg.get(Layouts.LE_INT32, off1));                                 // Next stride = size + pad
			Assertions.assertEquals(0, seg.get(Layouts.LE_INT32, off2));
			for (int i = off1 + 20; i < off1 + 24; i++) {                                                 // pad bytes are zero
				Assertions.assertEquals(0, seg.get(Layouts.BYTE, i));
			}
			Assertions.assertEquals(0x001F01FF, seg.get(Layouts.LE_INT32, off2 + 28));                    // MxAc MaximalAccess intact
		}

		@Test
		@DisplayName("Round-trip: CreateRequest.createContexts() re-parses the chain we just emitted")
		void roundTripsThroughRequestParser() {
			CreateContext small = syntheticContext(20, new byte[]{'D', 'H', 'n', 'Q'});
			CreateContext mxAc = CreateContext.mxAcResponse(0, 0x001F01FF);
			var base = new CreateResponse(PacketHeader.builder().build());

			CreateResponse withCtx = base.withCreateContexts(List.of(small, mxAc));

			// Reuse the same bytes in a CreateRequest so its parser walks the emitted chain.
			int ctxLength = withCtx.segment().get(Layouts.LE_INT32, 84);
			var requestBody = MemorySegment.ofArray(new byte[56 + ctxLength]);
			requestBody.set(Layouts.LE_UINT16, 0, (char) 57);
			requestBody.set(Layouts.LE_INT32, 48, PacketHeader.STRUCTURE_SIZE + 56);
			requestBody.set(Layouts.LE_INT32, 52, ctxLength);
			requestBody.asSlice(56, ctxLength).copyFrom(withCtx.segment().asSlice(CreateResponse.FIXED_PORTION_SIZE, ctxLength));

			var parsed = new CreateRequest(null, requestBody).createContexts();
			Assertions.assertEquals(2, parsed.size());
			Assertions.assertTrue(parsed.get(0).nameEquals(new byte[]{'D', 'H', 'n', 'Q'}));
			Assertions.assertTrue(parsed.get(1).nameEquals(CreateContext.NAME_MXAC));
		}

		@Test
		@DisplayName("A second withCreateContexts call throws IllegalStateException — guards against silently dropping the previously-emitted chain")
		void secondCallThrows() {
			var base = new CreateResponse(PacketHeader.builder().build());
			var first = base.withCreateContexts(List.of(CreateContext.mxAcResponse(0, 0x001F01FF)));
			var second = List.of(CreateContext.mxAcResponse(0, 0x001F01FF));

			Assertions.assertThrows(IllegalStateException.class, () -> first.withCreateContexts(second));
		}

		private static CreateContext syntheticContext(int size, byte[] name) {
			var seg = MemorySegment.ofArray(new byte[size]);
			seg.set(Layouts.LE_UINT16, 4, (char) 16);                 // NameOffset
			seg.set(Layouts.LE_UINT16, 6, (char) name.length);        // NameLength
			seg.asSlice(16, name.length).copyFrom(MemorySegment.ofArray(name));
			return new CreateContext(seg);
		}
	}
}
