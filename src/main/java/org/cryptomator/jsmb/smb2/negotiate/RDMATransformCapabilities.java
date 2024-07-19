package org.cryptomator.jsmb.smb2.negotiate;

import org.cryptomator.jsmb.util.Layouts;

import java.lang.foreign.MemorySegment;

public record RDMATransformCapabilities(MemorySegment data) implements NegotiateContext {

	public static final char TRANSFORM_NONE = 0x0000;
	public static final char TRANSFORM_ENCRYPTION = 0x0001;
	public static final char TRANSFORM_SIGNING = 0x0002;

	public static RDMATransformCapabilities build(char[] transformIds) {
		var transformIdsSegment = MemorySegment.ofArray(transformIds);
		var data = MemorySegment.ofArray(new byte[8 + (int) transformIdsSegment.byteSize()]);
		data.set(Layouts.LE_UINT16, 0, (char) 1); // transform count
		data.asSlice(8, transformIdsSegment.byteSize()).copyFrom(transformIdsSegment);
		return new RDMATransformCapabilities(data);
	}

	@Override
	public char contextType() {
		return NegotiateContext.RDMA_TRANSFORM_CAPABILITIES;
	}

	public char transformCount() {
		return data.get(Layouts.LE_UINT16, 0);
	}

	public char[] rdmaTransformIds() {
		return data.asSlice(8, transformCount() * Character.BYTES).toArray(Layouts.LE_UINT16);
	}
}
