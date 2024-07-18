package org.cryptomator.jsmb.smb2.negotiate;

import org.cryptomator.jsmb.util.Layouts;

import java.lang.foreign.MemorySegment;

public record RDMATransformCapabilities(MemorySegment data) implements NegotiateContext {

	public static final short TRANSFORM_NONE = 0x0000;
	public static final short TRANSFORM_ENCRYPTION = 0x0001;
	public static final short TRANSFORM_SIGNING = 0x0002;

	public static RDMATransformCapabilities build(short[] transformIds) {
		var transformIdsSegment = MemorySegment.ofArray(transformIds);
		var data = MemorySegment.ofArray(new byte[8 + (int) transformIdsSegment.byteSize()]);
		data.set(Layouts.LE_INT16, 0, (short) 1); // transform count
		data.asSlice(8, transformIdsSegment.byteSize()).copyFrom(transformIdsSegment);
		return new RDMATransformCapabilities(data);
	}

	@Override
	public short contextType() {
		return NegotiateContext.RDMA_TRANSFORM_CAPABILITIES;
	}

	public short transformCount() {
		return data.get(Layouts.LE_INT16, 0);
	}

	public short[] rdmaTransformIds() {
		return data.asSlice(8, transformCount() * Short.BYTES).toArray(Layouts.LE_INT16);
	}
}
