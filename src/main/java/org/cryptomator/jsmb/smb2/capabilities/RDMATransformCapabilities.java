package org.cryptomator.jsmb.smb2.capabilities;

import java.lang.foreign.MemorySegment;

public record RDMATransformCapabilities(MemorySegment data) implements NegotiateContext {

	@Override
	public short contextType() {
		return RDMA_TRANSFORM_CAPABILITIES;
	}
}
