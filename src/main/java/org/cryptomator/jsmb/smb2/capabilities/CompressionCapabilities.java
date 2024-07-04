package org.cryptomator.jsmb.smb2.capabilities;

import java.lang.foreign.MemorySegment;

public record CompressionCapabilities(MemorySegment data) implements NegotiateContext {

	@Override
	public short contextType() {
		return COMPRESSION_CAPABILITIES;
	}
}
