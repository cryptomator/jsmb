package org.cryptomator.jsmb.smb2.capabilities;

import java.lang.foreign.MemorySegment;

public record TransportCapabilities(MemorySegment data) implements NegotiateContext {

	@Override
	public short contextType() {
		return TRANSPORT_CAPABILITIES;
	}
}
