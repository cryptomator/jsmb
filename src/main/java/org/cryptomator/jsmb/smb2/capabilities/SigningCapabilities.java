package org.cryptomator.jsmb.smb2.capabilities;

import java.lang.foreign.MemorySegment;

public record SigningCapabilities(MemorySegment data) implements NegotiateContext {

	@Override
	public short contextType() {
		return SIGNING_CAPABILITIES;
	}
}
