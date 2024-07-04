package org.cryptomator.jsmb.smb2.capabilities;

import java.lang.foreign.MemorySegment;

public record NetnameNegotiateContextId(MemorySegment data) implements NegotiateContext {

	@Override
	public short contextType() {
		return NETNAME_NEGOTIATE_CONTEXT_ID;
	}
}
