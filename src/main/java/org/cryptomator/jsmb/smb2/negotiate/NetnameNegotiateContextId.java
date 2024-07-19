package org.cryptomator.jsmb.smb2.negotiate;

import java.lang.foreign.MemorySegment;

public record NetnameNegotiateContextId(MemorySegment data) implements NegotiateContext {

	@Override
	public char contextType() {
		return NegotiateContext.NETNAME_NEGOTIATE_CONTEXT_ID;
	}
}
