package org.cryptomator.jsmb.smb2.negotiate;

import java.lang.foreign.MemorySegment;

/**
 * This value MUST be reserved and MUST be ignored on receipt.
 */
public record ReservedCapabilities(MemorySegment data) implements NegotiateContext {

	@Override
	public char contextType() {
		return NegotiateContext.CONTEXTTYPE_RESERVED;
	}

}
