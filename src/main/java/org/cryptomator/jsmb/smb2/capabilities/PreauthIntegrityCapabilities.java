package org.cryptomator.jsmb.smb2.capabilities;

import java.lang.foreign.MemorySegment;

public record PreauthIntegrityCapabilities(MemorySegment data) implements NegotiateContext {

	@Override
	public short contextType() {
		return NegotiateContext.PREAUTH_INTEGRITY_CAPABILITIES;
	}

}
