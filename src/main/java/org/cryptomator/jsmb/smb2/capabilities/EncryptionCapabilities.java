package org.cryptomator.jsmb.smb2.capabilities;

import java.lang.foreign.MemorySegment;

public record EncryptionCapabilities(MemorySegment data) implements NegotiateContext {

	@Override
	public short contextType() {
		return NegotiateContext.ENCRYPTION_CAPABILITIES;
	}

}
