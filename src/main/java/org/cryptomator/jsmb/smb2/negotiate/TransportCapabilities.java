package org.cryptomator.jsmb.smb2.negotiate;

import org.cryptomator.jsmb.util.Layouts;

import java.lang.foreign.MemorySegment;

public record TransportCapabilities(MemorySegment data) implements NegotiateContext {

	public static final int ACCEPT_TRANSPORT_LEVEL_SECURITY = 0x00000001;

	public static TransportCapabilities build(int flags) {
		var data = MemorySegment.ofArray(new byte[4]);
		data.set(Layouts.LE_INT32, 0, flags);
		return new TransportCapabilities(data);
	}

	@Override
	public char contextType() {
		return NegotiateContext.TRANSPORT_CAPABILITIES;
	}

	public int flags() {
		return data.get(Layouts.LE_INT32, 0);
	}

}
