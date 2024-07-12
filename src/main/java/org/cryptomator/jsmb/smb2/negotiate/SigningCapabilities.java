package org.cryptomator.jsmb.smb2.negotiate;

import org.cryptomator.jsmb.util.Layouts;

import java.lang.foreign.MemorySegment;

public record SigningCapabilities(MemorySegment data) implements NegotiateContext {

	public static final short HMAC_SHA256 = 0x0000;
	public static final short AES_CMAC = 0x0001;
	public static final short AES_GMAC = 0x0002;

	public static SigningCapabilities build(short algId) {
		var data = MemorySegment.ofArray(new byte[4]);
		data.set(Layouts.LE_INT16, 0, (short) 1); // signing algorithm count
		data.set(Layouts.LE_INT16, 2, algId); // first element in algorithm list
		return new SigningCapabilities(data);
	}

	@Override
	public short contextType() {
		return SIGNING_CAPABILITIES;
	}

	public short signingAlgorithmCount() {
		return data.get(Layouts.LE_INT16, 0);
	}

	public short[] signingAlgorithms() {
		return data.asSlice(2, signingAlgorithmCount() * Short.BYTES).toArray(Layouts.LE_INT16);
	}
}
