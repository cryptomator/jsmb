package org.cryptomator.jsmb.smb2.negotiate;

import org.cryptomator.jsmb.util.Layouts;

import java.lang.foreign.MemorySegment;

public record SigningCapabilities(MemorySegment data) implements NegotiateContext {

	public static final char HMAC_SHA256 = 0x0000;
	public static final char AES_CMAC = 0x0001;
	public static final char AES_GMAC = 0x0002;

	public static SigningCapabilities build(char algId) {
		var data = MemorySegment.ofArray(new byte[4]);
		data.set(Layouts.LE_UINT16, 0, (char) 1); // signing algorithm count
		data.set(Layouts.LE_UINT16, 2, algId); // first element in algorithm list
		return new SigningCapabilities(data);
	}

	@Override
	public char contextType() {
		return NegotiateContext.SIGNING_CAPABILITIES;
	}

	public char signingAlgorithmCount() {
		return data.get(Layouts.LE_UINT16, 0);
	}

	public char[] signingAlgorithms() {
		return data.asSlice(2, signingAlgorithmCount() * Character.BYTES).toArray(Layouts.LE_UINT16);
	}
}
