package org.cryptomator.jsmb.smb2.negotiate;

import org.cryptomator.jsmb.util.Layouts;

import java.lang.foreign.MemorySegment;

/**
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/cb9b5d66-b6be-4d18-aa66-8784a871cc10">SMB2_SIGNING_CAPABILITIES</a>
 */
public record SigningCapabilities(MemorySegment data) implements NegotiateContext {

	public enum SigningAlgorithm {
		HMAC_SHA256(0x0000),
		AES_CMAC(0x0001),
		AES_GMAC(0x0002);

		private final char value;

		SigningAlgorithm(int value) {
			this.value = (char) value;
		}

		public char getValue() {
			return value;
		}
	}

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
