package org.cryptomator.jsmb.smb2.negotiate;

import org.cryptomator.jsmb.util.Layouts;

import java.lang.foreign.MemorySegment;
import java.nio.CharBuffer;
import java.util.Arrays;
import java.util.Spliterator;
import java.util.stream.IntStream;

/**
 * The context specifying the supported encryption algorithms.
 *
 * @param data Data field of the SMB2_NEGOTIATE_CONTEXT
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/16693be7-2b27-4d3b-804b-f605bde5bcdd">SMB2_ENCRYPTION_CAPABILITIES</a>
 */
public record EncryptionCapabilities(MemorySegment data) implements NegotiateContext {

	public static final char NO_COMMON_CIPHER = 0x0000;
	public static final char AES_128_CCM = 0x0001;
	public static final char AES_128_GCM = 0x0002;
	public static final char AES_256_CCM = 0x0003;
	public static final char AES_256_GCM = 0x0004;

	public static EncryptionCapabilities build(char cipherId) {
		var data = MemorySegment.ofArray(new byte[4]);
		data.set(Layouts.LE_UINT16, 0, (char) 1); // cipher count
		data.set(Layouts.LE_UINT16, 2, cipherId); // first element in cipher list
		return new EncryptionCapabilities(data);
	}

	@Override
	public char contextType() {
		return NegotiateContext.ENCRYPTION_CAPABILITIES;
	}

	public char cipherCount() {
		return data.get(Layouts.LE_UINT16, 0);
	}

	public char[] ciphers() {
		return data.asSlice(2, cipherCount() * Character.BYTES).toArray(Layouts.LE_UINT16);
	}

}
