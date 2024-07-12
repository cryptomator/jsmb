package org.cryptomator.jsmb.smb2.negotiate;

import org.cryptomator.jsmb.util.Layouts;

import java.lang.foreign.MemorySegment;

/**
 * The context specifying the supported encryption algorithms.
 *
 * @param data Data field of the SMB2_NEGOTIATE_CONTEXT
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/16693be7-2b27-4d3b-804b-f605bde5bcdd">SMB2_ENCRYPTION_CAPABILITIES</a>
 */
public record EncryptionCapabilities(MemorySegment data) implements NegotiateContext {

	public static final short AES_128_CCM = 0x0001;
	public static final short AES_128_GCM = 0x0002;
	public static final short AES_256_CCM = 0x0003;
	public static final short AES_256_GCM = 0x0004;

	public static EncryptionCapabilities build(short cipherId) {
		var data = MemorySegment.ofArray(new byte[4]);
		data.set(Layouts.LE_INT16, 0, (short) 1); // cipher count
		data.set(Layouts.LE_INT16, 2, cipherId); // first element in cipher list
		return new EncryptionCapabilities(data);
	}

	@Override
	public short contextType() {
		return NegotiateContext.ENCRYPTION_CAPABILITIES;
	}

	public short cipherCount() {
		return data.get(Layouts.LE_INT16, 0);
	}

	public short[] ciphers() {
		return data.asSlice(2, cipherCount() * Short.BYTES).toArray(Layouts.LE_INT16);
	}

}
