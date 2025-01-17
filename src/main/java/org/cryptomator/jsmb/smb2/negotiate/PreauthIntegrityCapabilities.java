package org.cryptomator.jsmb.smb2.negotiate;

import org.cryptomator.jsmb.util.Layouts;

import java.lang.foreign.MemorySegment;
import java.util.Arrays;
import java.util.HexFormat;

/**
 * The Pre-Auth Integrity Context required to negotiate a secure connection
 *
 * @param data Data field of the SMB2_NEGOTIATE_CONTEXT
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5a07bd66-4734-4af8-abcf-5a44ff7ee0e5">SMB2_PREAUTH_INTEGRITY_CAPABILITIES</a>
 * @see <a href="https://learn.microsoft.com/de-de/archive/blogs/openspecification/smb-3-1-1-pre-authentication-integrity-in-windows-10">SMB 3.1.1 Pre-authentication integrity in Windows 10</a>
 */
public record PreauthIntegrityCapabilities(MemorySegment data) implements NegotiateContext {

	public static final char HASH_ALGORITHM_SHA512 = 0x0001;

	public static PreauthIntegrityCapabilities build(char hash, byte[] salt) {
		var data = MemorySegment.ofArray(new byte[6 + salt.length]);
		data.set(Layouts.LE_UINT16, 0, (char) 1); // algorithm count
		data.set(Layouts.LE_UINT16, 2, (char) salt.length); // salt length
		data.set(Layouts.LE_UINT16, 4, hash);
		data.asSlice(6, salt.length).copyFrom(MemorySegment.ofArray(salt));
		return new PreauthIntegrityCapabilities(data);
	}

	@Override
	public char contextType() {
		return NegotiateContext.PREAUTH_INTEGRITY_CAPABILITIES;
	}

	public char hashAlgorithmCount() {
		return data.get(Layouts.LE_UINT16, 0);
	}

	public char saltLength() {
		return data.get(Layouts.LE_UINT16, 2);
	}

	public char[] hashAlgorithms() {
		return data.asSlice(4, hashAlgorithmCount() * Character.BYTES).toArray(Layouts.LE_UINT16);
	}

	public byte[] salt() {
		return data.asSlice(4 + hashAlgorithmCount() * Character.BYTES, saltLength()).toArray(Layouts.BYTE);
	}

	@Override
	public String toString() {
		return String.format("SMB2_NEGOTIATE_CONTEXT (hashAlgorithms: %s, salt: %s)", Arrays.toString(hashAlgorithms()), HexFormat.of().formatHex(salt()));
	}
}
