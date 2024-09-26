package org.cryptomator.jsmb.ntlm;

import org.cryptomator.jsmb.util.Layouts;

import java.lang.foreign.MemorySegment;
import java.nio.charset.StandardCharsets;

/**
 * The NTLM authenticate message is sent by the client to the server in response to the challenge message.
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/033d32cc-88f9-4483-9bf2-b273055038ce">AUTHENTICATE_MESSAGE</a>
 */
record NtlmAuthenticateMessage(MemorySegment segment) implements NtlmMessage {

	public static final int MESSAGE_TYPE = 0x00000003;

	// LmChallengeResponseFields (8 bytes):

	public char lmChallengeResponseLen() {
		return segment.get(Layouts.LE_UINT16, 12);
	}

	public char lmChallengeResponseMaxLen() {
		return segment.get(Layouts.LE_UINT16, 14);
	}

	public int lmChallengeResponseBufferOffset() {
		return segment.get(Layouts.LE_INT32, 16);
	}

	public MemorySegment lmChallengeResponseSegment() {
		if (lmChallengeResponseLen() == 0) {
			return MemorySegment.NULL;
		} else {
			return segment.asSlice(lmChallengeResponseBufferOffset(), lmChallengeResponseLen());
		}
	}

	public byte[] lmChallengeResponse() {
		return lmChallengeResponseSegment().toArray(Layouts.BYTE);
	}

	/**
	 * The {@link #lmChallengeResponse()} parsed as {@link LmV2Response}.
	 * @return LM v2 response
	 */
	public LmV2Response lmV2Response() {
		return new LmV2Response(lmChallengeResponseSegment());
	}

	// NtChallengeResponseFields (8 bytes):

	public char ntChallengeResponseLen() {
		return segment.get(Layouts.LE_UINT16, 20);
	}

	public char ntChallengeResponseMaxLen() {
		return segment.get(Layouts.LE_UINT16, 22);
	}

	public int ntChallengeResponseBufferOffset() {
		return segment.get(Layouts.LE_INT32, 24);
	}

	public MemorySegment ntChallengeResponseSegment() {
		if (ntChallengeResponseLen() == 0) {
			return MemorySegment.NULL;
		} else {
			return segment.asSlice(ntChallengeResponseBufferOffset(), ntChallengeResponseLen());
		}
	}

	public byte[] ntChallengeResponse() {
		return ntChallengeResponseSegment().toArray(Layouts.BYTE);
	}

	/**
	 * The {@link #ntChallengeResponse()} parsed as {@link NtlmV2Response}.
	 * @return NTLM v2 response
	 */
	public NtlmV2Response ntlmV2Response() {
		return new NtlmV2Response(ntChallengeResponseSegment());
	}

	// DomainNameFields (8 bytes):

	public char domainNameLen() {
		return segment.get(Layouts.LE_UINT16, 28);
	}

	public char domainNameMaxLen() {
		return segment.get(Layouts.LE_UINT16, 30);
	}

	public int domainNameBufferOffset() {
		return segment.get(Layouts.LE_INT32, 32);
	}

	public String domainName() {
		if (domainNameLen() == 0) {
			return null;
		} else {
			var buf = segment.asSlice(domainNameBufferOffset(), domainNameLen()).asByteBuffer();
			return StandardCharsets.UTF_16LE.decode(buf).toString();
		}
	}

	// UserNameFields (8 bytes):

	public char userNameLen() {
		return segment.get(Layouts.LE_UINT16, 36);
	}

	public char userNameMaxLen() {
		return segment.get(Layouts.LE_UINT16, 38);
	}

	public int userNameBufferOffset() {
		return segment.get(Layouts.LE_INT32, 40);
	}

	public String userName() {
		if (userNameLen() == 0) {
			return null;
		} else {
			var buf = segment.asSlice(userNameBufferOffset(), userNameLen()).asByteBuffer();
			return StandardCharsets.UTF_16LE.decode(buf).toString();
		}
	}

	// WorkstationFields (8 bytes):

	public char workstationLen() {
		return segment.get(Layouts.LE_UINT16, 44);
	}

	public char workstationMaxLen() {
		return segment.get(Layouts.LE_UINT16, 46);
	}

	public int workstationBufferOffset() {
		return segment.get(Layouts.LE_INT32, 48);
	}

	public String workstation() {
		if (workstationLen() == 0) {
			return null;
		} else {
			var buf = segment.asSlice(workstationBufferOffset(), workstationLen()).asByteBuffer();
			return StandardCharsets.UTF_16LE.decode(buf).toString();
		}
	}

	// EncryptedRandomSessionKeyFields (8 bytes):

	public char encryptedRandomSessionKeyLen() {
		return segment.get(Layouts.LE_UINT16, 52);
	}

	public char encryptedRandomSessionKeyMaxLen() {
		return segment.get(Layouts.LE_UINT16, 54);
	}

	public int encryptedRandomSessionKeyBufferOffset() {
		return segment.get(Layouts.LE_INT32, 56);
	}

	public byte[] encryptedRandomSessionKey() {
		if ((negotiateFlags() & NegotiateFlags.NTLMSSP_NEGOTIATE_KEY_EXCH) == 0) {
			return null;
		} else {
			return segment.asSlice(encryptedRandomSessionKeyBufferOffset(), encryptedRandomSessionKeyLen()).toArray(Layouts.BYTE);
		}
	}

	// NegotiateFlags (4 bytes):

	public int negotiateFlags() {
		return segment.get(Layouts.LE_INT32, 60);
	}

	// Version (8 bytes):

	public byte productMajorVersion() {
		return segment.get(Layouts.BYTE, 64);
	}

	public byte productMinorVersion() {
		return segment.get(Layouts.BYTE, 65);
	}

	public char productBuild() {
		return segment.get(Layouts.LE_UINT16, 66);
	}

	public byte ntlmRevisionCurrent() {
		return segment.get(Layouts.BYTE, 71);
	}

	// MIC (16 bytes):

	public byte[] mic() {
		return segment.asSlice(72, 16).toArray(Layouts.BYTE);
	}

	public void setMic(byte[] mic) {
		segment.asSlice(72, 16).copyFrom(MemorySegment.ofArray(mic));
	}

}
