package org.cryptomator.jsmb.ntlmv2;

import org.cryptomator.jsmb.util.Layouts;

import java.lang.foreign.MemorySegment;

/**
 * The NEGOTIATE_MESSAGE defines the message sent by the client to the server to initiate NTLM authentication.
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b34032e5-3aae-4bc6-84c3-c6d80eadf7f2">NEGOTIATE_MESSAGE</a>
 */
record NtlmNegotiateMessage(MemorySegment segment) implements NtlmMessage {

	public static final int MESSAGE_TYPE = 0x00000001;

	public static NtlmNegotiateMessage createBasicMessage() {
		MemorySegment segment = MemorySegment.ofArray(new byte[40]);
		segment.copyFrom(MemorySegment.ofArray(NtlmMessage.SIGNATURE)); // Signature
		segment.set(Layouts.LE_INT32, 8, MESSAGE_TYPE); // MessageType

		// Flags
		int flags = NegotiateFlags.NTLMSSP_NEGOTIATE_KEY_EXCH
				| NegotiateFlags.NTLMSSP_NEGOTIATE_128
				| NegotiateFlags.NTLMSSP_NEGOTIATE_VERSION
				| NegotiateFlags.NTLMSSP_NEGOTIATE_TARGET_INFO
				| NegotiateFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
				| NegotiateFlags.NTLMSSP_NEGOTIATE_ALWAYS_SIGN
				| NegotiateFlags.NTLMSSP_NEGOTIATE_NTLM
				| NegotiateFlags.NTLMSSP_NEGOTIATE_SIGN
				| NegotiateFlags.NTLMSSP_REQUEST_TARGET
				| NegotiateFlags.NTLMSSP_NEGOTIATE_UNICODE;
		segment.set(Layouts.LE_INT32, 12, flags);

		// DomainNameFields:
		segment.set(Layouts.LE_UINT16, 16, (char) 0); // DomainNameLen
		segment.set(Layouts.LE_UINT16, 18, (char) 0); // DomainNameMaxLen
		segment.set(Layouts.LE_INT32, 20, 40); // DomainNameBufferOffset

		// WorkstationFields:
		segment.set(Layouts.LE_UINT16, 24, (char) 0); // WorkstationLen
		segment.set(Layouts.LE_UINT16, 26, (char) 0); // WorkstationMaxLen
		segment.set(Layouts.LE_INT32, 28, 40); // WorkstationBufferOffset

		// Version (https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b1a6ceb2-f8ad-462b-b5af-f18527c48175):
		segment.set(Layouts.BYTE, 32, (byte) 6); // ProductMajorVersion TODO
		segment.set(Layouts.BYTE, 33, (byte) 1); // ProductMinorVersion TODO
		segment.set(Layouts.LE_UINT16, 34, (char) 7600); // ProductBuild TODO
		segment.set(Layouts.BYTE, 39, NtlmMessage.NTLMSSP_REVISION_W2K3); // NTLMRevisionCurrent

		// Payload (empty for now):
		// DomainName + WorkstationName
		// e.g. MemorySegment.copy(MemorySegment.ofArray(domainNameBytes), 0, segment, 40, domainNameBytes.length); // NegotiateFlags

		return new NtlmNegotiateMessage(segment);
	}

	public int negotiateFlags() {
		return segment.get(Layouts.LE_INT32, 12);
	}

	public char domainNameLen() {
		return segment.get(Layouts.LE_UINT16, 16);
	}

	public char domainNameMaxLen() {
		return segment.get(Layouts.LE_UINT16, 18);
	}

	public int domainNameBufferOffset() {
		return segment.get(Layouts.LE_INT32, 20);
	}

	public char workstationLen() {
		return segment.get(Layouts.LE_UINT16, 24);
	}

	public char workstationMaxLen() {
		return segment.get(Layouts.LE_UINT16, 26);
	}

	public int workstationBufferOffset() {
		return segment.get(Layouts.LE_INT32, 28);
	}

	public long version() {
		return segment.get(Layouts.LE_INT64, 32);
	}

	public byte productMajorVersion() {
		return segment.get(Layouts.BYTE, 32);
	}

	public byte productMinorVersion() {
		return segment.get(Layouts.BYTE, 33);
	}

	public char productBuild() {
		return segment.get(Layouts.LE_UINT16, 34);
	}

	public byte ntlmRevisionCurrent() {
		return segment.get(Layouts.BYTE, 39);
	}

	public byte[] domainName() {
		return segment.asSlice(domainNameBufferOffset(), domainNameLen()).toArray(Layouts.BYTE);
	}

	public byte[] workstationName() {
		return segment.asSlice(workstationBufferOffset(), workstationLen()).toArray(Layouts.BYTE);
	}

}
