package org.cryptomator.jsmb.ntlm;

import org.cryptomator.jsmb.util.Layouts;

import java.lang.foreign.MemorySegment;
import java.nio.charset.StandardCharsets;

/**
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b34032e5-3aae-4bc6-84c3-c6d80eadf7f2">NEGOTIATE_MESSAGE</a>
 */
public record NtlmNegotiateMessage(MemorySegment segment) {

	private static final byte[] SIGNATURE = new byte[] { (byte) 'N', (byte) 'T', (byte) 'L', (byte) 'M', (byte) 'S', (byte) 'S', (byte) 'P', 0 };
	private static final int MESSAGE_TYPE = 0x00000001;
	private static final byte NTLMSSP_REVISION_W2K3 = 0x0F;

	public static NtlmNegotiateMessage create(String domainName) {
		byte[] domainNameBytes = domainName.getBytes(StandardCharsets.US_ASCII);

		MemorySegment segment = MemorySegment.ofArray(new byte[40 + domainNameBytes.length]);
		segment.copyFrom(MemorySegment.ofArray(SIGNATURE)); // Signature
		segment.set(Layouts.LE_INT32, 8, MESSAGE_TYPE); // MessageType

		// Flags
		int flags = NegotiateFlags.NTLMSSP_NEGOTIATE_KEY_EXCH | NegotiateFlags.NTLMSSP_NEGOTIATE_VERSION | NegotiateFlags.NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED | NegotiateFlags.NTLMSSP_NEGOTIATE_UNICODE;
		segment.set(Layouts.LE_INT32, 12, flags);

		// DomainNameFields:
		segment.set(Layouts.LE_UINT16, 16, (char) domainNameBytes.length); // DomainNameLen
		segment.set(Layouts.LE_UINT16, 18, (char) domainNameBytes.length); // DomainNameMaxLen
		segment.set(Layouts.LE_INT32, 20, 40); // DomainNameBufferOffset

		// WorkstationFields:
		segment.set(Layouts.LE_UINT16, 24, (char) 0); // WorkstationLen
		segment.set(Layouts.LE_UINT16, 26, (char) 0); // WorkstationMaxLen
		segment.set(Layouts.LE_INT32, 28, 40 + domainNameBytes.length); // WorkstationBufferOffset

		// Version (https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b1a6ceb2-f8ad-462b-b5af-f18527c48175):
		segment.set(Layouts.BYTE, 32, (byte) 6); // ProductMajorVersion TODO
		segment.set(Layouts.BYTE, 33, (byte) 1); // ProductMinorVersion TODO
		segment.set(Layouts.LE_UINT16, 34, (char) 7600); // ProductBuild TODO
		segment.set(Layouts.BYTE, 39, NTLMSSP_REVISION_W2K3); // NTLMRevisionCurrent

		// Payload:
		// DomainName + WorkstationName
		MemorySegment.copy(MemorySegment.ofArray(domainNameBytes), 0, segment, 40, domainNameBytes.length); // NegotiateFlags

		return new NtlmNegotiateMessage(segment);
	}

}
