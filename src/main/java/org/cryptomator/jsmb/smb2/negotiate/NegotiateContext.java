package org.cryptomator.jsmb.smb2.negotiate;

import org.cryptomator.jsmb.util.Layouts;
import org.cryptomator.jsmb.util.MemorySegments;

import java.lang.foreign.MemorySegment;

/**
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/15332256-522e-4a53-8cd7-0bd17678a2f7">SMB2 NEGOTIATE_CONTEXT Request Values</a>
 */
public sealed interface NegotiateContext permits PreauthIntegrityCapabilities, EncryptionCapabilities, CompressionCapabilities, NetnameNegotiateContextId, TransportCapabilities, RDMATransformCapabilities, SigningCapabilities, ReservedCapabilities {

	char PREAUTH_INTEGRITY_CAPABILITIES = 0x01;
	char ENCRYPTION_CAPABILITIES = 0x02;
	char COMPRESSION_CAPABILITIES = 0x03;
	char NETNAME_NEGOTIATE_CONTEXT_ID = 0x05;
	char TRANSPORT_CAPABILITIES = 0x06;
	char RDMA_TRANSFORM_CAPABILITIES = 0x07;
	char SIGNING_CAPABILITIES = 0x08;
	char CONTEXTTYPE_RESERVED = 0x0100;

	static NegotiateContext parse(MemorySegment segment) {
		var contextType = segment.get(Layouts.LE_UINT16, 0);
		var dataLen = segment.get(Layouts.LE_UINT16, 2);
		var data = segment.asSlice(8, dataLen);
		return switch (contextType) {
			case PREAUTH_INTEGRITY_CAPABILITIES -> new PreauthIntegrityCapabilities(data);
			case ENCRYPTION_CAPABILITIES -> new EncryptionCapabilities(data);
			case COMPRESSION_CAPABILITIES -> new CompressionCapabilities(data);
			case NETNAME_NEGOTIATE_CONTEXT_ID -> new NetnameNegotiateContextId(data);
			case TRANSPORT_CAPABILITIES -> new TransportCapabilities(data);
			case RDMA_TRANSFORM_CAPABILITIES -> new RDMATransformCapabilities(data);
			case SIGNING_CAPABILITIES -> new SigningCapabilities(data);
			case CONTEXTTYPE_RESERVED -> new ReservedCapabilities(data);
			default -> throw new IllegalArgumentException("Unknown negotiate context type: 0x" + Integer.toHexString(contextType));
		};
	}

	char contextType();

	MemorySegment data();

	default int segmentSize() {
		return 8 + (char) data().byteSize();
	}

	default MemorySegment segment() {
		var header = MemorySegment.ofArray(new byte[8]);
		header.set(Layouts.LE_UINT16, 0, contextType());
		header.set(Layouts.LE_UINT16, 2, (char) data().byteSize());
		return MemorySegments.concat(header, data());
	}
}
