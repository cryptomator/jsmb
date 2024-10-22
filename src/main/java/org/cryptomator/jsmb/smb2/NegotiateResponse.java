package org.cryptomator.jsmb.smb2;

import org.cryptomator.jsmb.smb2.negotiate.NegotiateContext;
import org.cryptomator.jsmb.util.Layouts;
import org.cryptomator.jsmb.util.MemorySegments;

import java.lang.foreign.MemorySegment;
import java.util.Collection;
import java.util.UUID;

/**
 * A SMB 2 NEGOTIATE Response
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/63abf97c-0d09-47e2-88d6-6bfa552949a5">SMB2 NEGOTIATE Response Specification</a>
 */
public record NegotiateResponse(PacketHeader header, MemorySegment segment) implements SMB2Message {

	public static final char STRUCTURE_SIZE = 65;

	public NegotiateResponse {
		segment.set(Layouts.LE_UINT16, 0, STRUCTURE_SIZE);
	}

	public NegotiateResponse(PacketHeader header) {
		this(header, MemorySegment.ofArray(new byte[STRUCTURE_SIZE]));
		securityBufferOffset((char) (header.structureSize() + 64));
		securityBufferLength((char) 0);
		negotiateContextOffset(header.structureSize() + 64 + 0);
		negotiateContextCount((char) 0);
	}

	public void securityMode(char securityMode) {
		segment.set(Layouts.LE_UINT16, 2, securityMode);
	}

	public void dialectRevision(char dialectRevision) {
		segment.set(Layouts.LE_UINT16, 4, dialectRevision);
	}

	public void negotiateContextCount(char negotiateContextCount) {
		segment.set(Layouts.LE_UINT16, 6, negotiateContextCount);
	}

	public void serverGuid(UUID serverGuid) {
		segment.set(Layouts.BE_INT64, 8, serverGuid.getMostSignificantBits());
		segment.set(Layouts.BE_INT64, 16, serverGuid.getLeastSignificantBits());
	}

	public void capabilities(int capabilities) {
		segment.set(Layouts.LE_INT32, 24, capabilities);
	}

	public void maxTransactSize(int maxTransactSize) {
		segment.set(Layouts.LE_INT32, 28, maxTransactSize);
	}

	public void maxReadSize(int maxReadSize) {
		segment.set(Layouts.LE_INT32, 32, maxReadSize);
	}

	public void maxWriteSize(int maxWriteSize) {
		segment.set(Layouts.LE_INT32, 36, maxWriteSize);
	}

	public void systemTime(long systemTime) {
		segment.set(Layouts.LE_INT64, 40, systemTime);
	}

	public void serverStartTime(long serverStartTime) {
		segment.set(Layouts.LE_INT64, 48, serverStartTime);
	}

	public void securityBufferOffset(char securityBufferOffset) {
		segment.set(Layouts.LE_UINT16, 56, securityBufferOffset);
	}

	public void securityBufferLength(char securityBufferLength) {
		segment.set(Layouts.LE_UINT16, 58, securityBufferLength);
	}

	private char securityBufferLength() {
		return segment.get(Layouts.LE_UINT16, 58);
	}

	public void negotiateContextOffset(int negotiateContextOffset) {
		segment.set(Layouts.LE_INT32, 60, negotiateContextOffset);
	}

	public NegotiateResponse withSecurityBuffer(byte[] buffer) {
		if (buffer.length > Character.MAX_VALUE) {
			throw new IllegalArgumentException("Buffer too large");
		}
		var segmentWithoutBuffer = segment.asSlice(0, 64);
		var segmentWithBuffer = MemorySegments.concat(segmentWithoutBuffer, MemorySegment.ofArray(buffer));
		var updatedResponse = new NegotiateResponse(header, segmentWithBuffer);
		updatedResponse.securityBufferOffset((char) (header.structureSize() + 64));
		updatedResponse.securityBufferLength((char) buffer.length);
		return updatedResponse;
	}

	public NegotiateResponse withNegotiateContexts(Collection<NegotiateContext> contexts) {
		var maxCombinedSize = contexts.stream().mapToInt(NegotiateContext::segmentSize).map(size -> size + 8).sum();
		var contextsSegment = MemorySegment.ofArray(new byte[maxCombinedSize]);
		// start of negotiate context is 8-byte-aligned
		var pos = 0;
		for (var context : contexts) {
			// add further padding to align to 8 bytes
			if (pos % 8 != 0) {
				pos += (8 - pos % 8) % 8;
			}
			var contextSize = context.segmentSize();
			assert pos % 8 == 0;
			MemorySegment.copy(context.segment(), 0, contextsSegment, pos, contextSize);
			pos += contextSize;
		}
		var paddedSegment = MemorySegments.pad(segment, 8);
		var segmentWithContexts = MemorySegments.concat(paddedSegment, contextsSegment.asSlice(0, pos));
		var updatedResponse = new NegotiateResponse(header, segmentWithContexts);
		updatedResponse.negotiateContextOffset((int) (header.structureSize() + paddedSegment.byteSize()));
		updatedResponse.negotiateContextCount((char) contexts.size());
		return updatedResponse;
	}

}
