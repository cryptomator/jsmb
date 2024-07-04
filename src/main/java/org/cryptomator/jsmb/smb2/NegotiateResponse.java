package org.cryptomator.jsmb.smb2;

import org.cryptomator.jsmb.smb2.capabilities.NegotiateContext;
import org.cryptomator.jsmb.util.Layouts;
import org.cryptomator.jsmb.util.MemorySegments;

import java.lang.foreign.MemorySegment;
import java.util.Set;
import java.util.UUID;

/**
 * A SMB 2 NEGOTIATE Response
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/63abf97c-0d09-47e2-88d6-6bfa552949a5">SMB2 NEGOTIATE Response Specification</a>
 */
public record NegotiateResponse(PacketHeader header, MemorySegment segment) implements SMB2Message {

	public interface SecurityMode {
		short SIGNING_ENABLED = 0x0001;
		short SIGNING_REQUIRED = 0x0002;
	}

	public static final short STRUCTURE_SIZE = 65;

	public NegotiateResponse {
		segment.set(Layouts.LE_INT16, 0, STRUCTURE_SIZE);
	}

	public NegotiateResponse(PacketHeader header) {
		this(header, MemorySegment.ofArray(new byte[STRUCTURE_SIZE]));
	}

	public void securityMode(short securityMode) {
		segment.set(Layouts.LE_INT16, 2, securityMode);
	}

	public void dialectRevision(short dialectRevision) {
		segment.set(Layouts.LE_INT16, 4, dialectRevision);
	}

	public void negotiateContextCount(short negotiateContextCount) {
		segment.set(Layouts.LE_INT16, 6, negotiateContextCount);
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

	public void securityBufferOffset(short securityBufferOffset) {
		segment.set(Layouts.LE_INT16, 56, securityBufferOffset);
	}

	public void securityBufferLength(short securityBufferLength) {
		segment.set(Layouts.LE_INT16, 58, securityBufferLength);
	}

	private short securityBufferLength() {
		return segment.get(Layouts.LE_INT16, 58);
	}

	public void negotiateContextOffset(int negotiateContextOffset) {
		segment.set(Layouts.LE_INT32, 60, negotiateContextOffset);
	}

	public NegotiateResponse withSecurityBuffer(byte[] buffer) {
		if (buffer.length > Short.MAX_VALUE) {
			throw new IllegalArgumentException("Buffer too large");
		}
		var segmentWithoutBuffer = segment.asSlice(0, 64);
		var segmentWithBuffer = MemorySegments.concat(segmentWithoutBuffer, MemorySegment.ofArray(buffer));
		var updatedResponse = new NegotiateResponse(header, segmentWithBuffer);
		updatedResponse.securityBufferOffset((short) (header.structureSize() + 64));
		updatedResponse.securityBufferLength((short) buffer.length);
		return updatedResponse;
	}

	public NegotiateResponse withNegotiateContexts(Set<NegotiateContext> contexts) {
		// start of negotiate context is 8-byte-aligned
		int endOfSecurityBuffer = 64 + securityBufferLength();
		int padding = 8 - endOfSecurityBuffer % 8;
		var contextsSegment = MemorySegment.ofArray(new byte[padding]);
		for (var context : contexts) {
			contextsSegment = MemorySegments.concat(contextsSegment, context.segment());
		}
		var segmentWithContexts = MemorySegments.concat(segment, contextsSegment);
		var updatedResponse = new NegotiateResponse(header, segmentWithContexts);
		updatedResponse.negotiateContextOffset(header.structureSize() + endOfSecurityBuffer + padding);
		updatedResponse.negotiateContextCount((short) contexts.size());
		return updatedResponse;
	}

}
