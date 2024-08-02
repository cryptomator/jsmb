package org.cryptomator.jsmb.smb2;

import org.cryptomator.jsmb.util.Layouts;
import org.cryptomator.jsmb.util.MemorySegments;

import java.lang.foreign.MemorySegment;

/**
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/0324190f-a31b-4666-9fa9-5c624273a694">SMB2 SESSION_SETUP Response</a>
 */
public record SessionSetupResponse(PacketHeader header, MemorySegment segment) implements SMB2Message {

	public static final char SMB2_SESSION_FLAG_IS_GUEST = 0x0001;
	public static final char SMB2_SESSION_FLAG_IS_NULL = 0x0002;
	public static final char SMB2_SESSION_FLAG_ENCRYPT_DATA = 0x0004;

	public static final char STRUCTURE_SIZE = 9;

	public SessionSetupResponse {
		segment.set(Layouts.LE_UINT16, 0, STRUCTURE_SIZE);
	}

	public SessionSetupResponse(PacketHeader header) {
		this(header, MemorySegment.ofArray(new byte[STRUCTURE_SIZE]));
	}

	public void sessionFlags(char sessionFlags) {
		segment.set(Layouts.LE_UINT16, 2, sessionFlags);
	}

	public void securityBufferOffset(char securityBufferOffset) {
		segment.set(Layouts.LE_UINT16, 4, securityBufferOffset);
	}

	public void securityBufferLength(char securityBufferLength) {
		segment.set(Layouts.LE_UINT16, 6, securityBufferLength);
	}

	public SessionSetupResponse withSecurityBuffer(byte[] buffer) {
		if (buffer.length > Character.MAX_VALUE) {
			throw new IllegalArgumentException("Buffer too large");
		}
		var segmentWithoutBuffer = segment.asSlice(0, 8);
		var segmentWithBuffer = MemorySegments.concat(segmentWithoutBuffer, MemorySegment.ofArray(buffer));
		var updatedResponse = new SessionSetupResponse(header, segmentWithBuffer);
		updatedResponse.securityBufferOffset((char) (header.structureSize() + 8));
		updatedResponse.securityBufferLength((char) buffer.length);
		return updatedResponse;
	}

}
