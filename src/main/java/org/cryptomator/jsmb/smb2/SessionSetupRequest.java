package org.cryptomator.jsmb.smb2;

import org.cryptomator.jsmb.util.Layouts;

import java.lang.foreign.MemorySegment;

/**
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5a3c2c28-d6b0-48ed-b917-a86b2ca4575f">SMB2 SESSION_SETUP Request</a>
 */
public record SessionSetupRequest(PacketHeader header, MemorySegment segment) implements SMB2Message {

	public static final byte FLAG_BINDING = 0x01;

	public char structureSize() {
		return segment.get(Layouts.LE_UINT16, 0); // should always be 25, regardless of security buffer
	}

	public byte flags() {
		return segment.get(Layouts.BYTE, 2);
	}

	public byte securityMode() {
		return segment.get(Layouts.BYTE, 3);
	}

	public int capabilities() {
		return segment.get(Layouts.LE_INT32, 4);
	}

	public char securityBufferOffset() {
		return segment.get(Layouts.LE_UINT16, 12);
	}

	public int securityBufferLength() {
		return segment.get(Layouts.LE_UINT16, 14);
	}

	public long previousSessionId() {
		return segment.get(Layouts.LE_INT64, 16);
	}

	public byte[] securityBuffer() {
		return segment.asSlice(securityBufferOffset() - PacketHeader.STRUCTURE_SIZE, securityBufferLength()).toArray(Layouts.BYTE);
	}

}
