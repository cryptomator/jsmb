package org.cryptomator.jsmb.smb2.io;

import org.cryptomator.jsmb.smb2.PacketHeader;
import org.cryptomator.jsmb.smb2.SMB2Message;
import org.cryptomator.jsmb.util.Layouts;

import java.lang.foreign.MemorySegment;

/**
 * SMB2 WRITE Response. Fixed portion is 16 bytes; {@link #STRUCTURE_SIZE} is 17 per spec.
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/7b80a339-f4d3-4575-8ce2-70a06f24f133">2.2.22 SMB2 WRITE Response</a>
 */
public record WriteResponse(PacketHeader header, MemorySegment segment) implements SMB2Message {

	public static final char STRUCTURE_SIZE = 17;
	public static final int FIXED_PORTION_SIZE = 16;

	public WriteResponse {
		segment.set(Layouts.LE_UINT16, 0, STRUCTURE_SIZE);
	}

	public WriteResponse(PacketHeader header) {
		this(header, MemorySegment.ofArray(new byte[FIXED_PORTION_SIZE]));
	}

	public void count(int bytesWritten) {
		segment.set(Layouts.LE_INT32, 4, bytesWritten);
	}

	public void remaining(int remaining) {
		segment.set(Layouts.LE_INT32, 8, remaining);
	}
}
