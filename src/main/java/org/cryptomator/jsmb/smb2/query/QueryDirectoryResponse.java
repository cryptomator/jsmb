package org.cryptomator.jsmb.smb2.query;

import org.cryptomator.jsmb.smb2.PacketHeader;
import org.cryptomator.jsmb.smb2.SMB2Message;
import org.cryptomator.jsmb.util.Layouts;
import org.cryptomator.jsmb.util.MemorySegments;

import java.lang.foreign.MemorySegment;

/**
 * SMB2 QUERY_DIRECTORY Response. Fixed portion is 8 bytes; {@link #STRUCTURE_SIZE} is 9 per spec.
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/4f75351b-048c-4a0e-9c11-17da6f4dda17">2.2.34 SMB2 QUERY_DIRECTORY Response</a>
 */
public record QueryDirectoryResponse(PacketHeader header, MemorySegment segment) implements SMB2Message {

	public static final char STRUCTURE_SIZE = 9;
	public static final int FIXED_PORTION_SIZE = 8;

	public QueryDirectoryResponse {
		segment.set(Layouts.LE_UINT16, 0, STRUCTURE_SIZE);
	}

	public QueryDirectoryResponse(PacketHeader header) {
		this(header, MemorySegment.ofArray(new byte[FIXED_PORTION_SIZE]));
	}

	public void outputBufferOffset(char offset) {
		segment.set(Layouts.LE_UINT16, 2, offset);
	}

	public void outputBufferLength(int length) {
		segment.set(Layouts.LE_INT32, 4, length);
	}

	/**
	 * Appends {@code buffer} as the response's variable tail and sets the offset + length fields.
	 */
	public QueryDirectoryResponse withOutputBuffer(byte[] buffer) {
		var fixed = segment.asSlice(0, FIXED_PORTION_SIZE);
		var combined = MemorySegments.concat(fixed, MemorySegment.ofArray(buffer));
		var updated = new QueryDirectoryResponse(header, combined);
		updated.outputBufferOffset((char) (PacketHeader.STRUCTURE_SIZE + FIXED_PORTION_SIZE));
		updated.outputBufferLength(buffer.length);
		return updated;
	}
}
