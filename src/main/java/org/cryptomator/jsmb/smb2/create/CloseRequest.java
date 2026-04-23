package org.cryptomator.jsmb.smb2.create;

import org.cryptomator.jsmb.smb2.FileId;
import org.cryptomator.jsmb.smb2.FileIdCarrying;
import org.cryptomator.jsmb.smb2.PacketHeader;
import org.cryptomator.jsmb.smb2.SMB2Message;
import org.cryptomator.jsmb.util.Layouts;

import java.lang.foreign.MemorySegment;

/**
 * SMB2 CLOSE Request. Fixed 24-byte structure.
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/9e93dcd0-bb43-4d16-a4f2-eeb91d7a8e7b">2.2.15 SMB2 CLOSE Request</a>
 */
public record CloseRequest(PacketHeader header, MemorySegment segment) implements SMB2Message, FileIdCarrying {

	/**
	 * {@code SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB} — client wants post-close basic + standard info in the response.
	 */
	public static final char FLAG_POSTQUERY_ATTRIB = 0x0001;

	public char structureSize() {
		return segment.get(Layouts.LE_UINT16, 0);
	}

	public char flags() {
		return segment.get(Layouts.LE_UINT16, 2);
	}

	public boolean postQueryAttrib() {
		return (flags() & FLAG_POSTQUERY_ATTRIB) != 0;
	}

	public FileId fileId() {
		return FileId.fromSegment(segment.asSlice(8, FileId.SIZE));
	}

	public void fileId(FileId fileId) {
		fileId.writeTo(segment.asSlice(8, FileId.SIZE));
	}
}
