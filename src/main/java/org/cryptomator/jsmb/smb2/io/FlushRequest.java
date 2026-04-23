package org.cryptomator.jsmb.smb2.io;

import org.cryptomator.jsmb.smb2.FileId;
import org.cryptomator.jsmb.smb2.FileIdCarrying;
import org.cryptomator.jsmb.smb2.PacketHeader;
import org.cryptomator.jsmb.smb2.SMB2Message;
import org.cryptomator.jsmb.util.Layouts;

import java.lang.foreign.MemorySegment;

/**
 * SMB2 FLUSH Request. 24-byte fixed structure.
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/e494678b-b1fc-44a0-b86e-8195acf74ad7">2.2.17 SMB2 FLUSH Request</a>
 */
public record FlushRequest(PacketHeader header, MemorySegment segment) implements SMB2Message, FileIdCarrying {

	public char structureSize() {
		return segment.get(Layouts.LE_UINT16, 0);
	}

	public FileId fileId() {
		return FileId.fromSegment(segment.asSlice(8, FileId.SIZE));
	}

	public void fileId(FileId fileId) {
		fileId.writeTo(segment.asSlice(8, FileId.SIZE));
	}
}
