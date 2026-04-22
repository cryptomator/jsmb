package org.cryptomator.jsmb.smb2.query;

import org.cryptomator.jsmb.smb2.FileId;
import org.cryptomator.jsmb.smb2.PacketHeader;
import org.cryptomator.jsmb.smb2.SMB2Message;
import org.cryptomator.jsmb.util.Layouts;

import java.lang.foreign.MemorySegment;
import java.nio.charset.StandardCharsets;

/**
 * SMB2 QUERY_DIRECTORY Request. Fixed portion is 32 bytes; {@link #structureSize()} is 33 per the spec
 * convention (variable-length structures declare {@code FixedPortionSize + 1}).
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/10906442-294c-46d3-8515-c277efe1f752">2.2.33 SMB2 QUERY_DIRECTORY Request</a>
 */
public record QueryDirectoryRequest(PacketHeader header, MemorySegment segment) implements SMB2Message {

	/** Reset the directory enumeration to the start. */
	public static final byte FLAG_RESTART_SCAN = 0x01;
	/** Return at most one entry and stop. */
	public static final byte FLAG_RETURN_SINGLE_ENTRY = 0x02;
	/** Resume enumeration at {@link #fileIndex()}. */
	public static final byte FLAG_INDEX_SPECIFIED = 0x04;
	/** Reopen the directory from scratch (SMB 3.x). */
	public static final byte FLAG_REOPEN = 0x10;

	public char structureSize() {
		return segment.get(Layouts.LE_UINT16, 0);
	}

	public byte fileInformationClass() {
		return segment.get(Layouts.BYTE, 2);
	}

	public byte flags() {
		return segment.get(Layouts.BYTE, 3);
	}

	public int fileIndex() {
		return segment.get(Layouts.LE_INT32, 4);
	}

	public FileId fileId() {
		return FileId.fromSegment(segment.asSlice(8, FileId.SIZE));
	}

	public char fileNameOffset() {
		return segment.get(Layouts.LE_UINT16, 24);
	}

	public char fileNameLength() {
		return segment.get(Layouts.LE_UINT16, 26);
	}

	public int outputBufferLength() {
		return segment.get(Layouts.LE_INT32, 28);
	}

	public boolean hasFlag(byte flag) {
		return (flags() & flag) == flag;
	}

	/**
	 * @return the UTF-16LE search pattern (e.g. {@code *} or {@code *.txt}), or empty when no pattern was supplied.
	 */
	public String fileName() {
		int length = fileNameLength();
		if (length == 0) return "";
		int offset = fileNameOffset() - PacketHeader.STRUCTURE_SIZE;
		byte[] bytes = segment.asSlice(offset, length).toArray(Layouts.BYTE);
		return new String(bytes, StandardCharsets.UTF_16LE);
	}
}
