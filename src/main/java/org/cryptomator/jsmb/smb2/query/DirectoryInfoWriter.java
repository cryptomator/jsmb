package org.cryptomator.jsmb.smb2.query;

import org.cryptomator.jsmb.share.DirEntry;
import org.cryptomator.jsmb.util.WinFileTime;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Packs {@link DirEntry} records into one of the {@code FileXxxDirectoryInformation} buffer formats
 * that QUERY_DIRECTORY returns. Honors the MS-FSCC 8-byte inter-entry alignment rule, fills each
 * entry's {@code NextEntryOffset} (0 for the last entry), and truncates at {@code maxBufferSize}.
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/4718fc40-e539-4014-8e33-b675af74e3e1">MS-FSCC 2.4 File Information Classes</a>
 */
public final class DirectoryInfoWriter {

	/** 24 zero bytes — we don't generate 8.3 short names, so every ShortName field is empty. */
	private static final byte[] EMPTY_SHORT_NAME = new byte[24];

	private DirectoryInfoWriter() {}

	public record Result(byte[] buffer, int entriesWritten) {}

	/**
	 * Writes {@code entries} starting at {@code startIndex} into a buffer up to {@code maxBufferSize}
	 * bytes. Returns the trimmed buffer (exactly the bytes written, no trailing pad) and how many
	 * entries fit. An {@code entriesWritten} of {@code 0} with a non-empty remaining range means not
	 * even the first entry fit — the caller should map that to {@code STATUS_INFO_LENGTH_MISMATCH}.
	 *
	 * @param cls            info class to render
	 * @param entries        pre-collected directory listing (so we can peek/lookahead cheaply)
	 * @param startIndex     next entry to render
	 * @param maxBufferLen   upper bound on the returned buffer length
	 * @param singleEntry    true when {@code SL_RETURN_SINGLE_ENTRY} is set
	 */
	public static Result write(FileInformationClass cls, List<DirEntry> entries, int startIndex, int maxBufferLen, boolean singleEntry) {
		var buf = ByteBuffer.allocate(maxBufferLen).order(ByteOrder.LITTLE_ENDIAN);
		int written = 0;
		int lastEntryOffset = -1;
		int end = entries.size();

		for (int i = startIndex; i < end; i++) {
			var entry = entries.get(i);
			byte[] nameBytes = entry.name().getBytes(StandardCharsets.UTF_16LE);
			int headerSize = fixedHeaderSize(cls);
			int entrySize = headerSize + nameBytes.length;
			int paddingAfter = (8 - (entrySize % 8)) % 8;
			int alignedSize = entrySize + paddingAfter;

			if (buf.position() + alignedSize > maxBufferLen) {
				break; // no room for this entry; bail out
			}

			int entryStart = buf.position();
			if (lastEntryOffset >= 0) {
				// Patch the previous entry's NextEntryOffset (field lives at offset 0 of the entry)
				buf.putInt(lastEntryOffset, entryStart - lastEntryOffset);
			}

			writeEntry(buf, cls, entry, nameBytes);
			for (int p = 0; p < paddingAfter; p++) buf.put((byte) 0);

			lastEntryOffset = entryStart;
			written++;

			if (singleEntry) break;
		}

		byte[] out = new byte[buf.position()];
		buf.rewind();
		buf.get(out);
		return new Result(out, written);
	}

	/**
	 * Fixed-header size in bytes for each supported information class — excludes the trailing
	 * variable-length {@code FileName}.
	 */
	static int fixedHeaderSize(FileInformationClass cls) {
		return switch (cls) {
			case FILE_DIRECTORY_INFORMATION -> 64;
			case FILE_FULL_DIRECTORY_INFORMATION -> 68;
			case FILE_BOTH_DIRECTORY_INFORMATION -> 94;
			case FILE_NAMES_INFORMATION -> 12;
			case FILE_ID_FULL_DIRECTORY_INFORMATION -> 80;
			case FILE_ID_BOTH_DIRECTORY_INFORMATION -> 104;
		};
	}

	private static void writeEntry(ByteBuffer buf, FileInformationClass cls, DirEntry entry, byte[] nameBytes) {
		switch (cls) {
			case FILE_DIRECTORY_INFORMATION -> writeDirectoryInfo(buf, entry, nameBytes);
			case FILE_FULL_DIRECTORY_INFORMATION -> writeFullDirectoryInfo(buf, entry, nameBytes);
			case FILE_BOTH_DIRECTORY_INFORMATION -> writeBothDirectoryInfo(buf, entry, nameBytes);
			case FILE_NAMES_INFORMATION -> writeNamesInfo(buf, entry, nameBytes);
			case FILE_ID_FULL_DIRECTORY_INFORMATION -> writeIdFullDirectoryInfo(buf, entry, nameBytes);
			case FILE_ID_BOTH_DIRECTORY_INFORMATION -> writeIdBothDirectoryInfo(buf, entry, nameBytes);
		}
	}

	private static void writeCommonTimesAndSizes(ByteBuffer buf, DirEntry entry) {
		var basic = entry.basic();
		var std = entry.standard();
		buf.putLong(WinFileTime.fromInstant(basic.creationTime()));
		buf.putLong(WinFileTime.fromInstant(basic.lastAccessTime()));
		buf.putLong(WinFileTime.fromInstant(basic.lastWriteTime()));
		buf.putLong(WinFileTime.fromInstant(basic.changeTime()));
		buf.putLong(std.endOfFile());
		buf.putLong(std.allocationSize());
		buf.putInt(basic.fileAttributes());
	}

	private static void writeDirectoryInfo(ByteBuffer buf, DirEntry entry, byte[] nameBytes) {
		buf.putInt(0);                   // NextEntryOffset — patched later
		buf.putInt(0);                   // FileIndex (reserved, zero)
		writeCommonTimesAndSizes(buf, entry);
		buf.putInt(nameBytes.length);    // FileNameLength
		buf.put(nameBytes);              // FileName
	}

	private static void writeFullDirectoryInfo(ByteBuffer buf, DirEntry entry, byte[] nameBytes) {
		buf.putInt(0);
		buf.putInt(0);
		writeCommonTimesAndSizes(buf, entry);
		buf.putInt(nameBytes.length);
		buf.putInt(0);                   // EaSize
		buf.put(nameBytes);
	}

	private static void writeBothDirectoryInfo(ByteBuffer buf, DirEntry entry, byte[] nameBytes) {
		buf.putInt(0);
		buf.putInt(0);
		writeCommonTimesAndSizes(buf, entry);
		buf.putInt(nameBytes.length);
		buf.putInt(0);                   // EaSize
		buf.put((byte) 0);               // ShortNameLength
		buf.put((byte) 0);               // Reserved1
		buf.put(EMPTY_SHORT_NAME);       // ShortName (24 bytes of 0)
		buf.put(nameBytes);
	}

	private static void writeIdBothDirectoryInfo(ByteBuffer buf, DirEntry entry, byte[] nameBytes) {
		buf.putInt(0);
		buf.putInt(0);
		writeCommonTimesAndSizes(buf, entry);
		buf.putInt(nameBytes.length);
		buf.putInt(0);                   // EaSize
		buf.put((byte) 0);               // ShortNameLength
		buf.put((byte) 0);               // Reserved1
		buf.put(EMPTY_SHORT_NAME);
		buf.putShort((short) 0);         // Reserved2
		buf.putLong(fileReferenceNumber(entry));
		buf.put(nameBytes);
	}

	private static void writeIdFullDirectoryInfo(ByteBuffer buf, DirEntry entry, byte[] nameBytes) {
		buf.putInt(0);
		buf.putInt(0);
		writeCommonTimesAndSizes(buf, entry);
		buf.putInt(nameBytes.length);
		buf.putInt(0);                   // EaSize
		buf.putInt(0);                   // Reserved
		buf.putLong(fileReferenceNumber(entry));
		buf.put(nameBytes);
	}

	private static void writeNamesInfo(ByteBuffer buf, DirEntry entry, byte[] nameBytes) {
		buf.putInt(0);                   // NextEntryOffset
		buf.putInt(0);                   // FileIndex
		buf.putInt(nameBytes.length);    // FileNameLength
		buf.put(nameBytes);
	}

	/**
	 * Derives a deterministic 64-bit filesystem file reference number from the entry's name.
	 * Not collision-free, but smbj and smbclient only use this for display; a hash is fine for a
	 * test-grade backend.
	 */
	private static long fileReferenceNumber(DirEntry entry) {
		long h = 1125899906842597L; // large prime seed
		for (int i = 0; i < entry.name().length(); i++) {
			h = 31 * h + entry.name().charAt(i);
		}
		return h;
	}
}
