package org.cryptomator.jsmb.smb2.info;

import org.cryptomator.jsmb.share.FileBasicInfo;
import org.cryptomator.jsmb.share.FileStandardInfo;
import org.cryptomator.jsmb.util.WinFileTime;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

/**
 * Serializes the MS-FSCC 2.4 file-level info classes that {@code QUERY_INFO} can return against an
 * open file or directory.
 */
public final class FileInfoWriter {

	private FileInfoWriter() {}

	public static byte[] write(FileInfoClass cls, String openPath, FileBasicInfo basic, FileStandardInfo standard) {
		return switch (cls) {
			case FILE_BASIC_INFORMATION -> basicInfo(basic);
			case FILE_STANDARD_INFORMATION -> standardInfo(standard);
			case FILE_INTERNAL_INFORMATION -> internalInfo(openPath);
			case FILE_EA_INFORMATION -> eaInfo();
			case FILE_ACCESS_INFORMATION -> accessInfo();
			case FILE_NAME_INFORMATION -> nameInfo(openPath);
			case FILE_POSITION_INFORMATION -> positionInfo();
			case FILE_MODE_INFORMATION -> modeInfo();
			case FILE_ALIGNMENT_INFORMATION -> alignmentInfo();
			case FILE_ALL_INFORMATION -> allInfo(openPath, basic, standard);
			case FILE_STREAM_INFORMATION -> streamInfo();
			case FILE_NETWORK_OPEN_INFORMATION -> networkOpenInfo(basic, standard);
			case FILE_ATTRIBUTE_TAG_INFORMATION -> attributeTagInfo(basic);
		};
	}

	/** MS-FSCC 2.4.7 — 40 bytes. */
	static byte[] basicInfo(FileBasicInfo basic) {
		var buf = alloc(40);
		buf.putLong(WinFileTime.fromInstant(basic.creationTime()));
		buf.putLong(WinFileTime.fromInstant(basic.lastAccessTime()));
		buf.putLong(WinFileTime.fromInstant(basic.lastWriteTime()));
		buf.putLong(WinFileTime.fromInstant(basic.changeTime()));
		buf.putInt(basic.fileAttributes());
		buf.putInt(0);                         // Reserved
		return buf.array();
	}

	/** MS-FSCC 2.4.41 — 24 bytes. */
	static byte[] standardInfo(FileStandardInfo standard) {
		var buf = alloc(24);
		buf.putLong(standard.allocationSize());
		buf.putLong(standard.endOfFile());
		buf.putInt(standard.numberOfLinks());
		buf.put((byte) (standard.deletePending() ? 1 : 0));
		buf.put((byte) (standard.directory() ? 1 : 0));
		buf.putShort((short) 0);               // Reserved
		return buf.array();
	}

	/** MS-FSCC 2.4.20 — 8 bytes. Synthetic IndexNumber hashed from the path. */
	static byte[] internalInfo(String openPath) {
		var buf = alloc(8);
		buf.putLong(pathHash(openPath));
		return buf.array();
	}

	/** MS-FSCC 2.4.15 — 4 bytes, always zero (no extended attributes). */
	static byte[] eaInfo() {
		return new byte[4];
	}

	/** MS-FSCC 2.4.2 — 4 bytes. Reports {@code FILE_ALL_ACCESS} until actual access control lands. */
	static byte[] accessInfo() {
		var buf = alloc(4);
		buf.putInt(0x001F01FF);                // FILE_ALL_ACCESS
		return buf.array();
	}

	/** MS-FSCC 2.4.38 — 8 bytes. Always zero (we don't track cursor position). */
	static byte[] positionInfo() {
		return new byte[8];
	}

	/** MS-FSCC 2.4.24 — 4 bytes. Always zero (no synchronous-io / write-through modes). */
	static byte[] modeInfo() {
		return new byte[4];
	}

	/** MS-FSCC 2.4.3 — 4 bytes. Always zero (byte-aligned, no DMA). */
	static byte[] alignmentInfo() {
		return new byte[4];
	}

	/**
	 * MS-FSCC 2.4.26 — {@code FileNameLength(4) + FileName(UTF-16LE)}. Name is absolute from the
	 * share root, backslash-delimited, leading backslash: {@code "\\"} for root, {@code "\\file.txt"}
	 * for a file.
	 */
	static byte[] nameInfo(String openPath) {
		byte[] nameBytes = displayName(openPath).getBytes(StandardCharsets.UTF_16LE);
		var buf = alloc(4 + nameBytes.length);
		buf.putInt(nameBytes.length);
		buf.put(nameBytes);
		return buf.array();
	}

	/**
	 * MS-FSCC 2.4.2a — composite: Basic(40) + Standard(24) + Internal(8) + Ea(4) + Access(4) +
	 * Position(8) + Mode(4) + Alignment(4) + Name(variable). The fixed prefix is 96 bytes.
	 */
	static byte[] allInfo(String openPath, FileBasicInfo basic, FileStandardInfo standard) {
		byte[] nameBytes = displayName(openPath).getBytes(StandardCharsets.UTF_16LE);
		var buf = alloc(96 + 4 + nameBytes.length);
		// Basic
		buf.putLong(WinFileTime.fromInstant(basic.creationTime()));
		buf.putLong(WinFileTime.fromInstant(basic.lastAccessTime()));
		buf.putLong(WinFileTime.fromInstant(basic.lastWriteTime()));
		buf.putLong(WinFileTime.fromInstant(basic.changeTime()));
		buf.putInt(basic.fileAttributes());
		buf.putInt(0);
		// Standard
		buf.putLong(standard.allocationSize());
		buf.putLong(standard.endOfFile());
		buf.putInt(standard.numberOfLinks());
		buf.put((byte) (standard.deletePending() ? 1 : 0));
		buf.put((byte) (standard.directory() ? 1 : 0));
		buf.putShort((short) 0);
		// Internal
		buf.putLong(pathHash(openPath));
		// Ea
		buf.putInt(0);
		// Access
		buf.putInt(0x001F01FF);
		// Position
		buf.putLong(0L);
		// Mode
		buf.putInt(0);
		// Alignment
		buf.putInt(0);
		// Name
		buf.putInt(nameBytes.length);
		buf.put(nameBytes);
		return buf.array();
	}

	/** MS-FSCC 2.4.44 — empty buffer = "no alternate streams" (NTFS concept, not applicable here). */
	static byte[] streamInfo() {
		return new byte[0];
	}

	/** MS-FSCC 2.4.25 — 56 bytes. Timestamps + sizes + attrs, packed tight. */
	static byte[] networkOpenInfo(FileBasicInfo basic, FileStandardInfo standard) {
		var buf = alloc(56);
		buf.putLong(WinFileTime.fromInstant(basic.creationTime()));
		buf.putLong(WinFileTime.fromInstant(basic.lastAccessTime()));
		buf.putLong(WinFileTime.fromInstant(basic.lastWriteTime()));
		buf.putLong(WinFileTime.fromInstant(basic.changeTime()));
		buf.putLong(standard.allocationSize());
		buf.putLong(standard.endOfFile());
		buf.putInt(basic.fileAttributes());
		buf.putInt(0);                         // Reserved
		return buf.array();
	}

	/** MS-FSCC 2.4.6 — 8 bytes. ReparseTag=0 (no reparse points). */
	static byte[] attributeTagInfo(FileBasicInfo basic) {
		var buf = alloc(8);
		buf.putInt(basic.fileAttributes());
		buf.putInt(0);                         // ReparseTag
		return buf.array();
	}

	/**
	 * Translates our forward-slash relative path (e.g. {@code "sub/file.txt"}) into the
	 * backslash-delimited absolute-from-share-root form Windows clients expect
	 * (e.g. {@code "\\sub\\file.txt"}).
	 */
	private static String displayName(String openPath) {
		if (openPath.isEmpty()) return "\\";
		return "\\" + openPath.replace('/', '\\');
	}

	/**
	 * Deterministic synthetic file-id derived from the path. Not collision-free, but the value
	 * only surfaces in FileInternalInformation / FileAllInformation's IndexNumber field; a hash
	 * matches the semantics of a filesystem inode well enough for a test-grade backend.
	 */
	private static long pathHash(String openPath) {
		long h = 1125899906842597L;
		for (int i = 0; i < openPath.length(); i++) {
			h = 31 * h + openPath.charAt(i);
		}
		return h;
	}

	private static ByteBuffer alloc(int size) {
		return ByteBuffer.allocate(size).order(ByteOrder.LITTLE_ENDIAN);
	}
}
