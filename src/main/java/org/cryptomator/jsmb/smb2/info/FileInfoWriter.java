package org.cryptomator.jsmb.smb2.info;

import org.cryptomator.jsmb.share.FileBasicInfo;
import org.cryptomator.jsmb.share.FileStandardInfo;
import org.cryptomator.jsmb.util.InodeHash;
import org.cryptomator.jsmb.util.WinFileTime;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

/**
 * Serializes the MS-FSCC 2.4 file-level info classes that {@code QUERY_INFO} can return against an
 * open file or directory.
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/4718fc40-e539-4014-8e33-b675af74e3e1">MS-FSCC 2.4 File Information Classes</a>
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

	/**
	 * 40 bytes.
	 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/16023025-8a78-492f-8b96-c873b042ac50">MS-FSCC 2.4.7 FileBasicInformation</a>
	 */
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

	/**
	 * 24 bytes.
	 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/5afa7f66-619c-48f3-955f-68c4ece704ae">MS-FSCC 2.4.41 FileStandardInformation</a>
	 */
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

	/**
	 * 8 bytes. Synthetic IndexNumber hashed from the path.
	 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/7d796611-2fa5-41ac-8178-b6fea3a017b3">MS-FSCC 2.4.20 FileInternalInformation</a>
	 */
	static byte[] internalInfo(String openPath) {
		var buf = alloc(8);
		buf.putLong(InodeHash.of(openPath));
		return buf.array();
	}

	/**
	 * 4 bytes, always zero (no extended attributes).
	 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/db6cf109-ead8-441a-b29e-cb2032778b0f">MS-FSCC 2.4.15 FileEaInformation</a>
	 */
	static byte[] eaInfo() {
		return new byte[4];
	}

	/**
	 * 4 bytes. Reports {@code FILE_ALL_ACCESS} until actual access control lands.
	 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/01cf43d2-deb3-40d3-a39b-9e68693d7c90">MS-FSCC 2.4.2 FileAccessInformation</a>
	 */
	static byte[] accessInfo() {
		var buf = alloc(4);
		buf.putInt(0x001F01FF);                // FILE_ALL_ACCESS
		return buf.array();
	}

	/**
	 * 8 bytes. Always zero (we don't track cursor position).
	 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/e3ce4a39-327e-495c-99b6-6b61606b6f16">MS-FSCC 2.4.38 FilePositionInformation</a>
	 */
	static byte[] positionInfo() {
		return new byte[8];
	}

	/**
	 * 4 bytes. Always zero (no synchronous-io / write-through modes).
	 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/52df7798-8330-474b-ac31-9afe8075640c">MS-FSCC 2.4.24 FileModeInformation</a>
	 */
	static byte[] modeInfo() {
		return new byte[4];
	}

	/**
	 * 4 bytes. Always zero (byte-aligned, no DMA).
	 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/9b0b9971-85aa-4651-8438-f1c4298bcb0d">MS-FSCC 2.4.3 FileAlignmentInformation</a>
	 */
	static byte[] alignmentInfo() {
		return new byte[4];
	}

	/**
	 * {@code FileNameLength(4) + FileName(UTF-16LE)}. Name is absolute from the share root, backslash-
	 * delimited, leading backslash: {@code "\\"} for root, {@code "\\file.txt"} for a file.
	 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/cb30e415-54c5-4483-a346-822ea90e1e89">MS-FSCC 2.4.26 FileNameInformation</a>
	 */
	static byte[] nameInfo(String openPath) {
		byte[] nameBytes = displayName(openPath).getBytes(StandardCharsets.UTF_16LE);
		var buf = alloc(4 + nameBytes.length);
		buf.putInt(nameBytes.length);
		buf.put(nameBytes);
		return buf.array();
	}

	/**
	 * Composite: Basic(40) + Standard(24) + Internal(8) + Ea(4) + Access(4) + Position(8) + Mode(4) +
	 * Alignment(4) + Name(variable). The fixed prefix is 96 bytes.
	 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/95f3056a-ebc1-4f5d-b938-3f68a44677a6">MS-FSCC 2.4.2a FileAllInformation</a>
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
		buf.putLong(InodeHash.of(openPath));
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

	/**
	 * Empty buffer = "no alternate streams" (NTFS concept, not applicable here).
	 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/f8762be6-3ab9-411e-a7d6-5cc68f70c78d">MS-FSCC 2.4.44 FileStreamInformation</a>
	 */
	static byte[] streamInfo() {
		return new byte[0];
	}

	/**
	 * 56 bytes. Timestamps + sizes + attrs, packed tight.
	 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/26d261db-58d1-4513-a548-074448cbb146">MS-FSCC 2.4.25 FileNetworkOpenInformation</a>
	 */
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

	/**
	 * 8 bytes. ReparseTag=0 (no reparse points).
	 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/d295752f-ce89-4b98-8553-266d37c84f0e">MS-FSCC 2.4.6 FileAttributeTagInformation</a>
	 */
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

	private static ByteBuffer alloc(int size) {
		return ByteBuffer.allocate(size).order(ByteOrder.LITTLE_ENDIAN);
	}
}
