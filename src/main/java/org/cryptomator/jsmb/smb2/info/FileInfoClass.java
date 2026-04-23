package org.cryptomator.jsmb.smb2.info;

/**
 * File-level {@code FileInformationClass} values that {@code QUERY_INFO} can request against an
 * open file or directory, per MS-FSCC 2.4.
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/4718fc40-e539-4014-8e33-b675af74e3e1">MS-FSCC 2.4 File Information Classes</a>
 */
public enum FileInfoClass {

	/** MS-FSCC 2.4.7 — CreationTime/LastAccessTime/LastWriteTime/ChangeTime + FileAttributes. 40 bytes. */
	FILE_BASIC_INFORMATION(4),

	/** MS-FSCC 2.4.41 — AllocationSize, EndOfFile, NumberOfLinks, DeletePending, Directory. 24 bytes. */
	FILE_STANDARD_INFORMATION(5),

	/** MS-FSCC 2.4.20 — IndexNumber (filesystem inode analogue). 8 bytes. */
	FILE_INTERNAL_INFORMATION(6),

	/** MS-FSCC 2.4.15 — EaSize (extended attribute space used). 4 bytes. */
	FILE_EA_INFORMATION(7),

	/** MS-FSCC 2.4.2 — GrantedAccess mask. 4 bytes. */
	FILE_ACCESS_INFORMATION(8),

	/** MS-FSCC 2.4.26 — path of the file in UTF-16LE. Variable. */
	FILE_NAME_INFORMATION(9),

	/** MS-FSCC 2.4.38 — CurrentByteOffset. 8 bytes. */
	FILE_POSITION_INFORMATION(14),

	/** MS-FSCC 2.4.24 — Mode flags. 4 bytes. */
	FILE_MODE_INFORMATION(16),

	/** MS-FSCC 2.4.3 — AlignmentRequirement. 4 bytes. */
	FILE_ALIGNMENT_INFORMATION(17),

	/** MS-FSCC 2.4.2a — Composite: Basic + Standard + Internal + Ea + Access + Position + Mode + Alignment + Name. */
	FILE_ALL_INFORMATION(18),

	/** MS-FSCC 2.4.44 — Alternate data streams. Returning an empty buffer means "no alternate streams". */
	FILE_STREAM_INFORMATION(22),

	/** MS-FSCC 2.4.25 — CreationTime/LastAccessTime/LastWriteTime/ChangeTime + sizes + attrs, packed tight. 56 bytes. */
	FILE_NETWORK_OPEN_INFORMATION(34),

	/** MS-FSCC 2.4.6 — FileAttributes + ReparseTag. 8 bytes. */
	FILE_ATTRIBUTE_TAG_INFORMATION(35);

	private final int value;

	FileInfoClass(int value) {
		this.value = value;
	}

	public int value() {
		return value;
	}

	public static FileInfoClass fromValue(int value) {
		for (var v : values()) {
			if (v.value == value) return v;
		}
		throw new IllegalArgumentException("Unsupported FileInfoClass: " + value);
	}
}
