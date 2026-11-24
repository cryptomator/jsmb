package org.cryptomator.jsmb.smb2.info;

/**
 * Filesystem-level {@code FileFsInformationClass} values that {@code QUERY_INFO} can request against
 * any open on a share, per MS-FSCC 2.5.
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/ee12042a-e32b-4c18-b93c-3f7bfab76a99">MS-FSCC 2.5 File System Information Classes</a>
 */
public enum FsInfoClass {

	/** MS-FSCC 2.5.9 — VolumeCreationTime, serial number, label. */
	FILE_FS_VOLUME_INFORMATION(1, 18),

	/** MS-FSCC 2.5.8 — TotalAllocationUnits, AvailableAllocationUnits, sectors/unit, bytes/sector. 24 bytes. */
	FILE_FS_SIZE_INFORMATION(3),

	/** MS-FSCC 2.5.10 — DeviceType + Characteristics. 8 bytes. */
	FILE_FS_DEVICE_INFORMATION(4),

	/** MS-FSCC 2.5.1 — FileSystemAttributes, MaxComponentLength, FileSystemName. Variable. */
	FILE_FS_ATTRIBUTE_INFORMATION(5, 12),

	/** MS-FSCC 2.5.4 — Total / CallerAvailable / ActualAvailable allocation units + sector sizes. 32 bytes. */
	FILE_FS_FULL_SIZE_INFORMATION(7);

	private static final int ENTIRELY_FIXED = -1;

	private final int value;
	private final int fixedPartSize;

	FsInfoClass(int value) {
		this(value, ENTIRELY_FIXED);
	}

	// fixedPartSize: the size of what precedes the variable-length data, for classes that have such data
	FsInfoClass(int value, int fixedPartSize) {
		this.value = value;
		this.fixedPartSize = fixedPartSize;
	}

	public int value() {
		return value;
	}

	/**
	 * Tells how much of this class's information a client's buffer has to hold at least.
	 *
	 * @param totalSize the size of the complete information in bytes
	 * @return the size of its fixed part, which is all of it unless the class ends with variable-length data
	 */
	public int fixedPartSize(int totalSize) {
		return fixedPartSize == ENTIRELY_FIXED ? totalSize : fixedPartSize;
	}

	public static FsInfoClass fromValue(int value) {
		for (var v : values()) {
			if (v.value == value) return v;
		}
		throw new IllegalArgumentException("Unsupported FsInfoClass: " + value);
	}
}
