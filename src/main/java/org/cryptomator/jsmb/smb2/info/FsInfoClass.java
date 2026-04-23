package org.cryptomator.jsmb.smb2.info;

/**
 * Filesystem-level {@code FileFsInformationClass} values that {@code QUERY_INFO} can request against
 * any open on a share, per MS-FSCC 2.5.
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/ee12042a-e32b-4c18-b93c-3f7bfab76a99">MS-FSCC 2.5 File System Information Classes</a>
 */
public enum FsInfoClass {

	/** MS-FSCC 2.5.9 — VolumeCreationTime, serial number, label. */
	FILE_FS_VOLUME_INFORMATION(1),

	/** MS-FSCC 2.5.8 — TotalAllocationUnits, AvailableAllocationUnits, sectors/unit, bytes/sector. 24 bytes. */
	FILE_FS_SIZE_INFORMATION(3),

	/** MS-FSCC 2.5.10 — DeviceType + Characteristics. 8 bytes. */
	FILE_FS_DEVICE_INFORMATION(4),

	/** MS-FSCC 2.5.1 — FileSystemAttributes, MaxComponentLength, FileSystemName. Variable. */
	FILE_FS_ATTRIBUTE_INFORMATION(5),

	/** MS-FSCC 2.5.4 — Total / CallerAvailable / ActualAvailable allocation units + sector sizes. 32 bytes. */
	FILE_FS_FULL_SIZE_INFORMATION(7);

	private final int value;

	FsInfoClass(int value) {
		this.value = value;
	}

	public int value() {
		return value;
	}

	public static FsInfoClass fromValue(int value) {
		for (var v : values()) {
			if (v.value == value) return v;
		}
		throw new IllegalArgumentException("Unsupported FsInfoClass: " + value);
	}
}
