package org.cryptomator.jsmb.smb2.query;

/**
 * The subset of {@code FileInformationClass} values that can appear in a {@code QUERY_DIRECTORY}
 * request, per MS-SMB2 2.2.33 and MS-FSCC 2.4. We implement the three Windows-standard ones plus
 * {@link #FILE_NAMES_INFORMATION} because it's cheap and shows up in lightweight enumerations.
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/4718fc40-e539-4014-8e33-b675af74e3e1">MS-FSCC 2.4 File Information Classes</a>
 */
public enum FileInformationClass {

	/** MS-FSCC 2.4.12 — name, timestamps, sizes, attributes. 64-byte fixed header + name. */
	FILE_DIRECTORY_INFORMATION(1),

	/** MS-FSCC 2.4.14 — like {@link #FILE_DIRECTORY_INFORMATION} plus EaSize. 68-byte fixed header. */
	FILE_FULL_DIRECTORY_INFORMATION(2),

	/** MS-FSCC 2.4.8 — adds EaSize, ShortName. 94-byte fixed header. Default for Samba's {@code smbclient}. */
	FILE_BOTH_DIRECTORY_INFORMATION(3),

	/** MS-FSCC 2.4.26 — just name + index. 12-byte fixed header. Minimal, fastest. */
	FILE_NAMES_INFORMATION(12),

	/** MS-FSCC 2.4.20 — FullDirectoryInformation + FileId. 80-byte fixed header. */
	FILE_ID_FULL_DIRECTORY_INFORMATION(38),

	/** MS-FSCC 2.4.18 — BothDirectoryInformation + FileId. 104-byte fixed header. Default for {@code smbj}. */
	FILE_ID_BOTH_DIRECTORY_INFORMATION(37);

	private final int value;

	FileInformationClass(int value) {
		this.value = value;
	}

	public int value() {
		return value;
	}

	/**
	 * Looks up the enum constant by its numeric wire value.
	 *
	 * @throws IllegalArgumentException for unknown / unsupported classes
	 */
	public static FileInformationClass fromValue(int value) {
		for (var v : values()) {
			if (v.value == value) return v;
		}
		throw new IllegalArgumentException("Unknown / unsupported FileInformationClass: " + value);
	}
}
