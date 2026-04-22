package org.cryptomator.jsmb.share;

/**
 * Parameters the embedder needs to satisfy an {@code SMB2 CREATE} request. The four bitfields come
 * straight from the wire format (MS-SMB2 2.2.13); {@link Disposition} is a typed projection of the
 * {@code CreateDisposition} u32.
 *
 * @param desiredAccess NT access mask (e.g. {@code FILE_READ_DATA | FILE_WRITE_DATA})
 * @param shareAccess   NT share-access bitfield ({@code FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE})
 * @param disposition   how to handle an existing / missing target
 * @param createOptions NT {@code CreateOptions} bitfield (e.g. {@code FILE_DIRECTORY_FILE}, {@code FILE_DELETE_ON_CLOSE})
 */
public record OpenParams(int desiredAccess,
						 int shareAccess,
						 Disposition disposition,
						 int createOptions) {

	/**
	 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/e8fb45c1-a03d-44ca-b7ae-47385cfd7997">MS-SMB2 2.2.13 CreateDisposition</a>
	 */
	public enum Disposition {
		/** Replace the existing file; create if absent. ({@code FILE_SUPERSEDE}, value 0) */
		SUPERSEDE,
		/** Open existing; fail if absent. ({@code FILE_OPEN}, value 1) */
		OPEN,
		/** Create new; fail if already exists. ({@code FILE_CREATE}, value 2) */
		CREATE,
		/** Open existing or create if absent. ({@code FILE_OPEN_IF}, value 3) */
		OPEN_IF,
		/** Open existing and truncate; fail if absent. ({@code FILE_OVERWRITE}, value 4) */
		OVERWRITE,
		/** Open existing (truncate) or create if absent. ({@code FILE_OVERWRITE_IF}, value 5) */
		OVERWRITE_IF;

		public static Disposition fromWireValue(int value) {
			return switch (value) {
				case 0 -> SUPERSEDE;
				case 1 -> OPEN;
				case 2 -> CREATE;
				case 3 -> OPEN_IF;
				case 4 -> OVERWRITE;
				case 5 -> OVERWRITE_IF;
				default -> throw new IllegalArgumentException("Unknown CreateDisposition: " + value);
			};
		}
	}

	/** {@code FILE_DIRECTORY_FILE} — the target must be (or is being created as) a directory. */
	public static final int OPTION_DIRECTORY_FILE = 0x00000001;
	/** {@code FILE_NON_DIRECTORY_FILE} — the target must not be a directory. */
	public static final int OPTION_NON_DIRECTORY_FILE = 0x00000040;
	/** {@code FILE_DELETE_ON_CLOSE} — unlink the target when the open is closed. */
	public static final int OPTION_DELETE_ON_CLOSE = 0x00001000;
}
