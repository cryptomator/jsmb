package org.cryptomator.jsmb.share;

import java.time.Instant;

/**
 * Timestamps and NTFS attribute bits for a file or directory. Maps to
 * <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/16023025-8a78-492f-8b96-c873b042ac50">MS-FSCC 2.4.7 FileBasicInformation</a>.
 *
 * @param creationTime   when the object was created
 * @param lastAccessTime last read or metadata access
 * @param lastWriteTime  last content write
 * @param changeTime     last metadata change (rename, attr change, etc.)
 * @param fileAttributes NT file attribute bitfield (DIRECTORY, READONLY, HIDDEN, ...)
 */
public record FileBasicInfo(Instant creationTime,
							Instant lastAccessTime,
							Instant lastWriteTime,
							Instant changeTime,
							int fileAttributes) {

	/** {@code FILE_ATTRIBUTE_READONLY} */
	public static final int ATTR_READONLY = 0x0001;
	/** {@code FILE_ATTRIBUTE_HIDDEN} */
	public static final int ATTR_HIDDEN = 0x0002;
	/** {@code FILE_ATTRIBUTE_SYSTEM} */
	public static final int ATTR_SYSTEM = 0x0004;
	/** {@code FILE_ATTRIBUTE_DIRECTORY} */
	public static final int ATTR_DIRECTORY = 0x0010;
	/** {@code FILE_ATTRIBUTE_ARCHIVE} */
	public static final int ATTR_ARCHIVE = 0x0020;
	/** {@code FILE_ATTRIBUTE_NORMAL} (must be used alone) */
	public static final int ATTR_NORMAL = 0x0080;
}
