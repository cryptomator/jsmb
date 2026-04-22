package org.cryptomator.jsmb.share;

/**
 * Volume-level attributes for a share. Maps to
 * <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/ebc7e6e5-4650-4e54-b17c-cf60f6fbeeaa">MS-FSCC 2.5.1 FileFsAttributeInformation</a>.
 *
 * @param fileSystemAttributes NT filesystem attribute bits (e.g. {@code FILE_CASE_SENSITIVE_SEARCH}, {@code FILE_UNICODE_ON_DISK})
 * @param maxComponentLength   maximum length of a single path component (typically 255)
 * @param fileSystemName       name of the filesystem (e.g. {@code "NTFS"})
 */
public record FsAttributes(int fileSystemAttributes, int maxComponentLength, String fileSystemName) {

	/** {@code FILE_CASE_SENSITIVE_SEARCH} */
	public static final int FS_ATTR_CASE_SENSITIVE_SEARCH = 0x00000001;
	/** {@code FILE_CASE_PRESERVED_NAMES} */
	public static final int FS_ATTR_CASE_PRESERVED_NAMES = 0x00000002;
	/** {@code FILE_UNICODE_ON_DISK} */
	public static final int FS_ATTR_UNICODE_ON_DISK = 0x00000004;
}
