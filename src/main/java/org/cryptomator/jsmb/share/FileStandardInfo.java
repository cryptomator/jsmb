package org.cryptomator.jsmb.share;

/**
 * Size, link count, deletion, and directory status. Maps to
 * <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/5afa7f66-619c-48f3-955f-68c4ece704ae">MS-FSCC 2.4.41 FileStandardInformation</a>.
 *
 * @param allocationSize bytes reserved on disk (a multiple of the allocation unit)
 * @param endOfFile      logical end-of-file (size visible to readers)
 * @param numberOfLinks  hard-link count (1 for typical files; 1 for directories)
 * @param deletePending  true if the open is marked for deletion on close
 * @param directory      true for a directory, false for a regular file
 */
public record FileStandardInfo(long allocationSize,
							   long endOfFile,
							   int numberOfLinks,
							   boolean deletePending,
							   boolean directory) {}
