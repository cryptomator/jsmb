package org.cryptomator.jsmb.share;

/**
 * Volume size information. Maps to
 * <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/e13e068c-e3a7-4dd5-82c3-4a7b7ed5e6d6">MS-FSCC 2.5.8 FileFsSizeInformation</a>.
 *
 * @param totalAllocationUnits     total units on the volume
 * @param availableAllocationUnits units available to the caller
 * @param sectorsPerAllocationUnit sectors in a single allocation unit
 * @param bytesPerSector           bytes in a single sector (typically 512 or 4096)
 */
public record FsSize(long totalAllocationUnits,
					 long availableAllocationUnits,
					 int sectorsPerAllocationUnit,
					 int bytesPerSector) {}
