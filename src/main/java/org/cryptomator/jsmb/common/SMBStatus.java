package org.cryptomator.jsmb.common;

/**
 * Collection of NT status codes.
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55">MS-ERREF</a>
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb/6ab6ca20-b404-41fd-b91a-2ed39e3762ea">SMB Error Classes and Codes</a>
 */
public interface SMBStatus {
	int STATUS_SUCCESS = 0x00000000;
	int STATUS_MORE_PROCESSING_REQUIRED = 0xC0000016;
	int STATUS_SMB_BAD_COMMAND = 0x00160002;
	int STATUS_WRONG_PASSWORD = 0xC000006A;
}
