package org.cryptomator.jsmb.common;

/**
 * Collection of NT status codes.
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55">MS-ERREF</a>
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb/6ab6ca20-b404-41fd-b91a-2ed39e3762ea">SMB Error Classes and Codes</a>
 */
public interface NTStatus {
	// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55
	int STATUS_SUCCESS = 0x00000000;
	int STATUS_SMB_NO_PREAUTH_INTEGRITY_HASH_OVERLAP = 0xC05D0000;
	int STATUS_REQUEST_NOT_ACCEPTED = 0xC00000D0;

	// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb/6ab6ca20-b404-41fd-b91a-2ed39e3762ea
	int STATUS_MORE_PROCESSING_REQUIRED = 0xC0000016;
	int STATUS_SMB_BAD_COMMAND = 0x00160002;
	int STATUS_INVALID_PARAMETER = 0xC000000D;
	int STATUS_ACCESS_DENIED = 0xC0000022;
	int STATUS_LOGON_FAILURE = 0xC000006D;
	int STATUS_NOT_SUPPORTED = 0xC00000BB;
	int STATUS_USER_SESSION_DELETED = 0xC0000203;
}
