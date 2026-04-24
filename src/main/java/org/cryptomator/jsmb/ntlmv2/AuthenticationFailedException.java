package org.cryptomator.jsmb.ntlmv2;

import org.cryptomator.jsmb.common.NTStatusException;

/**
 * Raised when NTLMv2 authentication rejects the client — e.g. bad credentials or a malformed message.
 */
public class AuthenticationFailedException extends NTStatusException {
	/**
	 * Constructs a new instance carrying the given NTSTATUS code and detail message.
	 *
	 * @param status  the NTSTATUS code to propagate (typically a {@code STATUS_LOGON_*} value)
	 * @param message human-readable detail
	 */
	public AuthenticationFailedException(int status, String message) {
		super(status, message);
	}
}
