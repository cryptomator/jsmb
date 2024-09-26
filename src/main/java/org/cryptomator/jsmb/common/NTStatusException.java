package org.cryptomator.jsmb.common;

/**
 * An Exception denoting a specific NTSTATUS code.
 */
public class NTStatusException extends Exception {

	public final int status;

	public NTStatusException(int status) {
		this(status, "Status " + Integer.toHexString(status));
	}

	public NTStatusException(int status, String message) {
		this(status, message, null);
	}

	public NTStatusException(int status, String message, Throwable cause) {
		super(message, cause);
		this.status = status;
	}
}
