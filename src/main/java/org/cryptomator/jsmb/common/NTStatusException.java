package org.cryptomator.jsmb.common;

/**
 * An Exception denoting a specific NTSTATUS code.
 */
public class NTStatusException extends Exception {

	/** The NTSTATUS code (see MS-ERREF 2.3.1) this exception maps to on the wire. */
	public final int status;

	/**
	 * @param status NTSTATUS code
	 */
	public NTStatusException(int status) {
		this(status, "Status " + Integer.toHexString(status));
	}

	/**
	 * @param status  NTSTATUS code
	 * @param message human-readable detail
	 */
	public NTStatusException(int status, String message) {
		this(status, message, null);
	}

	/**
	 * @param status  NTSTATUS code
	 * @param message human-readable detail
	 * @param cause   underlying cause, or {@code null}
	 */
	public NTStatusException(int status, String message, Throwable cause) {
		super(message, cause);
		this.status = status;
	}
}
