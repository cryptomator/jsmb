package org.cryptomator.jsmb.common;

/**
 * Thrown when a client violates the protocol in a way that requires dropping the connection without sending a response.
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/4daf7dce-9f49-4413-99bf-323801c9283d">Verifying the Connection State</a>
 */
public class DisconnectException extends RuntimeException {

	/**
	 * @param message why the connection gets dropped
	 */
	public DisconnectException(String message) {
		super(message);
	}
}
