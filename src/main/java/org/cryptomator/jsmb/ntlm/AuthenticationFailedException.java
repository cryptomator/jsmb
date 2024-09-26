package org.cryptomator.jsmb.ntlm;

import org.cryptomator.jsmb.common.NTStatusException;

public class AuthenticationFailedException extends NTStatusException {
	public AuthenticationFailedException(int status, String message) {
		super(status, message);
	}
}
