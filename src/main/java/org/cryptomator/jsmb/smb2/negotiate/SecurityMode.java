package org.cryptomator.jsmb.smb2.negotiate;

public interface SecurityMode {
	char SIGNING_ENABLED = 0x0001;
	char SIGNING_REQUIRED = 0x0002;
}
