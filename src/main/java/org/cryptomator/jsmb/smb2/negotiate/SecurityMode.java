package org.cryptomator.jsmb.smb2.negotiate;

public interface SecurityMode {
	short SIGNING_ENABLED = 0x0001;
	short SIGNING_REQUIRED = 0x0002;
}
