package org.cryptomator.jsmb.smb2;

import java.util.HashMap;
import java.util.Map;

/**
 * Holds global (i.e. per server) values, as specified in the SMB2 protocol.
 */
public class Global {

	Map<Long, Session> sessionTable = new HashMap<>();
	Map<Long, Object> clientTable = new HashMap<>(); // TODO: create Client class

	public final boolean encryptData = true;
	public final boolean rejectUnencryptedAccess = true;
	public final boolean requireMessageSigning = true;

	public final boolean isMultiChannelCapable = false;

	public final boolean isEncryptionSupported = false; //TODO
	public final boolean isSigningCapabilitiesSupported = true; //TODO
}
