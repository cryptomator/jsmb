package org.cryptomator.jsmb.smb2;

import java.util.HashMap;
import java.util.Map;

/**
 * Holds global (i.e. per server) values, as specified in the SMB2 protocol.
 */
public class Global {

	Map<Long, Session> sessionTable = new HashMap<>();
	Map<Long, Object> clientTable = new HashMap<>(); // TODO: create Client class

}
