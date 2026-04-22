package org.cryptomator.jsmb.smb2;

import org.cryptomator.jsmb.Config;
import org.cryptomator.jsmb.share.SmbShare;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Holds global (i.e. per server) values, as specified in the SMB2 protocol.
 * Behavioral toggles are initialized from the {@link Config} set passed to
 * {@code TcpServer.start(port, flags)}.
 */
public class Global {

	Map<Long, Session> sessionTable = new HashMap<>();
	Map<Long, Object> clientTable = new HashMap<>(); // TODO: create Client class

	/**
	 * Shares registered with the server, keyed by share name. Populated via {@code TcpServer.registerShare}.
	 * Concurrent because {@code TREE_CONNECT} handlers (one per virtual-thread connection) read it while
	 * embedders may still be registering shares on the main thread.
	 */
	public final Map<String, SmbShare> shares = new ConcurrentHashMap<>();

	public final boolean encryptData;
	public final boolean rejectUnencryptedAccess;
	public final boolean requireMessageSigning;
	public final boolean debugEncryption;

	public final boolean isMultiChannelCapable = false;

	public Global(Set<Config> flags) {
		this.encryptData = flags.contains(Config.ENCRYPT_DATA);
		this.rejectUnencryptedAccess = flags.contains(Config.REJECT_UNENCRYPTED_ACCESS);
		this.requireMessageSigning = flags.contains(Config.REQUIRE_MESSAGE_SIGNING);
		this.debugEncryption = flags.contains(Config.DEBUG_ENCRYPTION);
	}
}
