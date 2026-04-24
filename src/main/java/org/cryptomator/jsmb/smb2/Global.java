package org.cryptomator.jsmb.smb2;

import org.cryptomator.jsmb.Config;
import org.cryptomator.jsmb.Credentials;
import org.cryptomator.jsmb.share.SmbShare;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentSkipListMap;

/**
 * Holds global (i.e. per server) values, as specified in the SMB2 protocol.
 * Behavioral toggles are initialized from the {@link Config} set passed to
 * {@code TcpServer.start(port, flags, credentials)}.
 */
public class Global {

	Map<Long, Session> sessionTable = new HashMap<>();
	Map<Long, Object> clientTable = new HashMap<>(); // TODO: create Client class

	/**
	 * Shares registered with the server, keyed by share name. Populated via {@code TcpServer.registerShare}.
	 * The lookup is <strong>case-insensitive</strong> — SMB share names are case-insensitive per
	 * convention, and real clients happily send {@code \\host\DATA} even when you registered
	 * {@code "data"}. Concurrent because {@code TREE_CONNECT} handlers (one per virtual-thread
	 * connection) read the map while embedders may still be registering shares on the main thread.
	 */
	public final Map<String, SmbShare> shares = new ConcurrentSkipListMap<>(String.CASE_INSENSITIVE_ORDER);

	/**
	 * The single identity this server accepts for NTLMv2 session setup. Set once at construction via
	 * {@link org.cryptomator.jsmb.TcpServer#start(int, Set, Credentials)}.
	 */
	public final Credentials credentials;

	public final boolean encryptData;
	public final boolean rejectUnencryptedAccess;
	public final boolean requireMessageSigning;
	public final boolean debugEncryption;

	public final boolean isMultiChannelCapable = false;

	// MS-SMB2 3.3.1.1 "IsXxxSupported" flags. Drive which SMB 3.1.1 negotiate contexts the server
	// processes. If a flag is FALSE, §3.3.5.4 says the server MUST ignore the corresponding request
	// context — and therefore MUST NOT emit a response context. Flipping one of these to TRUE is the
	// single thing needed to enable that feature (plus the backing implementation, of course).
	public final boolean isEncryptionSupported = true;
	public final boolean isSigningCapabilitiesSupported = true;
	public final boolean isCompressionSupported = false;
	public final boolean isRDMATransformSupported = false;
	public final boolean isTransportCapabilitiesSupported = false;

	public Global(Set<Config> flags, Credentials credentials) {
		this.credentials = credentials;
		this.encryptData = flags.contains(Config.ENCRYPT_DATA);
		this.rejectUnencryptedAccess = flags.contains(Config.REJECT_UNENCRYPTED_ACCESS);
		this.requireMessageSigning = flags.contains(Config.REQUIRE_MESSAGE_SIGNING);
		this.debugEncryption = flags.contains(Config.DEBUG_ENCRYPTION);
	}
}
