package org.cryptomator.jsmb.smb2;

import org.cryptomator.jsmb.smb2.negotiate.PreauthIntegrityCapabilities;
import org.cryptomator.jsmb.smb2.negotiate.SigningCapabilities;
import org.jetbrains.annotations.Nullable;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Connection parameters negotiated during the SMB2.0 dialect negotiation.
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/0055d1e1-18fa-4c1c-8941-df7203d440c7">Per Transport Connection</a>
 */
public class Connection {

	public final Global global;

	public Connection(Global global) {
		this.global = global;
	}

	public int clientCapabilities;
	public char clientSecurityMode;
	public UUID clientGuid;
	public char[] clientDialects;
	public boolean shouldSign;
	public char negotiateDialect = Dialects.NONE;
	public String dialect;
	public int serverCapabilities;
	public int maxWriteSize = 1 << 20; // 1MiB
	public int maxReadSize = 1 << 20; // 1MiB
	public int maxTransactSize = 1 << 20; // 1MiB
	public char preauthIntegrityHashId = PreauthIntegrityCapabilities.HASH_ALGORITHM_SHA512;
	public byte[] preauthIntegrityHashValue = new byte[64];
	public char cipherId;
	@Nullable
	public SigningCapabilities.Algorithm signingAlgorithmId;
	public char[] compressionIds = new char[0];
	public boolean supportsChainedCompression = false;
	public char[] RDMATransformIds = new char[0];
	public boolean supportsMultiCredit = false;
	public final CommandSequenceWindow commandSequenceWindow = new CommandSequenceWindow();
	public boolean acceptTransportSecurity = false;

	public char serverSecurityMode;

	// Concurrent, as a session may get removed by another connection's thread: the one that sets up the session replacing it (PreviousSessionId).
	public Map<Long, Session> sessionTable = new ConcurrentHashMap<>(1);
}
