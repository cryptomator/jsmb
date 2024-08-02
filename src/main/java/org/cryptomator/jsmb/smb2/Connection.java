package org.cryptomator.jsmb.smb2;

import org.cryptomator.jsmb.smb2.negotiate.PreauthIntegrityCapabilities;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

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
	public char negotiateDialect = (char) 0xFFFF;
	public String dialect;
	public int serverCapabilities;
	public int maxWriteSize = 1 << 20; // 1MiB
	public int maxReadSize = 1 << 20; // 1MiB
	public int maxTransactSize = 1 << 20; // 1MiB
	public char preauthIntegrityHashId = PreauthIntegrityCapabilities.HASH_ALGORITHM_SHA512;
	public byte[] preauthIntegrityHashValue = new byte[64];
	public char cipherId;
	public char signingAlgorithmId;
	public char[] compressionIds;
	public boolean supportsChainedCompression;
	public char[] RDMATransformIds;
	public boolean supportsMultiCredit;

	public char serverSecurityMode;

	public Map<Long, Session> sessionTable = HashMap.newHashMap(1);
}
