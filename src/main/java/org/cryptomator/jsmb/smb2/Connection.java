package org.cryptomator.jsmb.smb2;

import org.cryptomator.jsmb.smb2.negotiate.PreauthIntegrityCapabilities;

import java.util.UUID;

/**
 * Connection parameters negotiated during the SMB2.0 dialect negotiation.
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/0055d1e1-18fa-4c1c-8941-df7203d440c7">Per Transport Connection</a>
 */
public class Connection {

	public int clientCapabilities;
	public short clientSecurityMode;
	public UUID clientGuid;
	public short[] clientDialects;
	public boolean shouldSign;
	public short negotiateDialect = (short) 0xFFFF;
	public String dialect;
	public int serverCapabilities;
	public int maxWriteSize = 65536;
	public int maxReadSize = 65536;
	public int maxTransactSize = 65536;
	public short preauthIntegrityHashId = PreauthIntegrityCapabilities.HASH_ALGORITHM_SHA512;
	public byte[] preauthIntegrityHashValue = new byte[64];
	public int cipherId;
	public short[] compressionIds;
	public boolean supportsChainedCompression;
	public short[] RDMATransformIds;
	public boolean supportsMultiCredit;
	public short serverSecurityMode;
}
