package org.cryptomator.jsmb.smb2;

import org.cryptomator.jsmb.ntlmv2.NtlmSession;
import org.cryptomator.jsmb.share.FileId;
import org.cryptomator.jsmb.srvs.SrvsGlobal;
import org.cryptomator.jsmb.srvs.SrvsSession;
import org.jetbrains.annotations.Range;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * An SMB2 session.
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/fbcbc952-8c1f-4528-a0ab-7aed7d52264e">Per Session</a>
 */
public class Session {

	private static final AtomicLong SESSION_ID_GENERATOR = new AtomicLong(1);

	public enum State {
		IN_PROGRESS,
		EXPIRED,
		VALID
	}

	public final long sessionId;
	public final Connection connection;
	public NtlmSession ntlmSession;

	private Session(Connection connection, @Range(from = 1L, to = Long.MAX_VALUE) long sessionId) {
		if (sessionId < 1) {
			// make sure not to allow session IDs of 0, as this is a magic value in SMB2
			throw new IllegalArgumentException("Session ID must be positive");
		}
		this.connection = connection;
		this.sessionId = sessionId;
		this.ntlmSession = NtlmSession.create();
	}

	public int sessionGlobalId;
	public State state;
	public Object securityContext = null; // TODO adjust type
	public byte[] sessionKey = null;
	public boolean signingRequired = false;
	public Map<FileId, Open> openTable = new HashMap<>();
	public Map<Integer, TreeConnect> treeConnectTable = new HashMap<>();
	/** Generator for per-session {@code TreeId}s. MS-SMB2 requires uniqueness within a session; 0 and 0xFFFFFFFF are reserved. */
	public final AtomicInteger nextTreeId = new AtomicInteger(1);
	public boolean isAnonymous = false;
	public Instant creationTime = Instant.now();
	public Instant idleTime = Instant.now();
	public boolean encryptData = false;
	public List<?> channelList = new ArrayList<>();
	public byte[] preauthIntegrityHashValue;
	public byte[] fullSessionKey = null;
	public byte[] signingKey = null;
	public byte[] applicationKey = null;
	public byte[] encryptionKey = null;
	public byte[] decryptionKey = null;

	/**
	 * Creates a new session and registers it with the given connection.
	 * @param connection The connection on which the session is created.
	 * @return The session.
	 */
	public static Session create(Connection connection) {
		var session = new Session(connection, SESSION_ID_GENERATOR.incrementAndGet());
		connection.global.sessionTable.put(session.sessionId, session);
		connection.sessionTable.put(session.sessionId, session);
		session.sessionGlobalId = register();
		return session;
	}

	/**
	 * @return the globalSessionId
	 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-srvs/cb311421-de4d-4cd7-bb05-ce52e03814e4">Server Registers a New Session</a>
	 */
	private static int register() {
		var globalSessionId = SrvsSession.SRVS_SESSION_ID_GENERATOR.getAndIncrement();
		SrvsGlobal.INSTANCE.sessionList.put(globalSessionId, new SrvsSession(globalSessionId));
		return globalSessionId;
	}
}
