package org.cryptomator.jsmb.smb2;

import org.cryptomator.jsmb.ntlmv2.NtlmSession;
import org.jetbrains.annotations.Range;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

public class Session {

	private static final AtomicLong SESSION_ID_GENERATOR = new AtomicLong(1);

	public enum State {
		IN_PROGRESS,
		EXPIRED,
		VALID
	}

	public final long sessionId;
	public final long sessionGlobalId;
	public final Connection connection;
	public NtlmSession ntlmSession;

	private Session(Connection connection, @Range(from = 1L, to = Long.MAX_VALUE) long sessionId) {
		if (sessionId < 1) {
			// make sure not to allow session IDs of 0, as this is a magic value in SMB2
			throw new IllegalArgumentException("Session ID must be positive");
		}
		this.connection = connection;
		this.sessionId = sessionId;
		this.sessionGlobalId = sessionId;
		this.ntlmSession = NtlmSession.create();
	}

	public State state;
	public Object securityContext = null; // TODO adjust type
	public byte[] sessionKey = null;
	public boolean signingRequired = false;
	public Map<?, ?> openTable = new HashMap<>();
	public Map<?, ?> treeConnectTable = new HashMap<>();
	public boolean isAnonymous = false;
	public Instant creationTime = Instant.now();
	public Instant idleTime = Instant.now();
	public boolean encryptData = true;
	public List<?> channelList = new ArrayList<>();
	public byte[] preauthIntegrityHashValue;
	public byte[] fullSessionKey = null;

	/**
	 * Creates a new session and registers it with the given connection.
	 * @param connection The connection on which the session is created.
	 * @return The session.
	 */
	public static Session create(Connection connection) {
		var session = new Session(connection, SESSION_ID_GENERATOR.incrementAndGet());
		connection.global.sessionTable.put(session.sessionGlobalId, session);
		connection.sessionTable.put(session.sessionId, session);
		return session;
	}

}
