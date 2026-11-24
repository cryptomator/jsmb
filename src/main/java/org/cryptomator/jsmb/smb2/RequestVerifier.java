package org.cryptomator.jsmb.smb2;

import org.cryptomator.jsmb.common.NTStatus;
import org.jetbrains.annotations.Nullable;

/**
 * Checks an incoming request against the connection's state before it is dispatched to its handler.
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/b495e2da-8711-4772-b292-453be0394b49">Verifying the Session</a>
 */
public class RequestVerifier {

	private final Connection connection;

	public RequestVerifier(Connection connection) {
		this.connection = connection;
	}

	/**
	 * Verifies that the given request may be processed.
	 *
	 * @param request the request about to be dispatched
	 * @return the error response to send instead of processing the request, or {@code null} if the request passed verification
	 */
	public @Nullable ErrorResponse verify(SMB2Message request) {
		var command = request.header().command();
		// NEGOTIATE, ECHO and CANCEL are not bound to a session; SESSION_SETUP does its own lookup, as it is what creates the session.
		if (isAnyOf(command, Command.NEGOTIATE, Command.SESSION_SETUP, Command.ECHO, Command.CANCEL)) {
			return null;
		}
		var session = connection.sessionTable.get(request.header().sessionId());
		if (session == null) {
			return ErrorResponse.create(request, NTStatus.STATUS_USER_SESSION_DELETED);
		}
		// A session is registered as soon as the first SESSION_SETUP leg arrives, so its state is the only thing telling an authenticated client from one that merely started authenticating.
		// The spec leaves the error code for InProgress implementation-specific. Session.State.EXPIRED is never assigned (no session expiry), hence no STATUS_NETWORK_SESSION_EXPIRED.
		if (session.state != Session.State.VALID && !isAnyOf(command, Command.LOGOFF, Command.CLOSE, Command.LOCK)) {
			return ErrorResponse.create(request, NTStatus.STATUS_ACCESS_DENIED);
		}
		return null;
	}

	private static boolean isAnyOf(char command, Command... candidates) {
		for (var candidate : candidates) {
			if (candidate.value() == command) {
				return true;
			}
		}
		return false;
	}
}
