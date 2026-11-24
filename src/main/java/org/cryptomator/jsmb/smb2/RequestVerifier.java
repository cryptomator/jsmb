package org.cryptomator.jsmb.smb2;

import org.cryptomator.jsmb.common.NTStatus;
import org.cryptomator.jsmb.smb2.crypto.MessageSigner;
import org.jetbrains.annotations.Nullable;

/**
 * Checks an incoming request against the connection's state before it is dispatched to its handler.
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/85df1680-2ee7-4d25-a916-a982371ddc75">Verifying the Signature</a>
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/b495e2da-8711-4772-b292-453be0394b49">Verifying the Session</a>
 */
public class RequestVerifier {

	private final Connection connection;
	private final MessageSigner signer = new MessageSigner();

	public RequestVerifier(Connection connection) {
		this.connection = connection;
	}

	/**
	 * Verifies that the given request may be processed.
	 *
	 * @param request            the request about to be dispatched
	 * @param transformSessionId the SessionId of the SMB2 TRANSFORM_HEADER the request arrived in, or {@code null} if it arrived unencrypted
	 * @return the error response to send instead of processing the request, or {@code null} if the request passed verification
	 */
	public @Nullable ErrorResponse verify(SMB2Message request, @Nullable Long transformSessionId) {
		var command = request.header().command();
		var sessionId = request.header().sessionId();
		var session = connection.sessionTable.get(sessionId);
		// A transform is decrypted with the keys of the session named in its header, so it only vouches for requests of that very session.
		var encrypted = transformSessionId != null && transformSessionId == sessionId;

		// Verifying the Signature
		var signed = request.header().hasFlag(SMB2Message.Flags.SIGNED);
		if (signed && command == Command.NEGOTIATE.value()) {
			return ErrorResponse.create(request, NTStatus.STATUS_INVALID_PARAMETER);
		}
		if (signed && !encrypted) {
			if (session == null) {
				return ErrorResponse.create(request, NTStatus.STATUS_USER_SESSION_DELETED);
			}
			// Channel.SigningKey equals Session.SigningKey, as session binding is not supported
			if (session.signingKey == null) {
				return ErrorResponse.create(request, NTStatus.STATUS_NOT_SUPPORTED);
			}
			if (!signer.verify(request, session.signingKey, connection)) {
				return ErrorResponse.create(request, NTStatus.STATUS_ACCESS_DENIED);
			}
		} else if (!signed && !encrypted && session != null && session.signingRequired) {
			// Deviating from the spec's wording, requests that arrived encrypted are exempt: they aren't signed, as the AEAD cipher already authenticates them.
			return ErrorResponse.create(request, NTStatus.STATUS_ACCESS_DENIED);
		}

		// Verifying the Session
		// NEGOTIATE, ECHO and CANCEL are not bound to a session; SESSION_SETUP does its own lookup, as it is what creates the session.
		if (isAnyOf(command, Command.NEGOTIATE, Command.SESSION_SETUP, Command.ECHO, Command.CANCEL)) {
			return null;
		}
		if (session == null) {
			return ErrorResponse.create(request, NTStatus.STATUS_USER_SESSION_DELETED);
		}
		// A session is registered as soon as the first SESSION_SETUP leg arrives, so its state is the only thing telling an authenticated client from one that merely started authenticating.
		// The spec leaves the error code for InProgress implementation-specific. Session.State.EXPIRED is never assigned (no session expiry), hence no STATUS_NETWORK_SESSION_EXPIRED.
		if (session.state != Session.State.VALID && !isAnyOf(command, Command.LOGOFF, Command.CLOSE, Command.LOCK)) {
			return ErrorResponse.create(request, NTStatus.STATUS_ACCESS_DENIED);
		}
		// Not covered by the spec: a request wrapped in the transform of a different session. Its own session's keys never authenticated it.
		if (transformSessionId != null && !encrypted) {
			return ErrorResponse.create(request, NTStatus.STATUS_ACCESS_DENIED);
		}
		if (session.encryptData && !encrypted) {
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
