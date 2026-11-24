package org.cryptomator.jsmb.smb2;

import org.cryptomator.jsmb.common.NTStatus;
import org.cryptomator.jsmb.smb2.crypto.MessageSigner;
import org.cryptomator.jsmb.smb2.io.ReadRequest;
import org.cryptomator.jsmb.smb2.io.WriteRequest;
import org.cryptomator.jsmb.smb2.ioctl.IoctlRequest;
import org.cryptomator.jsmb.smb2.query.QueryDirectoryRequest;
import org.jetbrains.annotations.Nullable;

import java.util.OptionalInt;

/**
 * Checks an incoming request against the connection's state before it is dispatched to its handler.
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/85df1680-2ee7-4d25-a916-a982371ddc75">Verifying the Signature</a>
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/853e5234-d5d6-4a18-a2f5-1c792e562947">Handling Incorrectly Formatted Requests</a>
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/fba3123b-f566-4d8f-9715-0f529e856d25">Verifying the Credit Charge and the Payload Size</a>
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/b495e2da-8711-4772-b292-453be0394b49">Verifying the Session</a>
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/9a639360-87be-4d49-a1dd-4c6be0c020bd">Verifying the Tree Connect</a>
 */
public class RequestVerifier {

	// the payload size that one credit pays for
	private static final int CREDIT_PAYLOAD_SIZE = 65536;

	private final Connection connection;
	private final MessageSigner signer = new MessageSigner();

	public RequestVerifier(Connection connection) {
		this.connection = connection;
	}

	/**
	 * Verifies that the given request may be processed.
	 * <p>
	 * SessionId and TreeId are passed separately, as a compounded related request is processed with those of the operation before it (see {@link CompoundChain}) while its signature covers the header as sent.
	 *
	 * @param request            the request about to be dispatched, as received
	 * @param sessionId          the SessionId to process the request with, or {@code null} if there is none
	 * @param treeId             the TreeId to process the request with, or {@code null} if there is none
	 * @param transformSessionId the SessionId of the SMB2 TRANSFORM_HEADER the request arrived in, or {@code null} if it arrived unencrypted
	 * @return the status to fail the request with instead of processing it, or empty if the request passed verification
	 */
	public OptionalInt verify(SMB2Message request, @Nullable Long sessionId, @Nullable Integer treeId, @Nullable Long transformSessionId) {
		var command = request.header().command();
		var session = sessionId == null ? null : connection.sessionTable.get(sessionId);
		// A transform is decrypted with the keys of the session named in its header, so it only vouches for requests of that very session.
		var encrypted = transformSessionId != null && transformSessionId.equals(sessionId);

		// Verifying the Signature
		var signed = request.header().hasFlag(SMB2Message.Flags.SIGNED);
		if (signed && command == Command.NEGOTIATE.value()) {
			return OptionalInt.of(NTStatus.STATUS_INVALID_PARAMETER);
		}
		if (signed && !encrypted) {
			if (session == null) {
				return OptionalInt.of(NTStatus.STATUS_USER_SESSION_DELETED);
			}
			// Channel.SigningKey equals Session.SigningKey, as session binding is not supported
			if (session.signingKey == null) {
				return OptionalInt.of(NTStatus.STATUS_NOT_SUPPORTED);
			}
			if (!signer.verify(request, session.signingKey, connection)) {
				return OptionalInt.of(NTStatus.STATUS_ACCESS_DENIED);
			}
		} else if (!signed && !encrypted && session != null && session.signingRequired) {
			// Deviating from the spec's wording, requests that arrived encrypted are exempt: they aren't signed, as the AEAD cipher already authenticates them.
			return OptionalInt.of(NTStatus.STATUS_ACCESS_DENIED);
		}

		// Handling Incorrectly Formatted Requests. Has to precede everything that reads the request's body.
		if (!request.isWellFormed()) {
			return OptionalInt.of(NTStatus.STATUS_INVALID_PARAMETER);
		}

		// Verifying the Credit Charge and the Payload Size
		if (connection.supportsMultiCredit) {
			long payloadSize = payloadSize(request);
			int creditCharge = request.header().creditCharge();
			boolean sufficient = creditCharge == 0 ? payloadSize <= CREDIT_PAYLOAD_SIZE : (payloadSize - 1) / CREDIT_PAYLOAD_SIZE + 1 <= creditCharge;
			if (!sufficient) {
				return OptionalInt.of(NTStatus.STATUS_INVALID_PARAMETER);
			}
		}

		// Verifying the Session
		// NEGOTIATE, ECHO and CANCEL are not bound to a session; SESSION_SETUP does its own lookup, as it is what creates the session.
		if (Command.isAnyOf(command, Command.NEGOTIATE, Command.SESSION_SETUP, Command.ECHO, Command.CANCEL)) {
			return OptionalInt.empty();
		}
		if (sessionId == null) {
			// a related operation following one that neither used nor created a session
			return OptionalInt.of(NTStatus.STATUS_INVALID_PARAMETER);
		}
		if (session == null) {
			return OptionalInt.of(NTStatus.STATUS_USER_SESSION_DELETED);
		}
		// A session is registered as soon as the first SESSION_SETUP leg arrives, so its state is the only thing telling an authenticated client from one that merely started authenticating.
		// The spec leaves the error code for InProgress implementation-specific. Session.State.EXPIRED is never assigned (no session expiry), hence no STATUS_NETWORK_SESSION_EXPIRED.
		if (session.state != Session.State.VALID && !Command.isAnyOf(command, Command.LOGOFF, Command.CLOSE, Command.LOCK)) {
			return OptionalInt.of(NTStatus.STATUS_ACCESS_DENIED);
		}
		// Not covered by the spec: a request wrapped in the transform of a different session. Its own session's keys never authenticated it.
		if (transformSessionId != null && !encrypted) {
			return OptionalInt.of(NTStatus.STATUS_ACCESS_DENIED);
		}
		if (session.encryptData && !encrypted) {
			return OptionalInt.of(NTStatus.STATUS_ACCESS_DENIED);
		}

		// Verifying the Tree Connect
		if (Command.isAnyOf(command, Command.LOGOFF, Command.TREE_CONNECT)) {
			return OptionalInt.empty();
		}
		if (treeId == null) {
			// a related operation following one that neither used nor created a tree connect, or a request with an async header, which has no TreeId
			return OptionalInt.of(NTStatus.STATUS_INVALID_PARAMETER);
		}
		if (!session.treeConnectTable.containsKey(treeId)) {
			return OptionalInt.of(NTStatus.STATUS_NETWORK_NAME_DELETED);
		}
		// The section's STATUS_ACCESS_DENIED cases can't occur: shares have no EncryptData setting of their own, and a session on a connection without cipher is refused if RejectUnencryptedAccess is set.
		return OptionalInt.empty();
	}

	// The larger of a request's payload and the maximum size of its response, which is what its CreditCharge has to cover.
	// Only these four commands are charged by size. Clients send any other command with a CreditCharge of 1, however large it is.
	// See https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/0edce9a0-766e-41aa-a3b7-2044defbbb8f
	private static long payloadSize(SMB2Message request) {
		return switch (request) {
			case ReadRequest read -> Integer.toUnsignedLong(read.length());
			case WriteRequest write -> Integer.toUnsignedLong(write.length());
			case QueryDirectoryRequest queryDirectory -> Integer.toUnsignedLong(queryDirectory.outputBufferLength());
			case IoctlRequest ioctl -> Math.max(Integer.toUnsignedLong(ioctl.inputCount()), Integer.toUnsignedLong(ioctl.maxOutputResponse()));
			default -> 0L;
		};
	}
}
