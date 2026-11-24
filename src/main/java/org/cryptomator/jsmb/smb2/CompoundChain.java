package org.cryptomator.jsmb.smb2;

import org.jetbrains.annotations.Nullable;

/**
 * Tracks the SessionId and TreeId that the operations of one compounded request pass on to a related operation following them.
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/46dd4182-62d3-4e30-9fe5-e2ec124edca1">Handling Compounded Related Requests</a>
 */
public class CompoundChain {

	// what the previous operation used or created, null if it did neither
	private @Nullable Long sessionId;
	private @Nullable Integer treeId;

	/**
	 * Determines the SessionId to process an operation with.
	 *
	 * @param request the next operation of the compounded request
	 * @return its own SessionId or, for a related operation, the one of the previous operation; {@code null} if the previous operation neither used nor created one
	 */
	public @Nullable Long sessionId(SMB2Message request) {
		var header = request.header();
		return header.hasFlag(SMB2Message.Flags.RELATED_OPERATIONS) ? sessionId : (Long) header.sessionId();
	}

	/**
	 * Determines the TreeId to process an operation with.
	 *
	 * @param request the next operation of the compounded request
	 * @return its own TreeId or, for a related operation, the one of the previous operation; {@code null} if there is none
	 */
	public @Nullable Integer treeId(SMB2Message request) {
		var header = request.header();
		if (header.hasFlag(SMB2Message.Flags.ASYNC_COMMAND)) {
			return null; // an async header carries an AsyncId in place of the TreeId
		}
		return header.hasFlag(SMB2Message.Flags.RELATED_OPERATIONS) ? treeId : (Integer) header.treeId();
	}

	/**
	 * Records the outcome of an operation, so that a related operation following it inherits the right identifiers.
	 *
	 * @param request  the operation that got processed
	 * @param response its response, or {@code null} if it has none
	 */
	public void processed(SMB2Message request, @Nullable SMB2Message response) {
		var usedSessionId = sessionId(request);
		var usedTreeId = treeId(request);
		var command = request.header().command();
		boolean succeeded = response != null && !(response instanceof ErrorResponse);
		if (Command.isAnyOf(command, Command.NEGOTIATE, Command.ECHO, Command.CANCEL)) {
			sessionId = null;
		} else if (command == Command.SESSION_SETUP.value()) {
			sessionId = succeeded ? (Long) response.header().sessionId() : null;
		} else {
			sessionId = usedSessionId;
		}
		if (Command.isAnyOf(command, Command.NEGOTIATE, Command.SESSION_SETUP, Command.LOGOFF, Command.ECHO, Command.CANCEL)) {
			treeId = null;
		} else if (command == Command.TREE_CONNECT.value()) {
			treeId = succeeded ? (Integer) response.header().treeId() : null;
		} else {
			treeId = usedTreeId;
		}
	}
}
