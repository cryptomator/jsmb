package org.cryptomator.jsmb.smb2;

import org.cryptomator.jsmb.common.NTStatus;
import org.cryptomator.jsmb.share.FileId;
import org.cryptomator.jsmb.smb2.create.CreateResponse;
import org.jetbrains.annotations.Nullable;

import java.util.OptionalInt;

/**
 * Tracks the SessionId, TreeId and FileId that the operations of one compounded request pass on to a related operation following them.
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/46dd4182-62d3-4e30-9fe5-e2ec124edca1">Handling Compounded Related Requests</a>
 */
public class CompoundChain {

	// where the FileId is found in the body of the commands that carry one but aren't parsed any further
	private static final long FILE_ID_OFFSET = 8;

	// what the previous operation used or created, null if it did neither
	private @Nullable Long sessionId;
	private @Nullable Integer treeId;
	private @Nullable FileId fileId;
	// the status of the CREATE that was to supply the FileId but failed, STATUS_SUCCESS if that is not why there is none
	private int createStatus = NTStatus.STATUS_SUCCESS;
	// set once a related operation lacked a FileId to inherit, which fails all related operations following it
	private boolean invalidHandle;

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
	 * Tells whether a related operation has to be failed for want of a FileId to inherit.
	 * <p>
	 * A CREATE that failed passes its status on to the operations that would have worked on its file. Without any preceding operation
	 * to take a FileId from, the status is {@code STATUS_INVALID_HANDLE}, for the operation in need of it and all related ones after it.
	 * <p>
	 * An operation that failed on a valid FileId doesn't keep the following ones from being processed, other than the specification
	 * suggests ("SHOULD fail the current operation with the same error code"). A CLOSE at the end of a chain would otherwise leave the file open.
	 *
	 * @param request the next operation of the compounded request
	 * @return the status to fail the operation with, or empty if nothing stands in its way
	 */
	public OptionalInt fileIdRejection(SMB2Message request) {
		if (!request.header().hasFlag(SMB2Message.Flags.RELATED_OPERATIONS)) {
			return OptionalInt.empty();
		}
		if (invalidHandle) {
			return OptionalInt.of(NTStatus.STATUS_INVALID_HANDLE);
		}
		if (!(request instanceof FileIdCarrying) || fileId != null) {
			return OptionalInt.empty();
		}
		return OptionalInt.of(createStatus != NTStatus.STATUS_SUCCESS ? createStatus : NTStatus.STATUS_INVALID_HANDLE);
	}

	/**
	 * Tells which FileId a related operation is processed with, whatever its own FileId field says.
	 *
	 * @return the FileId the previous operation used or created, {@code null} if it did neither
	 */
	public @Nullable FileId fileId() {
		return fileId;
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
		boolean related = request.header().hasFlag(SMB2Message.Flags.RELATED_OPERATIONS);
		if (!related) {
			invalidHandle = false; // an unrelated operation starts over
		}
		if (command == Command.CREATE.value()) {
			fileId = response instanceof CreateResponse created ? created.fileId() : null;
			createStatus = fileId == null && response != null ? response.header().status() : NTStatus.STATUS_SUCCESS;
		} else if (Command.isAnyOf(command, Command.CLOSE, Command.FLUSH, Command.READ, Command.WRITE, Command.LOCK, Command.IOCTL, Command.QUERY_DIRECTORY, Command.CHANGE_NOTIFY, Command.QUERY_INFO, Command.SET_INFO, Command.OPLOCK_BREAK)) {
			if (!related) {
				fileId = ownFileId(request);
				createStatus = NTStatus.STATUS_SUCCESS;
			} else if (request instanceof FileIdCarrying && fileId == null && createStatus == NTStatus.STATUS_SUCCESS) {
				invalidHandle = true;
			}
			// A related operation otherwise used the FileId it inherited, or got failed with the status of the CREATE. Either way things stay as they are.
		} else {
			fileId = null; // the operation neither contains nor generates a FileId
			createStatus = NTStatus.STATUS_SUCCESS;
		}
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

	// the FileId an operation states itself, null if its body is too short to hold one
	private static @Nullable FileId ownFileId(SMB2Message request) {
		if (request instanceof FileIdCarrying carrying) {
			return request.isWellFormed() ? carrying.fileId() : null;
		}
		var body = request.segment();
		return body.byteSize() >= FILE_ID_OFFSET + FileId.SIZE ? FileId.fromSegment(body.asSlice(FILE_ID_OFFSET, FileId.SIZE)) : null;
	}
}
