package org.cryptomator.jsmb.smb2.query;

import org.cryptomator.jsmb.common.NTStatus;
import org.cryptomator.jsmb.smb2.Command;
import org.cryptomator.jsmb.smb2.Connection;
import org.cryptomator.jsmb.smb2.ErrorResponse;
import org.cryptomator.jsmb.smb2.Open;
import org.cryptomator.jsmb.smb2.PacketHeader;
import org.cryptomator.jsmb.smb2.SMB2Message;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

/**
 * Handles {@code QUERY_DIRECTORY} for SMB 3.1.1.
 * <p>
 * Enumeration state (cached listing + cursor) lives on the {@link Open} — the first
 * {@code QUERY_DIRECTORY} populates it, subsequent calls resume from the cursor, and
 * {@code SL_RESTART_SCAN} / {@code SL_REOPEN} force a refetch.
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/29e99487-1fa9-4ab0-9f91-3dc1d2d2d898">3.3.5.18 Receiving an SMB2 QUERY_DIRECTORY Request</a>
 */
public record QueryDirectoryHandler(Connection connection) {

	private static final Logger LOG = LoggerFactory.getLogger(QueryDirectoryHandler.class);

	public SMB2Message query(QueryDirectoryRequest request) {
		var session = connection.sessionTable.get(request.header().sessionId());
		if (session == null) {
			return ErrorResponse.create(request, NTStatus.STATUS_USER_SESSION_DELETED);
		}
		var open = session.openTable.get(request.fileId());
		if (open == null) {
			return ErrorResponse.create(request, NTStatus.STATUS_FILE_CLOSED);
		}

		FileInformationClass cls;
		try {
			cls = FileInformationClass.fromValue(request.fileInformationClass());
		} catch (IllegalArgumentException e) {
			LOG.debug("QUERY_DIRECTORY with unsupported InfoClass 0x{}", Integer.toHexString(request.fileInformationClass()));
			return ErrorResponse.create(request, NTStatus.STATUS_INVALID_INFO_CLASS);
		}

		boolean restart = request.hasFlag(QueryDirectoryRequest.FLAG_RESTART_SCAN)
				|| request.hasFlag(QueryDirectoryRequest.FLAG_REOPEN);
		boolean firstListing = open.directoryEntries == null;

		if (firstListing || restart) {
			var pattern = request.fileName();
			try (var stream = open.backend.listChildren(pattern.isEmpty() ? null : pattern)) {
				open.directoryEntries = stream.toList();
			} catch (UnsupportedOperationException e) {
				return ErrorResponse.create(request, NTStatus.STATUS_INVALID_PARAMETER);
			} catch (IOException e) {
				LOG.warn("QUERY_DIRECTORY listing failed", e);
				return ErrorResponse.create(request, NTStatus.STATUS_UNEXPECTED_IO_ERROR);
			}
			open.nextDirectoryIndex = 0;
		}

		if (request.hasFlag(QueryDirectoryRequest.FLAG_INDEX_SPECIFIED)) {
			open.nextDirectoryIndex = request.fileIndex();
		}

		var entries = open.directoryEntries;
		if (open.nextDirectoryIndex >= entries.size()) {
			// Empty listing on the first call is STATUS_NO_SUCH_FILE; a drained cursor after earlier
			// calls is STATUS_NO_MORE_FILES. Both are common "end of enumeration" markers.
			int status = (firstListing || restart) && entries.isEmpty()
					? NTStatus.STATUS_NO_SUCH_FILE
					: NTStatus.STATUS_NO_MORE_FILES;
			return ErrorResponse.create(request, status);
		}

		var result = DirectoryInfoWriter.write(cls, entries, open.nextDirectoryIndex,
				request.outputBufferLength(),
				request.hasFlag(QueryDirectoryRequest.FLAG_RETURN_SINGLE_ENTRY));

		if (result.entriesWritten() == 0) {
			// Not even one entry fit in the client's buffer.
			return ErrorResponse.create(request, NTStatus.STATUS_INFO_LENGTH_MISMATCH);
		}

		open.nextDirectoryIndex += result.entriesWritten();
		LOG.debug("QUERY_DIRECTORY fileId={} wrote {} entr{} ({}/{} total, {} bytes)",
				open.fileId, result.entriesWritten(),
				result.entriesWritten() == 1 ? "y" : "ies",
				open.nextDirectoryIndex, entries.size(), result.buffer().length);

		var header = buildResponseHeader(request);
		return new QueryDirectoryResponse(header).withOutputBuffer(result.buffer());
	}

	private PacketHeader buildResponseHeader(QueryDirectoryRequest request) {
		var header = PacketHeader.builder();
		header.creditCharge((char) 0);
		header.command(Command.QUERY_DIRECTORY.value());
		header.creditResponse((char) 1);
		header.flags(SMB2Message.Flags.SERVER_TO_REDIR);
		header.nextCommand(0);
		header.messageId(request.header().messageId());
		header.treeId(request.header().treeId());
		header.sessionId(request.header().sessionId());
		header.status(NTStatus.STATUS_SUCCESS);
		return header.build();
	}
}
