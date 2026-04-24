package org.cryptomator.jsmb.smb2.io;

import org.cryptomator.jsmb.common.NTStatus;
import org.cryptomator.jsmb.share.SmbFile;
import org.cryptomator.jsmb.smb2.Command;
import org.cryptomator.jsmb.smb2.Connection;
import org.cryptomator.jsmb.smb2.ErrorResponse;
import org.cryptomator.jsmb.smb2.PacketHeader;
import org.cryptomator.jsmb.smb2.SMB2Message;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * Handles {@code WRITE} for SMB 3.1.1. Dispatches to {@link org.cryptomator.jsmb.share.SmbOpen#write} and
 * caps the accepted length at {@link Connection#maxWriteSize}.
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/829f93f5-ed10-4f12-8347-42d235019459">3.3.5.13 Receiving an SMB2 WRITE Request</a>
 */
public record WriteHandler(Connection connection) {

	private static final Logger LOG = LoggerFactory.getLogger(WriteHandler.class);

	public SMB2Message write(WriteRequest request) {
		var session = connection.sessionTable.get(request.header().sessionId());
		if (session == null) {
			return ErrorResponse.create(request, NTStatus.STATUS_USER_SESSION_DELETED);
		}
		var open = session.openTable.get(request.fileId());
		if (open == null) {
			return ErrorResponse.create(request, NTStatus.STATUS_FILE_CLOSED);
		}
		if (!(open.backend instanceof SmbFile file)) {
			// WRITE on a directory handle — spec (MS-SMB2 3.3.5.13) has the server reject this.
			return ErrorResponse.create(request, NTStatus.STATUS_INVALID_DEVICE_REQUEST);
		}

		int length = request.length();
		if (length < 0 || length > connection.maxWriteSize) {
			// Client exceeded the MaxWriteSize we negotiated — spec says STATUS_INVALID_PARAMETER (MS-SMB2 3.3.5.13).
			return ErrorResponse.create(request, NTStatus.STATUS_INVALID_PARAMETER);
		}

		ByteBuffer src = request.data().asByteBuffer();
		int bytesWritten;
		try {
			bytesWritten = file.write(src, request.offset());
		} catch (IOException e) {
			LOG.warn("WRITE fileId={} offset={} length={} failed", open.fileId, request.offset(), length, e);
			return ErrorResponse.create(request, NTStatus.STATUS_UNEXPECTED_IO_ERROR);
		}

		LOG.debug("WRITE fileId={} offset={} wrote {}/{} bytes", open.fileId, request.offset(), bytesWritten, length);

		var response = new WriteResponse(buildResponseHeader(request, Command.WRITE));
		response.count(bytesWritten);
		response.remaining(0);
		return response;
	}

	public SMB2Message flush(FlushRequest request) {
		var session = connection.sessionTable.get(request.header().sessionId());
		if (session == null) {
			return ErrorResponse.create(request, NTStatus.STATUS_USER_SESSION_DELETED);
		}
		var open = session.openTable.get(request.fileId());
		if (open == null) {
			return ErrorResponse.create(request, NTStatus.STATUS_FILE_CLOSED);
		}
		if (!(open.backend instanceof SmbFile file)) {
			return ErrorResponse.create(request, NTStatus.STATUS_INVALID_DEVICE_REQUEST);
		}
		try {
			file.flush();
		} catch (IOException e) {
			LOG.warn("FLUSH fileId={} failed", open.fileId, e);
			return ErrorResponse.create(request, NTStatus.STATUS_UNEXPECTED_IO_ERROR);
		}
		LOG.debug("FLUSH fileId={}", open.fileId);
		return new FlushResponse(buildResponseHeader(request, Command.FLUSH));
	}

	private PacketHeader buildResponseHeader(SMB2Message request, Command command) {
		var header = PacketHeader.builder();
		header.creditCharge((char) 0);
		header.command(command.value());
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
