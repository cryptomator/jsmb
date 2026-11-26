package org.cryptomator.jsmb.smb2.io;

import org.cryptomator.jsmb.common.NTStatus;
import org.cryptomator.jsmb.share.SmbFile;
import org.cryptomator.jsmb.smb2.AccessMask;
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
 * Handles {@code READ} for SMB 3.1.1. Dispatches to {@link org.cryptomator.jsmb.share.SmbOpen#read} and
 * caps the returned length at {@link Connection#maxReadSize} — honoring the server-advertised ceiling is how clients
 * know not to ask for more. {@code STATUS_END_OF_FILE} when {@code Offset >= EndOfFile}.
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/21e8b343-34e9-4fca-8d93-03dd2d3e961e">3.3.5.12 Receiving an SMB2 READ Request</a>
 */
public record ReadHandler(Connection connection) {

	private static final Logger LOG = LoggerFactory.getLogger(ReadHandler.class);

	public SMB2Message read(ReadRequest request) {
		var session = connection.sessionTable.get(request.header().sessionId());
		if (session == null) {
			return ErrorResponse.create(request, NTStatus.STATUS_USER_SESSION_DELETED);
		}
		var open = session.openTable.get(request.fileId());
		if (open == null) {
			return ErrorResponse.create(request, NTStatus.STATUS_FILE_CLOSED);
		}
		if (!(open.backend instanceof SmbFile file)) {
			// READ on a directory handle — spec (MS-SMB2 3.3.5.12) has the server reject this.
			return ErrorResponse.create(request, NTStatus.STATUS_INVALID_DEVICE_REQUEST);
		}
		// MS-SMB2 3.3.5.12: "If Open.GrantedAccess does not allow for FILE_READ_DATA, the request MUST be failed with STATUS_ACCESS_DENIED."
		if (!open.isGranted(AccessMask.FILE_READ_DATA)) {
			return ErrorResponse.create(request, NTStatus.STATUS_ACCESS_DENIED);
		}

		int requested = request.length();
		if (requested < 0 || requested > connection.maxReadSize) {
			// Client exceeded the MaxReadSize we negotiated — spec says STATUS_INVALID_PARAMETER (MS-SMB2 3.3.5.12).
			return ErrorResponse.create(request, NTStatus.STATUS_INVALID_PARAMETER);
		}

		byte[] buffer = new byte[requested];
		int bytesRead;
		try {
			bytesRead = file.read(ByteBuffer.wrap(buffer), request.offset());
		} catch (IOException e) {
			int status = NTStatus.of(e);
			if (status == NTStatus.STATUS_UNEXPECTED_IO_ERROR) {
				LOG.warn("READ fileId={} offset={} length={} failed", open.fileId, request.offset(), requested, e);
			}
			return ErrorResponse.create(request, status);
		}

		if (bytesRead < 0) {
			return ErrorResponse.create(request, NTStatus.STATUS_END_OF_FILE);
		}
		if (bytesRead < request.minimumCount()) {
			// Client required a minimum and we came up short — per spec this is STATUS_END_OF_FILE too.
			return ErrorResponse.create(request, NTStatus.STATUS_END_OF_FILE);
		}

		byte[] payload = bytesRead == buffer.length ? buffer : java.util.Arrays.copyOf(buffer, bytesRead);
		LOG.debug("READ fileId={} offset={} wrote {}/{} bytes", open.fileId, request.offset(), bytesRead, requested);

		var header = buildResponseHeader(request);
		return new ReadResponse(header).withData(payload);
	}

	private PacketHeader buildResponseHeader(ReadRequest request) {
		var header = PacketHeader.builder();
		header.command(Command.READ.value());
		header.flags(SMB2Message.Flags.SERVER_TO_REDIR);
		header.nextCommand(0);
		header.messageId(request.header().messageId());
		header.treeId(request.header().treeId());
		header.sessionId(request.header().sessionId());
		header.status(NTStatus.STATUS_SUCCESS);
		return header.build();
	}
}
