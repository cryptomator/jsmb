package org.cryptomator.jsmb.smb2.info;

import org.cryptomator.jsmb.Server;
import org.cryptomator.jsmb.common.NTStatus;
import org.cryptomator.jsmb.share.FileBasicInfo;
import org.cryptomator.jsmb.share.FileStandardInfo;
import org.cryptomator.jsmb.smb2.AccessMask;
import org.cryptomator.jsmb.smb2.Command;
import org.cryptomator.jsmb.smb2.Connection;
import org.cryptomator.jsmb.smb2.ErrorResponse;
import org.cryptomator.jsmb.smb2.Open;
import org.cryptomator.jsmb.smb2.PacketHeader;
import org.cryptomator.jsmb.smb2.SMB2Message;
import org.cryptomator.jsmb.util.WinFileTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.AccessDeniedException;
import java.util.Arrays;

/**
 * Handles {@code QUERY_INFO} for SMB 3.1.1. Dispatches on {@code InfoType}:
 * <ul>
 *   <li>{@code FILE} (0x01) — file-level info delegated to {@link FileInfoWriter}.</li>
 *   <li>{@code FILESYSTEM} (0x02) — filesystem-level info delegated to {@link FsInfoWriter}.</li>
 *   <li>{@code SECURITY} (0x03), {@code QUOTA} (0x04) — {@code STATUS_NOT_SUPPORTED} for now.</li>
 * </ul>
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5a5bca30-3b3e-4b0b-a13a-90a36dc62c8b">3.3.5.20 Receiving an SMB2 QUERY_INFO Request</a>
 */
public record QueryInfoHandler(Server server, Connection connection) {

	private static final Logger LOG = LoggerFactory.getLogger(QueryInfoHandler.class);

	public SMB2Message query(QueryInfoRequest request) {
		var session = connection.sessionTable.get(request.header().sessionId());
		if (session == null) {
			return ErrorResponse.create(request, NTStatus.STATUS_USER_SESSION_DELETED);
		}
		var open = session.openTable.get(request.fileId());
		if (open == null) {
			return ErrorResponse.create(request, NTStatus.STATUS_FILE_CLOSED);
		}
		// MS-SMB2 3.3.5.20: "If OutputBufferLength is greater than Connection.MaxTransactSize, the server SHOULD fail the request with STATUS_INVALID_PARAMETER."
		if (Integer.toUnsignedLong(request.outputBufferLength()) > connection.maxTransactSize) {
			return ErrorResponse.create(request, NTStatus.STATUS_INVALID_PARAMETER);
		}

		try {
			Info info = switch (request.infoType()) {
				case QueryInfoRequest.INFO_TYPE_FILE -> writeFileInfo(open, request);
				case QueryInfoRequest.INFO_TYPE_FILESYSTEM -> writeFsInfo(open, request);
				case QueryInfoRequest.INFO_TYPE_SECURITY, QueryInfoRequest.INFO_TYPE_QUOTA -> null;
				default -> null;
			};
			if (info == null) {
				return ErrorResponse.create(request, NTStatus.STATUS_NOT_SUPPORTED);
			}
			// MS-SMB2 3.3.5.20.1 and 3.3.5.20.2: the fixed part has to fit, or else there is nothing useful to return.
			// Variable-length data that doesn't fit gets cut off, which the client learns from STATUS_BUFFER_OVERFLOW. The length fields within the data still state the full size.
			int outputBufferLength = request.outputBufferLength(); // not beyond MaxTransactSize, hence positive
			if (outputBufferLength == 0 || outputBufferLength < info.fixedPartSize()) {
				return ErrorResponse.create(request, NTStatus.STATUS_INFO_LENGTH_MISMATCH);
			}
			if (info.data().length > outputBufferLength) {
				var header = buildResponseHeader(request, NTStatus.STATUS_BUFFER_OVERFLOW);
				return new QueryInfoResponse(header).withOutputBuffer(Arrays.copyOf(info.data(), outputBufferLength));
			}
			var header = buildResponseHeader(request, NTStatus.STATUS_SUCCESS);
			return new QueryInfoResponse(header).withOutputBuffer(info.data());
		} catch (UnsupportedInfoClassException e) {
			return ErrorResponse.create(request, NTStatus.STATUS_INVALID_INFO_CLASS);
		} catch (IOException e) {
			int status = NTStatus.of(e);
			if (status == NTStatus.STATUS_UNEXPECTED_IO_ERROR) {
				LOG.warn("QUERY_INFO backend query failed", e);
			}
			return ErrorResponse.create(request, status);
		}
	}

	// the requested information and how many of its leading bytes are the fixed part
	private record Info(byte[] data, int fixedPartSize) {
	}

	private Info writeFileInfo(Open open, QueryInfoRequest request) throws UnsupportedInfoClassException, IOException {
		FileInfoClass cls;
		try {
			cls = FileInfoClass.fromValue(request.fileInfoClass());
		} catch (IllegalArgumentException e) {
			LOG.debug("QUERY_INFO FILE with unsupported class 0x{}", Integer.toHexString(request.fileInfoClass()));
			throw new UnsupportedInfoClassException();
		}
		// MS-SMB2 3.3.5.20.1: "[...] and Open.GrantedAccess does not include FILE_READ_ATTRIBUTES, the server MUST fail the request with STATUS_ACCESS_DENIED."
		if (cls.requiresReadAttributes() && !open.isGranted(AccessMask.FILE_READ_ATTRIBUTES)) {
			throw new AccessDeniedException(open.path); // which the caller maps to that status
		}
		FileBasicInfo basic = open.backend.queryBasic();
		FileStandardInfo standard = open.backend.queryStandard();
		byte[] data = FileInfoWriter.write(cls, open.path, open.grantedAccess, basic, standard);
		return new Info(data, cls.fixedPartSize(data.length));
	}

	private Info writeFsInfo(Open open, QueryInfoRequest request) throws UnsupportedInfoClassException, IOException {
		FsInfoClass cls;
		try {
			cls = FsInfoClass.fromValue(request.fileInfoClass());
		} catch (IllegalArgumentException e) {
			LOG.debug("QUERY_INFO FILESYSTEM with unsupported class 0x{}", Integer.toHexString(request.fileInfoClass()));
			throw new UnsupportedInfoClassException();
		}
		var share = open.treeConnect.share();
		if (share == null) {
			// IPC$ / pipe tree — FILESYSTEM queries are meaningless here.
			throw new UnsupportedInfoClassException();
		}
		var size = share.fsSize();
		var attrs = share.fsAttributes();
		byte[] data = FsInfoWriter.write(cls, size, attrs, open.treeConnect.shareName(), WinFileTime.fromInstant(server.startTime));
		return new Info(data, cls.fixedPartSize(data.length));
	}

	private PacketHeader buildResponseHeader(QueryInfoRequest request, int status) {
		var header = PacketHeader.builder();
		header.command(Command.QUERY_INFO.value());
		header.flags(SMB2Message.Flags.SERVER_TO_REDIR);
		header.nextCommand(0);
		header.messageId(request.header().messageId());
		header.treeId(request.header().treeId());
		header.sessionId(request.header().sessionId());
		header.status(status);
		return header.build();
	}

	/** Local sentinel for "the parsed info class isn't in our supported set". */
	private static final class UnsupportedInfoClassException extends Exception {
	}
}
