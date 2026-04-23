package org.cryptomator.jsmb.smb2.info;

import org.cryptomator.jsmb.common.NTStatus;
import org.cryptomator.jsmb.share.FileBasicInfo;
import org.cryptomator.jsmb.smb2.Command;
import org.cryptomator.jsmb.smb2.Connection;
import org.cryptomator.jsmb.smb2.ErrorResponse;
import org.cryptomator.jsmb.smb2.Open;
import org.cryptomator.jsmb.smb2.PacketHeader;
import org.cryptomator.jsmb.smb2.SMB2Message;
import org.cryptomator.jsmb.util.Layouts;
import org.cryptomator.jsmb.util.WinFileTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.nio.charset.StandardCharsets;
import java.nio.file.AccessDeniedException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.NoSuchFileException;
import java.time.Instant;

/**
 * Handles {@code SET_INFO} for SMB 3.1.1. Supported info classes:
 * <ul>
 *   <li>{@link FileInfoClass#FILE_BASIC_INFORMATION} — timestamps + attributes</li>
 *   <li>{@code FILE_DISPOSITION_INFORMATION} (13) — mark for deletion on close</li>
 *   <li>{@code FILE_END_OF_FILE_INFORMATION} (20) — truncate / extend</li>
 *   <li>{@code FILE_RENAME_INFORMATION} (10) — rename / move</li>
 * </ul>
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/194c56d2-7fdc-4640-a2be-8bea6f8d177a">3.3.5.21 Receiving an SMB2 SET_INFO Request</a>
 */
public record SetInfoHandler(Connection connection) {

	private static final Logger LOG = LoggerFactory.getLogger(SetInfoHandler.class);

	private static final byte FILE_BASIC_INFORMATION = 4;
	private static final byte FILE_RENAME_INFORMATION = 10;
	private static final byte FILE_DISPOSITION_INFORMATION = 13;
	private static final byte FILE_END_OF_FILE_INFORMATION = 20;

	public SMB2Message set(SetInfoRequest request) {
		var session = connection.sessionTable.get(request.header().sessionId());
		if (session == null) {
			return ErrorResponse.create(request, NTStatus.STATUS_USER_SESSION_DELETED);
		}
		var open = session.openTable.get(request.fileId());
		if (open == null) {
			return ErrorResponse.create(request, NTStatus.STATUS_FILE_CLOSED);
		}

		if (request.infoType() != SetInfoRequest.INFO_TYPE_FILE) {
			// Only file-level SET_INFO is supported; security/quota/filesystem are not implemented.
			return ErrorResponse.create(request, NTStatus.STATUS_NOT_SUPPORTED);
		}

		try {
			int status = applyFileInfo(open, request);
			if (status != NTStatus.STATUS_SUCCESS) {
				return ErrorResponse.create(request, status);
			}
		} catch (IOException e) {
			LOG.warn("SET_INFO fileId={} class=0x{} failed", open.fileId, Integer.toHexString(request.fileInfoClass()), e);
			return ErrorResponse.create(request, NTStatus.STATUS_UNEXPECTED_IO_ERROR);
		}

		var header = buildResponseHeader(request);
		return new SetInfoResponse(header);
	}

	private int applyFileInfo(Open open, SetInfoRequest request) throws IOException {
		var buffer = request.buffer();
		return switch (request.fileInfoClass()) {
			case FILE_BASIC_INFORMATION -> applyBasic(open, buffer);
			case FILE_DISPOSITION_INFORMATION -> applyDisposition(open, buffer);
			case FILE_END_OF_FILE_INFORMATION -> applyEndOfFile(open, buffer);
			case FILE_RENAME_INFORMATION -> applyRename(open, buffer);
			default -> {
				LOG.debug("SET_INFO FILE with unsupported class 0x{}", Integer.toHexString(request.fileInfoClass()));
				yield NTStatus.STATUS_INVALID_INFO_CLASS;
			}
		};
	}

	/**
	 * MS-FSCC 2.4.7 — 40 bytes: 4x FILETIME + FileAttributes + Reserved. A FILETIME of {@code 0} means
	 * "don't change"; any non-zero value replaces the stored timestamp. {@code FileAttributes == 0}
	 * likewise leaves attributes alone.
	 */
	private int applyBasic(Open open, MemorySegment buffer) throws IOException {
		if (buffer.byteSize() < 36) {
			return NTStatus.STATUS_INFO_LENGTH_MISMATCH;
		}
		Instant creation = readFileTime(buffer, 0);
		Instant lastAccess = readFileTime(buffer, 8);
		Instant lastWrite = readFileTime(buffer, 16);
		Instant change = readFileTime(buffer, 24);
		int attrs = buffer.get(Layouts.LE_INT32, 32);
		open.backend.setBasic(new FileBasicInfo(creation, lastAccess, lastWrite, change, attrs));
		return NTStatus.STATUS_SUCCESS;
	}

	/**
	 * MS-FSCC 2.4.11 — 1 byte. {@code DeletePending != 0} flags the open for unlink on CLOSE.
	 */
	private int applyDisposition(Open open, MemorySegment buffer) {
		if (buffer.byteSize() < 1) {
			return NTStatus.STATUS_INFO_LENGTH_MISMATCH;
		}
		boolean deletePending = buffer.get(Layouts.BYTE, 0) != 0;
		if (deletePending) {
			open.backend.markForDeletion();
			LOG.debug("SET_INFO fileId={} marked for deletion on close", open.fileId);
		}
		return NTStatus.STATUS_SUCCESS;
	}

	/**
	 * MS-FSCC 2.4.13 — 8 bytes: the new file length in bytes.
	 */
	private int applyEndOfFile(Open open, MemorySegment buffer) throws IOException {
		if (buffer.byteSize() < 8) {
			return NTStatus.STATUS_INFO_LENGTH_MISMATCH;
		}
		long length = buffer.get(Layouts.LE_INT64, 0);
		open.backend.setEndOfFile(length);
		LOG.debug("SET_INFO fileId={} setEndOfFile({})", open.fileId, length);
		return NTStatus.STATUS_SUCCESS;
	}

	/**
	 * MS-FSCC 2.4.37.2 (type-2 layout, used by SMB2 SET_INFO). 20 bytes fixed:
	 * ReplaceIfExists (1) + Reserved (7) + RootDirectory (8) + FileNameLength (4), then UTF-16LE name.
	 */
	private int applyRename(Open open, MemorySegment buffer) throws IOException {
		if (buffer.byteSize() < 20) {
			return NTStatus.STATUS_INFO_LENGTH_MISMATCH;
		}
		boolean replaceIfExists = buffer.get(Layouts.BYTE, 0) != 0;
		int nameLength = buffer.get(Layouts.LE_INT32, 16);
		if (nameLength < 0 || 20L + nameLength > buffer.byteSize()) {
			return NTStatus.STATUS_INFO_LENGTH_MISMATCH;
		}
		byte[] nameBytes = buffer.asSlice(20, nameLength).toArray(Layouts.BYTE);
		var newPath = new String(nameBytes, StandardCharsets.UTF_16LE);
		try {
			open.backend.rename(newPath, replaceIfExists);
		} catch (NoSuchFileException e) {
			return NTStatus.STATUS_OBJECT_NAME_NOT_FOUND;
		} catch (FileAlreadyExistsException e) {
			return NTStatus.STATUS_OBJECT_NAME_COLLISION;
		} catch (AccessDeniedException e) {
			return NTStatus.STATUS_ACCESS_DENIED;
		}
		LOG.debug("SET_INFO fileId={} renamed to '{}' (replace={})", open.fileId, newPath, replaceIfExists);
		return NTStatus.STATUS_SUCCESS;
	}

	private static Instant readFileTime(MemorySegment buffer, int offset) {
		long value = buffer.get(Layouts.LE_INT64, offset);
		return value == 0L ? null : WinFileTime.toInstant(value);
	}

	private PacketHeader buildResponseHeader(SetInfoRequest request) {
		var header = PacketHeader.builder();
		header.creditCharge((char) 0);
		header.command(Command.SET_INFO.value());
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
