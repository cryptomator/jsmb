package org.cryptomator.jsmb.smb2.create;

import org.cryptomator.jsmb.common.NTStatus;
import org.cryptomator.jsmb.share.FileBasicInfo;
import org.cryptomator.jsmb.share.FileStandardInfo;
import org.cryptomator.jsmb.share.OpenParams;
import org.cryptomator.jsmb.share.SmbDirectory;
import org.cryptomator.jsmb.share.SmbFile;
import org.cryptomator.jsmb.share.SmbOpen;
import org.cryptomator.jsmb.smb2.Command;
import org.cryptomator.jsmb.smb2.Connection;
import org.cryptomator.jsmb.smb2.ErrorResponse;
import org.cryptomator.jsmb.smb2.Open;
import org.cryptomator.jsmb.smb2.PacketHeader;
import org.cryptomator.jsmb.smb2.PathNames;
import org.cryptomator.jsmb.smb2.SMB2Message;
import org.cryptomator.jsmb.util.WinFileTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.List;

/**
 * Handles {@code CREATE} and {@code CLOSE} for SMB 3.1.1.
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/8c61e928-9242-44ed-96a0-98d1032d0d39">3.3.5.9 Receiving an SMB2 CREATE Request</a>
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/cfd45bd7-3b03-4df8-bfce-b9f7d1ce5cf0">3.3.5.10 Receiving an SMB2 CLOSE Request</a>
 */
public record CreateHandler(Connection connection) {

	private static final Logger LOG = LoggerFactory.getLogger(CreateHandler.class);

	public SMB2Message create(CreateRequest request) {
		var session = connection.sessionTable.get(request.header().sessionId());
		if (session == null) {
			return ErrorResponse.create(request, NTStatus.STATUS_USER_SESSION_DELETED);
		}
		var treeConnect = session.treeConnectTable.get(request.header().treeId());
		if (treeConnect == null) {
			return ErrorResponse.create(request, NTStatus.STATUS_NETWORK_NAME_DELETED);
		}
		if (treeConnect.share() == null) {
			// IPC$ tree — pipe CREATE isn't implemented, fail every name as "not found".
			return ErrorResponse.create(request, NTStatus.STATUS_OBJECT_NAME_NOT_FOUND);
		}

		OpenParams.Disposition disposition;
		try {
			disposition = OpenParams.Disposition.fromWireValue(request.createDisposition());
		} catch (IllegalArgumentException e) {
			return ErrorResponse.create(request, NTStatus.STATUS_INVALID_PARAMETER);
		}
		int validity = validate(request, disposition);
		if (validity != NTStatus.STATUS_SUCCESS) {
			return ErrorResponse.create(request, validity);
		}
		var name = PathNames.toBackendPath(request.name());
		var params = new OpenParams(request.desiredAccess(), request.shareAccess(), disposition, request.createOptions());

		SmbOpen backend;
		try {
			backend = treeConnect.share().open(name, params);
		} catch (IOException e) {
			int status = NTStatus.of(e);
			if (status == NTStatus.STATUS_UNEXPECTED_IO_ERROR) {
				LOG.warn("CREATE '{}' failed", name, e);
			}
			return ErrorResponse.create(request, status);
		}
		// MS-SMB2 2.2.13: FILE_DIRECTORY_FILE on a file fails with STATUS_NOT_A_DIRECTORY, FILE_NON_DIRECTORY_FILE on a directory with STATUS_FILE_IS_A_DIRECTORY.
		// A backend may report these itself. This covers one that simply opens what it finds.
		if ((request.createOptions() & OpenParams.OPTION_DIRECTORY_FILE) != 0 && backend instanceof SmbFile) {
			closeQuietly(backend);
			return ErrorResponse.create(request, NTStatus.STATUS_NOT_A_DIRECTORY);
		}
		if ((request.createOptions() & OpenParams.OPTION_NON_DIRECTORY_FILE) != 0 && backend instanceof SmbDirectory) {
			closeQuietly(backend);
			return ErrorResponse.create(request, NTStatus.STATUS_FILE_IS_A_DIRECTORY);
		}

		FileBasicInfo basic;
		FileStandardInfo standard;
		try {
			basic = backend.queryBasic();
			standard = backend.queryStandard();
		} catch (IOException e) {
			closeQuietly(backend);
			int status = NTStatus.of(e);
			if (status == NTStatus.STATUS_UNEXPECTED_IO_ERROR) {
				LOG.warn("CREATE '{}' post-open query failed", name, e);
			}
			return ErrorResponse.create(request, status);
		}

		var fileId = backend.fileId();
		session.openTable.put(fileId, new Open(fileId, backend, session, treeConnect, name, request.createOptions())); // FILE_DELETE_ON_CLOSE takes effect when the open is closed
		LOG.debug("CREATE '{}' → fileId={}  action={}", name, fileId, disposition);

		var header = buildResponseHeader(request, Command.CREATE, treeConnect.treeId());
		var response = new CreateResponse(header);
		response.oplockLevel((byte) 0);
		response.flags((byte) 0);
		response.createAction(resolveCreateAction(disposition, backend.existedBeforeOpen()));
		response.creationTime(WinFileTime.fromInstant(basic.creationTime()));
		response.lastAccessTime(WinFileTime.fromInstant(basic.lastAccessTime()));
		response.lastWriteTime(WinFileTime.fromInstant(basic.lastWriteTime()));
		response.changeTime(WinFileTime.fromInstant(basic.changeTime()));
		response.allocationSize(standard.allocationSize());
		response.endOfFile(standard.endOfFile());
		response.fileAttributes(basic.fileAttributes());
		response.fileId(fileId);
		response.createContextsOffset(0);
		response.createContextsLength(0);
		if (request.hasCreateContext(CreateContext.NAME_MXAC)) {
			// The client is asking for the maximal access mask on the freshly opened handle. We don't track ACLs,
			// so mirror FileInfoWriter.accessInfo() and report FILE_ALL_ACCESS with a success status.
			response = response.withCreateContexts(List.of(CreateContext.mxAcResponse(NTStatus.STATUS_SUCCESS, FILE_ALL_ACCESS)));
		}
		return response;
	}

	/** {@code FILE_ALL_ACCESS} — full generic access mask. MS-DTYP 2.4.3. */
	private static final int FILE_ALL_ACCESS = 0x001F01FF;

	private static final int OPTION_OPEN_BY_FILE_ID = 0x00002000;
	private static final int OPTION_RESERVE_OPFILTER = 0x00100000;
	private static final int DIRECTORY_OPTIONS = OpenParams.OPTION_DIRECTORY_FILE | OpenParams.OPTION_NON_DIRECTORY_FILE;
	private static final int RESERVED_ACCESS_BITS = 0x0CE0FE00;

	// The checks of a CREATE request that need no look at the share: MS-SMB2 2.2.13 for the options, MS-FSA 2.1.5.1 phase 1 for the rest. Yields the status to fail the request with.
	private static int validate(CreateRequest request, OpenParams.Disposition disposition) {
		int options = request.createOptions();
		if ((options & (OPTION_OPEN_BY_FILE_ID | OPTION_RESERVE_OPFILTER)) != 0) {
			return NTStatus.STATUS_NOT_SUPPORTED;
		}
		if ((options & DIRECTORY_OPTIONS) == DIRECTORY_OPTIONS) {
			return NTStatus.STATUS_INVALID_PARAMETER;
		}
		boolean directory = (options & OpenParams.OPTION_DIRECTORY_FILE) != 0;
		boolean directoryDisposition = switch (disposition) {
			case CREATE, OPEN, OPEN_IF -> true;
			case SUPERSEDE, OVERWRITE, OVERWRITE_IF -> false;
		};
		if (directory && !directoryDisposition) {
			return NTStatus.STATUS_INVALID_PARAMETER;
		}
		if (request.desiredAccess() == 0 || (request.desiredAccess() & RESERVED_ACCESS_BITS) != 0) {
			return NTStatus.STATUS_ACCESS_DENIED;
		}
		var name = request.name();
		if (PathNames.referencesStream(name)) {
			return NTStatus.STATUS_OBJECT_NAME_NOT_FOUND; // named streams aren't supported, so there is none to be found
		}
		if (!PathNames.isValid(name)) {
			return NTStatus.STATUS_OBJECT_NAME_INVALID;
		}
		if (PathNames.hasTrailingSeparator(name) && (options & OpenParams.OPTION_NON_DIRECTORY_FILE) != 0) {
			return NTStatus.STATUS_OBJECT_NAME_INVALID;
		}
		return NTStatus.STATUS_SUCCESS;
	}

	public SMB2Message close(CloseRequest request) {
		var session = connection.sessionTable.get(request.header().sessionId());
		if (session == null) {
			return ErrorResponse.create(request, NTStatus.STATUS_USER_SESSION_DELETED);
		}
		var open = session.openTable.remove(request.fileId());
		if (open == null) {
			return ErrorResponse.create(request, NTStatus.STATUS_FILE_CLOSED);
		}

		FileBasicInfo basic = null;
		FileStandardInfo standard = null;
		if (request.postQueryAttrib()) {
			try {
				basic = open.backend.queryBasic();
				standard = open.backend.queryStandard();
			} catch (IOException e) {
				LOG.debug("CLOSE post-query attrib failed", e);
			}
		}
		open.close();
		LOG.debug("CLOSE fileId={}", open.fileId);

		var header = buildResponseHeader(request, Command.CLOSE, request.header().treeId());
		var response = new CloseResponse(header);
		if (basic != null && standard != null) {
			response.flags(CloseRequest.FLAG_POSTQUERY_ATTRIB);
			response.creationTime(WinFileTime.fromInstant(basic.creationTime()));
			response.lastAccessTime(WinFileTime.fromInstant(basic.lastAccessTime()));
			response.lastWriteTime(WinFileTime.fromInstant(basic.lastWriteTime()));
			response.changeTime(WinFileTime.fromInstant(basic.changeTime()));
			response.allocationSize(standard.allocationSize());
			response.endOfFile(standard.endOfFile());
			response.fileAttributes(basic.fileAttributes());
		}
		return response;
	}

	/**
	 * Maps the request's {@code CreateDisposition} to the {@code CreateAction} value the response carries back
	 * (MS-SMB2 2.2.14). For {@code FILE_OPEN_IF} / {@code FILE_OVERWRITE_IF} the spec distinguishes OPENED /
	 * OVERWRITTEN (the target existed) from CREATED (a fresh entry had to be made), so we key off the backend's
	 * pre-open existence flag; the other dispositions are unambiguous given that {@link SmbShare#open} already
	 * threw on a conflicting state.
	 */
	private static int resolveCreateAction(OpenParams.Disposition disposition, boolean existedBeforeOpen) {
		return switch (disposition) {
			case SUPERSEDE -> CreateResponse.CREATE_ACTION_SUPERSEDED;
			case OPEN -> CreateResponse.CREATE_ACTION_OPENED;
			case CREATE -> CreateResponse.CREATE_ACTION_CREATED;
			case OPEN_IF -> existedBeforeOpen ? CreateResponse.CREATE_ACTION_OPENED : CreateResponse.CREATE_ACTION_CREATED;
			case OVERWRITE -> CreateResponse.CREATE_ACTION_OVERWRITTEN;
			case OVERWRITE_IF -> existedBeforeOpen ? CreateResponse.CREATE_ACTION_OVERWRITTEN : CreateResponse.CREATE_ACTION_CREATED;
		};
	}

	private PacketHeader buildResponseHeader(SMB2Message request, Command command, int treeId) {
		var header = PacketHeader.builder();
		header.command(command.value());
		header.flags(SMB2Message.Flags.SERVER_TO_REDIR);
		header.nextCommand(0);
		header.messageId(request.header().messageId());
		header.treeId(treeId);
		header.sessionId(request.header().sessionId());
		header.status(NTStatus.STATUS_SUCCESS);
		return header.build();
	}

	private static void closeQuietly(SmbOpen open) {
		try {
			open.close();
		} catch (IOException ignored) {
			// swallow — we've already committed to releasing the handle
		}
	}
}
