package org.cryptomator.jsmb.smb2.tree;

import org.cryptomator.jsmb.common.NTStatus;
import org.cryptomator.jsmb.smb2.Command;
import org.cryptomator.jsmb.smb2.Connection;
import org.cryptomator.jsmb.smb2.ErrorResponse;
import org.cryptomator.jsmb.smb2.PacketHeader;
import org.cryptomator.jsmb.smb2.SMB2Message;
import org.cryptomator.jsmb.smb2.TreeConnect;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Handles {@code TREE_CONNECT} and {@code TREE_DISCONNECT} for SMB 3.1.1.
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/06eaaabc-caca-4776-9daf-82439e90dacd">3.3.5.7 Receiving an SMB2 TREE_CONNECT Request</a>
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/42ba4346-cea1-4bae-a82d-3e4e7a1cb82a">3.3.5.8 Receiving an SMB2 TREE_DISCONNECT Request</a>
 */
public record TreeConnectHandler(Connection connection) {

	private static final Logger LOG = LoggerFactory.getLogger(TreeConnectHandler.class);

	/**
	 * Administrative named-pipe share. Every SMB client probes this one to access RPC endpoints
	 * (SRVSVC, LSARPC, WKSSVC, …) for share enumeration and server-info queries. Handled inline —
	 * embedders don't (and shouldn't) register it themselves.
	 */
	static final String IPC_SHARE_NAME = "IPC$";

	/**
	 * All standard file access bits set: {@code GENERIC_ALL} resolved down to {@code FILE_ALL_ACCESS}.
	 * Returned verbatim as {@code MaximalAccess} until access checks are actually implemented.
	 */
	private static final int FILE_ALL_ACCESS = 0x001F01FF;

	public SMB2Message connect(TreeConnectRequest request) {
		var session = connection.sessionTable.get(request.header().sessionId());
		if (session == null) {
			return ErrorResponse.create(request, NTStatus.STATUS_USER_SESSION_DELETED);
		}
		var shareName = shareNameOf(request.path());
		if (IPC_SHARE_NAME.equalsIgnoreCase(shareName)) {
			return connectIpc(request, session);
		}
		var share = connection.global.shares.get(shareName);
		if (share == null) {
			LOG.debug("TREE_CONNECT to unknown share '{}' (path={})", shareName, request.path());
			return ErrorResponse.create(request, NTStatus.STATUS_BAD_NETWORK_NAME);
		}
		int treeId = session.nextTreeId.getAndIncrement();
		session.treeConnectTable.put(treeId, new TreeConnect(treeId, shareName, share, FILE_ALL_ACCESS));
		LOG.debug("TREE_CONNECT '{}' → treeId=0x{}", shareName, Integer.toHexString(treeId));

		var header = buildResponseHeader(request, Command.TREE_CONNECT, treeId);
		var response = new TreeConnectResponse(header);
		response.shareType(TreeConnectResponse.SHARE_TYPE_DISK);
		response.shareFlags(0);
		response.capabilities(0);
		response.maximalAccess(FILE_ALL_ACCESS);
		return response;
	}

	/**
	 * Accepts a tree connect to {@code IPC$} with {@code ShareType=PIPE}. The stored
	 * {@link TreeConnect} carries a {@code null} backend — any {@code CREATE} on this tree must
	 * branch on the share name / null backend and fail with a pipe-appropriate NT status.
	 */
	private SMB2Message connectIpc(TreeConnectRequest request, org.cryptomator.jsmb.smb2.Session session) {
		int treeId = session.nextTreeId.getAndIncrement();
		session.treeConnectTable.put(treeId, new TreeConnect(treeId, IPC_SHARE_NAME, null, FILE_ALL_ACCESS));
		LOG.debug("TREE_CONNECT to IPC$ → treeId=0x{} (pipe tree, no disk backend)", Integer.toHexString(treeId));

		var header = buildResponseHeader(request, Command.TREE_CONNECT, treeId);
		var response = new TreeConnectResponse(header);
		response.shareType(TreeConnectResponse.SHARE_TYPE_PIPE);
		response.shareFlags(0);
		response.capabilities(0);
		response.maximalAccess(FILE_ALL_ACCESS);
		return response;
	}

	private PacketHeader buildResponseHeader(SMB2Message request, Command command, int treeId) {
		var header = PacketHeader.builder();
		header.creditCharge((char) 0);
		header.command(command.value());
		header.creditResponse((char) 1);
		header.flags(SMB2Message.Flags.SERVER_TO_REDIR);
		header.nextCommand(0);
		header.messageId(request.header().messageId());
		header.treeId(treeId);
		header.sessionId(request.header().sessionId());
		header.status(NTStatus.STATUS_SUCCESS);
		return header.build();
	}

	public SMB2Message disconnect(TreeDisconnectRequest request) {
		var session = connection.sessionTable.get(request.header().sessionId());
		if (session == null) {
			return ErrorResponse.create(request, NTStatus.STATUS_USER_SESSION_DELETED);
		}
		int treeId = request.header().treeId();
		var removed = session.treeConnectTable.remove(treeId);
		if (removed == null) {
			return ErrorResponse.create(request, NTStatus.STATUS_NETWORK_NAME_DELETED);
		}
		LOG.debug("TREE_DISCONNECT treeId=0x{} ('{}')", Integer.toHexString(treeId), removed.shareName());
		return new TreeDisconnectResponse(buildResponseHeader(request, Command.TREE_DISCONNECT, treeId));
	}

	/**
	 * Extracts the share component from a UNC path such as {@code \\server\share}. Returns the
	 * substring after the last backslash, or the whole input if no backslash is present.
	 */
	static String shareNameOf(String path) {
		int last = path.lastIndexOf('\\');
		return last < 0 ? path : path.substring(last + 1);
	}
}
