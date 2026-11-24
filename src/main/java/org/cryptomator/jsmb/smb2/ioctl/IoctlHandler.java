package org.cryptomator.jsmb.smb2.ioctl;

import org.cryptomator.jsmb.common.DisconnectException;
import org.cryptomator.jsmb.common.NTStatus;
import org.cryptomator.jsmb.smb2.Connection;
import org.cryptomator.jsmb.smb2.ErrorResponse;
import org.cryptomator.jsmb.smb2.SMB2Message;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Minimal SMB2 IOCTL handler. Handles the spec-mandated {@code FSCTL_VALIDATE_NEGOTIATE_INFO}
 * response for dialect 3.1.1 and refuses everything else with {@code STATUS_INVALID_DEVICE_REQUEST}.
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/138ed63d-84e8-4d89-9bc7-a73211642d52">3.3.5.15 Receiving an SMB2 IOCTL Request</a>
 */
public record IoctlHandler(Connection connection) {

	private static final Logger LOG = LoggerFactory.getLogger(IoctlHandler.class);

	public SMB2Message handle(IoctlRequest request) {
		if (request.flags() != IoctlRequest.FLAG_IS_FSCTL) {
			return ErrorResponse.create(request, NTStatus.STATUS_NOT_SUPPORTED);
		}
		long maxTransactSize = connection.maxTransactSize;
		if (Integer.toUnsignedLong(request.inputCount()) > maxTransactSize
				|| Integer.toUnsignedLong(request.maxInputResponse()) > maxTransactSize
				|| Integer.toUnsignedLong(request.maxOutputResponse()) > maxTransactSize) {
			return ErrorResponse.create(request, NTStatus.STATUS_INVALID_PARAMETER);
		}
		int ctlCode = request.ctlCode();
		if (ctlCode == FsctlCode.FSCTL_VALIDATE_NEGOTIATE_INFO) {
			// MS-SMB2 3.3.5.15.12: "If Connection.Dialect is "3.1.1", the server MUST terminate the transport connection", and 3.1.1 is the only dialect there is.
			// A 3.1.1 client has no reason to send this: the preauth integrity hash protects the negotiation already.
			throw new DisconnectException("FSCTL_VALIDATE_NEGOTIATE_INFO on a connection using dialect 3.1.1");
		}
		LOG.debug("Unhandled FSCTL/IOCTL 0x{}, replying STATUS_INVALID_DEVICE_REQUEST", Integer.toHexString(ctlCode));
		return ErrorResponse.create(request, NTStatus.STATUS_INVALID_DEVICE_REQUEST);
	}
}
