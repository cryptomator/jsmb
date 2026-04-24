package org.cryptomator.jsmb.smb2.ioctl;

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
		int ctlCode = request.ctlCode();
		if (ctlCode == FsctlCode.FSCTL_VALIDATE_NEGOTIATE_INFO) {
			// MS-SMB2 3.3.5.15.12: for dialect 3.1.1, the server MUST reject this FSCTL with STATUS_FILE_CLOSED.
			// The client treats that as "preauth integrity already protects against downgrade" and proceeds.
			LOG.debug("Rejecting FSCTL_VALIDATE_NEGOTIATE_INFO with STATUS_FILE_CLOSED (dialect 3.1.1)");
			return ErrorResponse.create(request, NTStatus.STATUS_FILE_CLOSED);
		}
		LOG.debug("Unhandled FSCTL/IOCTL 0x{}, replying STATUS_INVALID_DEVICE_REQUEST", Integer.toHexString(ctlCode));
		return ErrorResponse.create(request, NTStatus.STATUS_INVALID_DEVICE_REQUEST);
	}
}
