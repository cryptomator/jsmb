package org.cryptomator.jsmb.smb2.ioctl;

/**
 * Selected FSCTL codes carried inside an SMB2 IOCTL. Only codes this server recognizes
 * for dispatch decisions are listed here.
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/4dc02779-9d95-43f8-bba4-8d4ce4961458">MS-FSCC 2.3 FSCTL Structures</a>
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5c03c9d6-15de-48a2-9835-8fb37f8a79d8">MS-SMB2 2.2.31 SMB2 IOCTL Request</a>
 */
public final class FsctlCode {

	private FsctlCode() {}

	/** MS-SMB2 2.2.31.4 — client asks server to reconfirm the negotiated dialect to detect downgrade attacks. */
	public static final int FSCTL_VALIDATE_NEGOTIATE_INFO = 0x00140204;
}
