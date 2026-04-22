package org.cryptomator.jsmb.smb2.ioctl;

/**
 * Selected FSCTL codes carried inside an SMB2 IOCTL. Only codes this server recognizes
 * for dispatch decisions are listed here.
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/6c6a9e1c-75ba-4f48-93e7-5b35e8c73683">MS-FSCC 2.3 FSCTL Structures</a>
 */
public final class FsctlCode {

	private FsctlCode() {}

	/** MS-SMB2 2.2.31.4 — client asks server to reconfirm the negotiated dialect to detect downgrade attacks. */
	public static final int FSCTL_VALIDATE_NEGOTIATE_INFO = 0x00140204;
}
