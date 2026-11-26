package org.cryptomator.jsmb.smb2;

/**
 * The access rights a client asks for in a {@code CREATE} request, and which requests on the resulting open are checked against.
 *
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/77b36d0f-6016-458a-a7a0-0f4a72ae1534">2.2.13.1.1 File_Pipe_Printer_Access_Mask</a>
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/0a5934b1-80f1-4da0-b1bf-5e021c309b71">2.2.13.1.2 Directory_Access_Mask</a>
 */
public interface AccessMask {

	int FILE_READ_DATA = 0x00000001;
	/** The same bit as {@link #FILE_READ_DATA}, under the name it has for a directory. */
	int FILE_LIST_DIRECTORY = 0x00000001;
	int FILE_WRITE_DATA = 0x00000002;
	int FILE_APPEND_DATA = 0x00000004;
	int FILE_READ_EA = 0x00000008;
	int FILE_WRITE_EA = 0x00000010;
	int FILE_EXECUTE = 0x00000020;
	int FILE_DELETE_CHILD = 0x00000040;
	int FILE_READ_ATTRIBUTES = 0x00000080;
	int FILE_WRITE_ATTRIBUTES = 0x00000100;
	int DELETE = 0x00010000;
	int READ_CONTROL = 0x00020000;
	int WRITE_DAC = 0x00040000;
	int WRITE_OWNER = 0x00080000;
	int SYNCHRONIZE = 0x00100000;
	int ACCESS_SYSTEM_SECURITY = 0x01000000;
	int MAXIMUM_ALLOWED = 0x02000000;
	int GENERIC_ALL = 0x10000000;
	int GENERIC_EXECUTE = 0x20000000;
	int GENERIC_WRITE = 0x40000000;
	int GENERIC_READ = 0x80000000;

	/** All rights but {@link #ACCESS_SYSTEM_SECURITY}, which is what {@link #GENERIC_ALL} stands for. */
	int FILE_ALL_ACCESS = 0x001F01FF;

	/** The bits that are none of the rights above. */
	int RESERVED = 0x0CE0FE00;

	/**
	 * Determines the rights an open is granted, which in the absence of access control are those the client asks for.
	 * <p>
	 * Generic rights are replaced by the specific rights they stand for. {@link #MAXIMUM_ALLOWED} yields all of them.
	 *
	 * @param desiredAccess the {@code DesiredAccess} of a {@code CREATE} request
	 * @return the specific rights granted, free of generic rights and of {@link #MAXIMUM_ALLOWED}
	 */
	static int grantedFor(int desiredAccess) {
		int granted = desiredAccess & (FILE_ALL_ACCESS | ACCESS_SYSTEM_SECURITY);
		if ((desiredAccess & GENERIC_READ) != 0) {
			granted |= FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA | SYNCHRONIZE | READ_CONTROL;
		}
		if ((desiredAccess & GENERIC_WRITE) != 0) {
			granted |= FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | SYNCHRONIZE | READ_CONTROL;
		}
		if ((desiredAccess & GENERIC_EXECUTE) != 0) {
			granted |= FILE_READ_ATTRIBUTES | FILE_EXECUTE | SYNCHRONIZE | READ_CONTROL;
		}
		if ((desiredAccess & (GENERIC_ALL | MAXIMUM_ALLOWED)) != 0) {
			granted |= FILE_ALL_ACCESS;
		}
		if ((granted & FILE_EXECUTE) != 0) {
			granted |= FILE_READ_DATA; // 3.3.5.9: "If Open.GrantedAccess includes FILE_EXECUTE, the server MUST set FILE_READ_DATA in Open.GrantedAccess."
		}
		return granted;
	}
}
