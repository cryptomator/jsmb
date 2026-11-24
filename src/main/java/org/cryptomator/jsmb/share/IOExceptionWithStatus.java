package org.cryptomator.jsmb.share;

import org.cryptomator.jsmb.common.NTStatus;

import java.io.IOException;

/**
 * An {@link IOException} by which a share backend tells the server which status to fail a request with.
 * <p>
 * Meant for failures that no exception type of the JDK stands for, such as a sharing violation or a full disk.
 * See {@link SmbShare} for how other exceptions are mapped.
 */
public class IOExceptionWithStatus extends IOException {

	/**
	 * The statuses a backend can report.
	 *
	 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55">MS-ERREF 2.3.1 NTSTATUS Values</a>
	 */
	public enum Status {

		/** The file or directory doesn't exist. */
		OBJECT_NAME_NOT_FOUND(NTStatus.STATUS_OBJECT_NAME_NOT_FOUND),

		/** A file or directory of that name exists already. */
		OBJECT_NAME_COLLISION(NTStatus.STATUS_OBJECT_NAME_COLLISION),

		/** The operation is not permitted. */
		ACCESS_DENIED(NTStatus.STATUS_ACCESS_DENIED),

		/** A directory was called for, but the path denotes a file. */
		NOT_A_DIRECTORY(NTStatus.STATUS_NOT_A_DIRECTORY),

		/** A file was called for, but the path denotes a directory. */
		FILE_IS_A_DIRECTORY(NTStatus.STATUS_FILE_IS_A_DIRECTORY),

		/** The directory can't be removed or replaced, as it has entries. */
		DIRECTORY_NOT_EMPTY(NTStatus.STATUS_DIRECTORY_NOT_EMPTY),

		/** The file is in use in a way that conflicts with the requested access. */
		SHARING_VIOLATION(NTStatus.STATUS_SHARING_VIOLATION),

		/** There is no space left to store the data. */
		DISK_FULL(NTStatus.STATUS_DISK_FULL),

		/** Anything else. This is also what an {@link IOException} of an unknown kind is reported as. */
		UNEXPECTED_IO_ERROR(NTStatus.STATUS_UNEXPECTED_IO_ERROR);

		private final int ntStatus;

		Status(int ntStatus) {
			this.ntStatus = ntStatus;
		}

		/**
		 * @return the numerical NTSTATUS value
		 */
		public int ntStatus() {
			return ntStatus;
		}
	}

	private final Status status;

	/**
	 * @param status the status to fail the request with
	 */
	public IOExceptionWithStatus(Status status) {
		this(status, status.name(), null);
	}

	/**
	 * @param status  the status to fail the request with
	 * @param message human-readable detail, which stays on the server
	 * @param cause   underlying cause, or {@code null}
	 */
	public IOExceptionWithStatus(Status status, String message, Throwable cause) {
		super(message, cause);
		this.status = status;
	}

	/**
	 * @return the status to fail the request with
	 */
	public Status status() {
		return status;
	}
}
