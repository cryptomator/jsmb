package org.cryptomator.jsmb.common;

import org.cryptomator.jsmb.share.IOExceptionWithStatus;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.nio.file.AccessDeniedException;
import java.nio.file.DirectoryNotEmptyException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.FileSystemException;
import java.nio.file.NoSuchFileException;
import java.nio.file.NotDirectoryException;
import java.util.stream.Stream;

class NTStatusTest {

	@ParameterizedTest(name = "{0}")
	@DisplayName("of() maps the exception types that stand for a specific failure to its status")
	@MethodSource("knownExceptions")
	void knownException(IOException exception, int expectedStatus) {
		int status = NTStatus.of(exception);

		Assertions.assertEquals(expectedStatus, status);
	}

	static Stream<Arguments> knownExceptions() {
		return Stream.of(
				Arguments.of(new NoSuchFileException("x"), NTStatus.STATUS_OBJECT_NAME_NOT_FOUND),
				Arguments.of(new FileAlreadyExistsException("x"), NTStatus.STATUS_OBJECT_NAME_COLLISION),
				Arguments.of(new AccessDeniedException("x"), NTStatus.STATUS_ACCESS_DENIED),
				Arguments.of(new NotDirectoryException("x"), NTStatus.STATUS_NOT_A_DIRECTORY),
				Arguments.of(new DirectoryNotEmptyException("x"), NTStatus.STATUS_DIRECTORY_NOT_EMPTY));
	}

	@ParameterizedTest(name = "{0}")
	@DisplayName("of() maps an exception of an unknown kind to STATUS_UNEXPECTED_IO_ERROR")
	@MethodSource("unknownExceptions")
	void unknownException(IOException exception) {
		int status = NTStatus.of(exception);

		Assertions.assertEquals(NTStatus.STATUS_UNEXPECTED_IO_ERROR, status);
	}

	static Stream<IOException> unknownExceptions() {
		return Stream.of(new IOException("x"), new FileSystemException("x"));
	}

	@ParameterizedTest(name = "{0}")
	@DisplayName("of() maps an IOExceptionWithStatus to the status it carries")
	@EnumSource(IOExceptionWithStatus.Status.class)
	void exceptionWithStatus(IOExceptionWithStatus.Status carried) {
		int status = NTStatus.of(new IOExceptionWithStatus(carried));

		Assertions.assertEquals(carried.ntStatus(), status);
	}

	@Test
	@DisplayName("The statuses a backend can report have the values defined in MS-ERREF")
	void statusValues() {
		Assertions.assertEquals(0xC0000034, IOExceptionWithStatus.Status.OBJECT_NAME_NOT_FOUND.ntStatus());
		Assertions.assertEquals(0xC0000035, IOExceptionWithStatus.Status.OBJECT_NAME_COLLISION.ntStatus());
		Assertions.assertEquals(0xC0000022, IOExceptionWithStatus.Status.ACCESS_DENIED.ntStatus());
		Assertions.assertEquals(0xC0000103, IOExceptionWithStatus.Status.NOT_A_DIRECTORY.ntStatus());
		Assertions.assertEquals(0xC00000BA, IOExceptionWithStatus.Status.FILE_IS_A_DIRECTORY.ntStatus());
		Assertions.assertEquals(0xC0000101, IOExceptionWithStatus.Status.DIRECTORY_NOT_EMPTY.ntStatus());
		Assertions.assertEquals(0xC0000043, IOExceptionWithStatus.Status.SHARING_VIOLATION.ntStatus());
		Assertions.assertEquals(0xC000007F, IOExceptionWithStatus.Status.DISK_FULL.ntStatus());
		Assertions.assertEquals(0xC00000E9, IOExceptionWithStatus.Status.UNEXPECTED_IO_ERROR.ntStatus());
	}
}
