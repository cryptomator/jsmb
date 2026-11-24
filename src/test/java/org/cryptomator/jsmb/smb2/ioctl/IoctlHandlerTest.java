package org.cryptomator.jsmb.smb2.ioctl;

import org.cryptomator.jsmb.Config;
import org.cryptomator.jsmb.Credentials;
import org.cryptomator.jsmb.common.DisconnectException;
import org.cryptomator.jsmb.common.NTStatus;
import org.cryptomator.jsmb.smb2.Command;
import org.cryptomator.jsmb.smb2.Connection;
import org.cryptomator.jsmb.smb2.ErrorResponse;
import org.cryptomator.jsmb.smb2.Global;
import org.cryptomator.jsmb.smb2.PacketHeader;
import org.cryptomator.jsmb.util.Layouts;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.lang.foreign.MemorySegment;

class IoctlHandlerTest {

	private Connection connection;
	private IoctlHandler handler;

	@BeforeEach
	void setUp() {
		connection = new Connection(new Global(Config.DEFAULT, new Credentials("DOMAIN", "user", "password")));
		handler = new IoctlHandler(connection);
	}

	private static IoctlRequest buildRequest(int ctlCode) {
		var headerSeg = MemorySegment.ofArray(new byte[PacketHeader.STRUCTURE_SIZE]);
		headerSeg.set(Layouts.LE_INT32, 0, 0x424D53FE); // ProtocolId
		headerSeg.set(Layouts.LE_UINT16, 4, PacketHeader.STRUCTURE_SIZE); // StructureSize
		headerSeg.set(Layouts.LE_UINT16, 12, Command.IOCTL.value()); // Command
		var header = new PacketHeader(headerSeg);

		var bodySeg = MemorySegment.ofArray(new byte[56]);
		bodySeg.set(Layouts.LE_UINT16, 0, (char) 57);
		bodySeg.set(Layouts.LE_INT32, 4, ctlCode);
		bodySeg.set(Layouts.LE_INT32, 48, IoctlRequest.FLAG_IS_FSCTL);
		return new IoctlRequest(header, bodySeg);
	}

	@Test
	@DisplayName("FSCTL_VALIDATE_NEGOTIATE_INFO drops the connection, as the dialect is 3.1.1")
	public void testValidateNegotiateInfoDisconnects() {
		var request = buildRequest(FsctlCode.FSCTL_VALIDATE_NEGOTIATE_INFO);

		Assertions.assertThrows(DisconnectException.class, () -> handler.handle(request));
	}

	@Test
	@DisplayName("Unknown FSCTL returns STATUS_INVALID_DEVICE_REQUEST")
	public void testUnknownFsctlReturnsInvalidDeviceRequest() {
		var response = handler.handle(buildRequest(0xDEADBEEF));

		Assertions.assertInstanceOf(ErrorResponse.class, response);
		Assertions.assertEquals(NTStatus.STATUS_INVALID_DEVICE_REQUEST, response.header().status());
	}

	@Test
	@DisplayName("An IOCTL whose Flags are not SMB2_0_IOCTL_IS_FSCTL returns STATUS_NOT_SUPPORTED")
	public void testNonFsctlReturnsNotSupported() {
		var request = buildRequest(0xDEADBEEF);
		request.segment().set(Layouts.LE_INT32, 48, 0);

		var response = handler.handle(request);

		Assertions.assertEquals(NTStatus.STATUS_NOT_SUPPORTED, response.header().status());
	}

	@ParameterizedTest(name = "field at offset {0}")
	@DisplayName("InputCount, MaxInputResponse or MaxOutputResponse beyond MaxTransactSize returns STATUS_INVALID_PARAMETER")
	@ValueSource(ints = {28, 32, 44})
	public void testSizeBeyondMaxTransactSize(int fieldOffset) {
		var request = buildRequest(0xDEADBEEF);
		request.segment().set(Layouts.LE_INT32, fieldOffset, connection.maxTransactSize + 1);

		var response = handler.handle(request);

		Assertions.assertEquals(NTStatus.STATUS_INVALID_PARAMETER, response.header().status());
	}

	@Test
	@DisplayName("Error response preserves the IOCTL command code in the header")
	public void testErrorResponseCarriesIoctlCommand() {
		var response = handler.handle(buildRequest(0xDEADBEEF));

		Assertions.assertEquals(Command.IOCTL.value(), response.header().command());
	}
}
