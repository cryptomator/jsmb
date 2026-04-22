package org.cryptomator.jsmb.smb2.ioctl;

import org.cryptomator.jsmb.common.NTStatus;
import org.cryptomator.jsmb.smb2.Command;
import org.cryptomator.jsmb.smb2.ErrorResponse;
import org.cryptomator.jsmb.smb2.PacketHeader;
import org.cryptomator.jsmb.util.Layouts;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.foreign.MemorySegment;

class IoctlHandlerTest {

	private static IoctlRequest buildRequest(int ctlCode) {
		var headerSeg = MemorySegment.ofArray(new byte[PacketHeader.STRUCTURE_SIZE]);
		headerSeg.set(Layouts.LE_INT32, 0, 0x424D53FE); // ProtocolId
		headerSeg.set(Layouts.LE_UINT16, 4, PacketHeader.STRUCTURE_SIZE); // StructureSize
		headerSeg.set(Layouts.LE_UINT16, 12, Command.IOCTL.value()); // Command
		var header = new PacketHeader(headerSeg);

		var bodySeg = MemorySegment.ofArray(new byte[56]);
		bodySeg.set(Layouts.LE_UINT16, 0, (char) 57);
		bodySeg.set(Layouts.LE_INT32, 4, ctlCode);
		return new IoctlRequest(header, bodySeg);
	}

	@Test
	@DisplayName("FSCTL_VALIDATE_NEGOTIATE_INFO returns STATUS_FILE_CLOSED on dialect 3.1.1")
	public void testValidateNegotiateInfoReturnsFileClosed() {
		var handler = new IoctlHandler(null);
		var response = handler.handle(buildRequest(FsctlCode.FSCTL_VALIDATE_NEGOTIATE_INFO));

		Assertions.assertInstanceOf(ErrorResponse.class, response);
		Assertions.assertEquals(NTStatus.STATUS_FILE_CLOSED, response.header().status());
	}

	@Test
	@DisplayName("Unknown FSCTL returns STATUS_INVALID_DEVICE_REQUEST")
	public void testUnknownFsctlReturnsInvalidDeviceRequest() {
		var handler = new IoctlHandler(null);
		var response = handler.handle(buildRequest(0xDEADBEEF));

		Assertions.assertInstanceOf(ErrorResponse.class, response);
		Assertions.assertEquals(NTStatus.STATUS_INVALID_DEVICE_REQUEST, response.header().status());
	}

	@Test
	@DisplayName("Error response preserves the IOCTL command code in the header")
	public void testErrorResponseCarriesIoctlCommand() {
		var handler = new IoctlHandler(null);
		var response = handler.handle(buildRequest(FsctlCode.FSCTL_VALIDATE_NEGOTIATE_INFO));

		Assertions.assertEquals(Command.IOCTL.value(), response.header().command());
	}
}
