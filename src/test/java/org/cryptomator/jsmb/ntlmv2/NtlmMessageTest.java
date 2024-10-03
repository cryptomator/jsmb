package org.cryptomator.jsmb.ntlmv2;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.foreign.MemorySegment;
import java.util.Base64;

class NtlmMessageTest {

	@Test
	@DisplayName("Parse NTLM Negotiate Message")
	public void testParseNegotiateMessage() {
		byte[] token = Base64.getDecoder().decode("TlRMTVNTUAABAAAAFYKIYgAAAAAAAAAAAAAAAAAAAAAGAbAdAAAADw==");

		var message = NtlmMessage.parse(MemorySegment.ofArray(token));
		var negotiateMessage = Assertions.assertInstanceOf(NtlmNegotiateMessage.class, message);

		Assertions.assertEquals(NtlmNegotiateMessage.MESSAGE_TYPE, message.messageType());
		Assertions.assertEquals(0x62888215, negotiateMessage.negotiateFlags());
		Assertions.assertArrayEquals(new byte[]{}, negotiateMessage.domainName());
		Assertions.assertArrayEquals(new byte[]{}, negotiateMessage.workstationName());
		Assertions.assertEquals(6, negotiateMessage.productMajorVersion());
		Assertions.assertEquals(1, negotiateMessage.productMinorVersion());
		Assertions.assertEquals(7600, negotiateMessage.productBuild());
		Assertions.assertEquals(15, negotiateMessage.ntlmRevisionCurrent());

	}

	@Test
	@DisplayName("Parse NTLM Authenticate Message")
	public void testParseAuthenticateMessage() {
		byte[] token = Base64.getDecoder().decode("TlRMTVNTUAADAAAAAAAAAFgAAACkAKQAWAAAABIAEgD8AAAABgAGAA4BAAAAAAAAFAEAABAAEAAUAQAAFYKIYgYBsB0AAAAP6RhssGDQLAZ2mIfMYKe9gtTPFNsbtxxUYkVtlNslXUkBAQAAAAAAAHAks4wu5NoB0utszfNTYKQAAAAAAQAWAGMAcgB5AHAAdABvAG0AYQB0AG8AcgACAAoAbABvAGMAYQBsAAMACgBsAG8AYwBhAGwABAAKAGwAbwBjAGEAbAAHAAgAcCSzjC7k2gEGAAQAAgAAAAkAFABjAGkAZgBzAC8AbABvAGMAYQBsAAAAAAAAAAAAVwBPAFIASwBHAFIATwBVAFAAYQBzAGQAHchB58RfK1jfphf9ma8t+Q==");

		var message = NtlmMessage.parse(MemorySegment.ofArray(token));
		var authenticateMessage = Assertions.assertInstanceOf(NtlmAuthenticateMessage.class, message);

		Assertions.assertEquals(NtlmAuthenticateMessage.MESSAGE_TYPE, message.messageType());
		Assertions.assertEquals("asd", authenticateMessage.userName());
		Assertions.assertEquals("WORKGROUP", authenticateMessage.domainName());
		Assertions.assertNull(authenticateMessage.workstation());
		Assertions.assertArrayEquals(Base64.getDecoder().decode("HchB58RfK1jfphf9ma8t+Q=="), authenticateMessage.encryptedRandomSessionKey());
		Assertions.assertEquals(0x62888215, authenticateMessage.negotiateFlags());
		Assertions.assertEquals(6, authenticateMessage.productMajorVersion());
		Assertions.assertEquals(1, authenticateMessage.productMinorVersion());
		Assertions.assertEquals(7600, authenticateMessage.productBuild());
		Assertions.assertEquals(15, authenticateMessage.ntlmRevisionCurrent());

	}

}