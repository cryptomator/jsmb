package org.cryptomator.jsmb.asn1;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Base64;

class NegotiationTokenTest {

	@Test
	@DisplayName("Parse NegTokenInit")
	public void testParseNegTokenInit() {
		byte[] negTokenInitBytes = Base64.getDecoder().decode("YFEGBisGAQUFAqBHMEWgDjAMBgorBgEEAYI3AgIKojMEMU5UTE1TU1AAAQAAABWCCGIAAAAAAAAAAAAAAAAAAAAABgGwHQAAAA9XT1JLR1JPVVA=");
		byte[] expectedMechToken = Base64.getDecoder().decode("TlRMTVNTUAABAAAAFYIIYgAAAAAAAAAAAAAAAAAAAAAGAbAdAAAAD1dPUktHUk9VUA==");

		var token = NegotiationToken.parse(negTokenInitBytes);

		var initToken = Assertions.assertInstanceOf(NegTokenInit.class, token);
		Assertions.assertArrayEquals(expectedMechToken, initToken.getMechToken());
		Assertions.assertEquals(1, initToken.getContentTypes().length);
		Assertions.assertArrayEquals(OID.NTLM, initToken.getContentTypes()[0]);
	}

	@Test
	@DisplayName("Parse NegTokenResp")
	public void testParseNegTokenResp() {
		byte[] negTokenRespBytes = Base64.getDecoder().decode("oYIBRDCCAUCiggEoBIIBJE5UTE1TU1AAAwAAAAAAAABYAAAApACkAFgAAAASABIA/AAAAAYABgAOAQAAAAAAABQBAAAQABAAFAEAABWCiGIGAbAdAAAAD7oNTY4aRdZN+uXC3+qIgCt7I4DfQmWtyZl91UI8pe/QAQEAAAAAAABgN1xH5uPaAcDbUVXGHngoAAAAAAEAFgBjAHIAeQBwAHQAbwBtAGEAdABvAHIAAgAKAGwAbwBjAGEAbAADAAoAbABvAGMAYQBsAAQACgBsAG8AYwBhAGwABwAIAGA3XEfm49oBBgAEAAIAAAAJABQAYwBpAGYAcwAvAGwAbwBjAGEAbAAAAAAAAAAAAFcATwBSAEsARwBSAE8AVQBQAGEAcwBkACnER2xPGI1iB/5mmif39SqjEgQQAQAAAH5iBqLzaytGAAAAAA==");
		byte[] expectedResponseToken = Base64.getDecoder().decode("TlRMTVNTUAADAAAAAAAAAFgAAACkAKQAWAAAABIAEgD8AAAABgAGAA4BAAAAAAAAFAEAABAAEAAUAQAAFYKIYgYBsB0AAAAPug1NjhpF1k365cLf6oiAK3sjgN9CZa3JmX3VQjyl79ABAQAAAAAAAGA3XEfm49oBwNtRVcYeeCgAAAAAAQAWAGMAcgB5AHAAdABvAG0AYQB0AG8AcgACAAoAbABvAGMAYQBsAAMACgBsAG8AYwBhAGwABAAKAGwAbwBjAGEAbAAHAAgAYDdcR+bj2gEGAAQAAgAAAAkAFABjAGkAZgBzAC8AbABvAGMAYQBsAAAAAAAAAAAAVwBPAFIASwBHAFIATwBVAFAAYQBzAGQAKcRHbE8YjWIH/maaJ/f1Kg==");

		var token = NegotiationToken.parse(negTokenRespBytes);

		var respToken = Assertions.assertInstanceOf(NegTokenResp.class, token);
		Assertions.assertArrayEquals(expectedResponseToken, respToken.getResponseToken());

	}

}