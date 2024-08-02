package org.cryptomator.jsmb.asn1;

interface OID {

	/**
	 * 1.3.6.1.4.1.311.2.2.10
	 *
	 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/e21c0b07-8662-41b7-8853-2b9184eab0db">NTLM spec</a>
	 */
	byte[] NTLM = new byte[]{0x2B, 0x06, 0x01, 0x04, 0x01, (byte) 0x82, 0x37, 0x02, 0x02, 0x0A};

	/**
	 * 1.3.6.1.5.5.2
	 *
	 * @see <a href="https://www.rfc-editor.org/rfc/rfc2478#section-3.2">RFC 2478, section 3.2</a>
	 */
	byte[] SPNEGO = new byte[]{0x2B, 0x06, 0x01, 0x05, 0x05, 0x02};

}
