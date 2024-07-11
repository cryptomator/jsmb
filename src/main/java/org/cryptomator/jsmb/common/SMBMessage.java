package org.cryptomator.jsmb.common;

public interface SMBMessage {

	/**
	 * Serializes this message in order to send it over the network.
	 * @return The serialized message.
	 */
	byte[] serialize();

}
