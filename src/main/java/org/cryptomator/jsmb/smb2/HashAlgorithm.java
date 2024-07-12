package org.cryptomator.jsmb.smb2;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public enum HashAlgorithm {
	SHA512((short) 0x0001,  "SHA-512");

	public final short id;
	private final String algorithm;

	HashAlgorithm(short id, String algorithm) {
		this.id = id;
		this.algorithm = algorithm;
	}

	public byte[] compute(byte[] data) {
		try {
			var digest = MessageDigest.getInstance(algorithm);
			return digest.digest(data);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("Algorithm not available: " + algorithm, e);
		}
	}

	static HashAlgorithm lookup(short id) {
		for (var alg : HashAlgorithm.values()) {
			if (alg.id == id) {
				return alg;
			}
		}
		throw new IllegalArgumentException("Unknown hash id: " + id);
	}

	static boolean isSupported(short id) {
		for (var alg : HashAlgorithm.values()) {
			if (alg.id == id) {
				return true;
			}
		}
		return false;
	}
}
