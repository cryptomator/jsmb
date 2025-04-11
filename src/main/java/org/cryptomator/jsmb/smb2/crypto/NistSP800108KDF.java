package org.cryptomator.jsmb.smb2.crypto;

import org.cryptomator.jsmb.util.Bytes;
import org.jetbrains.annotations.VisibleForTesting;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * KDF in Counter Mode as specified in by NIST SP 800-108r1, Section 5.1, using HMAC-SHA256 as the PRF.
 * <p>
 * Required to derive keys for SMB 3.x, as described in <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/da4e579e-02ce-4e27-bbce-3fc816a3ff92">Generating Cryptographic Keys</a>
 *
 * @see <a href="https://doi.org/10.6028/NIST.SP.800-108">NIST SP 800-108r1</a>
 */
public class NistSP800108KDF {

	private NistSP800108KDF(){}

	public static byte[] withHmacSha256(byte[] key, byte[] label, byte[] context, int outputLength) {
		// fixedInputData = Label || 0x00 || Context || [L]_2
		byte[] fixedInputData = new byte[label.length + 1 + context.length + Integer.BYTES];
		var buf = ByteBuffer.wrap(fixedInputData);
		buf.put(label);
		buf.put(label.length, (byte) 0x00);
		buf.put(label.length + 1, context);
		buf.putInt(label.length + 1 + context.length, outputLength * Byte.SIZE);
		return withHmacSha256(key, fixedInputData, outputLength);
	}

	@VisibleForTesting
	static byte[] withHmacSha256(byte[] key, byte[] fixedInputData, int outputLength) {
		Mac prf;
		try {
			prf = Mac.getInstance("HmacSHA256");
			SecretKeySpec keySpec = new SecretKeySpec(key, "HmacSHA256");
			prf.init(keySpec);
		} catch (NoSuchAlgorithmException e) {
			throw new AssertionError("Every implementation of the Java platform is required to support HmacSHA256", e);
		} catch (InvalidKeyException e) {
			throw new IllegalArgumentException("Unsuitable key", e);
		}

		int h = prf.getMacLength();
		int n = Math.ceilDiv(outputLength, h);
		assert n < Integer.MAX_VALUE : "since outputLength is an integer, n must be smaller. Thus n < 2^r - 1"; // required as per spec

		byte[] result = new byte[0];
		byte[] tmp = new byte[Integer.BYTES + fixedInputData.length];
		ByteBuffer tmpBuf = ByteBuffer.wrap(tmp);
		tmpBuf.put(Integer.BYTES, fixedInputData);
		for (int i = 1; i <= n; i++) {
			tmpBuf.putInt(0, i);
			result = Bytes.concat(result, prf.doFinal(tmp));
		}
		assert result.length >= outputLength : "result length must be greater than or equal to outputLength by now";
		return Arrays.copyOf(result, outputLength);

	}
}
