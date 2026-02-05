package org.cryptomator.jsmb.smb2.crypto;

import com.google.common.io.BaseEncoding;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class NistSP800108KDFTest {

	private static final BaseEncoding HEX = BaseEncoding.base16().lowerCase();

	// test vectors taken from https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Key-Derivation
	@DisplayName("CAVS 14.4 Test Vectors [PRF=HMAC_SHA256], [CTRLOCATION=BEFORE_FIXED], [RLEN=32_BITS]")
	@ParameterizedTest(name = "kdf({0}, {1}, {2}) = {3}")
	@CsvSource(value = {
			/* COUNT  0 */ "dd1d91b7d90b2bd3138533ce92b272fbf8a369316aefe242e659cc0ae238afe0, 01322b96b30acd197979444e468e1c5c6859bf1b1cf951b7e725303e237e46b864a145fab25e517b08f8683d0315bb2911d80a0e8aba17f3b413faac, 16, 10621342bfb0fd40046c0e29f2cfdbf0",
			/* COUNT 10 */ "e204d6d466aad507ffaf6d6dab0a5b26152c9e21e764370464e360c8fbc765c6, 7b03b98d9f94b899e591f3ef264b71b193fba7043c7e953cde23bc5384bc1a6293580115fae3495fd845dadbd02bd6455cf48d0f62b33e62364a3a80, 32, 770dfab6a6a4a4bee0257ff335213f78d8287b4fd537d5c1fffa956910e7c779",
			/* COUNT 20 */ "dc60338d884eecb72975c603c27b360605011756c697c4fc388f5176ef81efb1, 44d7aa08feba26093c14979c122c2437c3117b63b78841cd10a4bc5ed55c56586ad8986d55307dca1d198edcffbc516a8fbe6152aa428cdd800c062d, 20, 29ac07dccf1f28d506cd623e6e3fc2fa255bd60b",
			/* COUNT 30 */ "c4bedbddb66493e7c7259a3bbbc25f8c7e0ca7fe284d92d431d9cd99a0d214ac, 1c69c54766791e315c2cc5c47ecd3ffab87d0d273dd920e70955814c220eacace6a5946542da3dfe24ff626b4897898cafb7db83bdff3c14fa46fd4b, 40, 1da47638d6c9c4d04d74d4640bbd42ab814d9e8cc22f4326695239f96b0693f12d0dd1152cf44430"
	})
	public void testWithHmacSha256(String key, String fixedInputData, int outLen, String expected) {
		byte[] keyBytes = HEX.decode(key);
		byte[] fixedInputDataBytes = HEX.decode(fixedInputData);

		byte[] result = NistSP800108KDF.withHmacSha256(keyBytes, fixedInputDataBytes, outLen);

		Assertions.assertEquals(expected, HEX.encode(result));
	}

}