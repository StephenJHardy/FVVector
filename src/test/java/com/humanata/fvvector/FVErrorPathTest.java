package com.humanata.fvvector;

import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import cc.redberry.rings.poly.univar.UnivariatePolynomialZp64;

class FVErrorPathTest {

	private static FVParameters params;
	private static FVPrivateKey privKey;
	private static FVPublicKey pubKey;
	private static FVEncoder encoder;
	private static FVRelinearisationKey relinKey;
	private static FVContext context;
	private static int n;

	@BeforeAll
	static void setUp() {
		params = FVParameters.FVParamsN1024S128insecure;
		privKey = new FVPrivateKey(params);
		pubKey = new FVPublicKey(privKey);
		encoder = new FVEncoder(params);
		relinKey = new FVRelinearisationKey(privKey);
		context = new FVContext(pubKey, encoder, relinKey, null);
		n = (int) params.polynomialModulusExponent;
	}

	@Test
	void testContextEncodeRejectsNullAndWrongLength() {
		assertThrows(RuntimeException.class, () -> context.encode(null));
		assertThrows(RuntimeException.class, () -> context.encode(new long[n - 1]));
	}

	@Test
	void testContextDecryptRejectsWrongKey() {
		long[] data = new long[n];
		data[0] = 1L;

		FVCipherText ct = context.encodeAndEncrypt(data);
		FVPrivateKey otherKey = new FVPrivateKey(FVParameters.FVParamsN1024S128);

		assertThrows(RuntimeException.class, () -> context.decrypt(ct, otherKey));
	}

	@Test
	void testPlaintextEncryptRejectsMismatchedModulus() {
		FVPlainText pt = new FVPlainText();
		UnivariatePolynomialZp64 poly = UnivariatePolynomialZp64.zero(FVParameters.FVParamsN2048S128.plainTextModulus);
		pt.set(poly);

		assertThrows(RuntimeException.class, () -> pt.encrypt(pubKey));
	}

	@Test
	void testCiphertextAddRejectsMismatchedParams() {
		long[] data = new long[n];
		FVCipherText ct1 = context.encodeAndEncrypt(data);

		FVParameters otherParams = FVParameters.FVParamsN1024S128;
		FVPrivateKey otherPriv = new FVPrivateKey(otherParams);
		FVPublicKey otherPub = new FVPublicKey(otherPriv);
		FVEncoder otherEncoder = new FVEncoder(otherParams);
		FVPlainText pt2 = new FVPlainText();
		pt2.encode(otherEncoder, data);
		FVCipherText ct2 = pt2.encrypt(otherPub);

		assertThrows(RuntimeException.class, () -> ct1.addTo(ct2));
	}

	@Test
	void testCiphertextMultiplyRejectsPlaintextSizeMismatch() {
		long[] data = new long[n];
		FVCipherText ct = context.encodeAndEncrypt(data);

		FVPlainText pt = new FVPlainText();
		pt.set(UnivariatePolynomialZp64.zero(params.plainTextModulus));

		assertThrows(RuntimeException.class, () -> ct.multiplyBy(pt));
	}

	@Test
	void testRelineariseRejectsNonCubicCiphertext() {
		long[] data = new long[n];
		FVCipherText ct = context.encodeAndEncrypt(data);

		assertThrows(RuntimeException.class, () -> ct.relineariseCubic(relinKey));
	}

	@Test
	void testRotateRejectsNonBinaryCiphertext() {
		long[] data = new long[n];
		FVCipherText ct = context.encodeAndEncrypt(data);
		FVCipherText ct2 = new FVCipherText(ct);
		ct.multiplyBy(ct2);

		assertThrows(RuntimeException.class, () -> ct.rotate(encoder, encoder.interchangeIndex()));
	}
}
