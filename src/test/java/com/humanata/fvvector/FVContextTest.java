package com.humanata.fvvector;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class FVContextTest {

	private static FVParameters ps;
	private static FVPrivateKey privKey;
	private static FVContext context;
	private static int n;

	@BeforeAll
	static void setUp() {
		// Insecure parameters for faster tests; do not use in production.
		ps = FVParameters.FVParamsN1024S128insecure;
		privKey = new FVPrivateKey(ps);
		context = FVContext.BuildDefaultContext(privKey);
		n = (int) ps.polynomialModulusExponent;
	}

	@Test
	void testEncodeDecodeRoundTrip() {
		long[] data = new long[n];
		data[0] = 1;
		data[1] = 2;
		data[n / 2] = 3;
		data[n - 1] = 4;

		FVPlainText pt = context.encode(data);
		long[] decoded = context.decode(pt);

		assertEquals(ps.ptRing.modulus(data[0]), decoded[0]);
		assertEquals(ps.ptRing.modulus(data[1]), decoded[1]);
		assertEquals(ps.ptRing.modulus(data[n / 2]), decoded[n / 2]);
		assertEquals(ps.ptRing.modulus(data[n - 1]), decoded[n - 1]);
	}

	@Test
	void testEncryptDecryptAddSubtractAndMultiply() {
		long[] data1 = new long[n];
		long[] data2 = new long[n];
		for (int i = 0; i < n; i++) {
			data1[i] = (i * 3L + 7L) % 97L;
			data2[i] = (i * 5L + 11L) % 89L;
		}

		FVPlainText pt1 = context.encode(data1);
		FVPlainText pt2 = context.encode(data2);
		FVCipherText ct1 = context.encrypt(pt1);
		FVCipherText ct2 = context.encrypt(pt2);

		long[] decrypted = context.decode(context.decrypt(ct1, privKey));
		for (int i = 0; i < n; i++) {
			assertEquals(ps.ptRing.modulus(data1[i]), decrypted[i]);
		}

		long[] added = context.decryptAndDecode(context.add(ct1, ct2), privKey);
		for (int i = 0; i < n; i++) {
			assertEquals(ps.ptRing.modulus(data1[i] + data2[i]), added[i]);
		}

		long[] subtracted = context.decryptAndDecode(context.subtract(ct1, ct2), privKey);
		for (int i = 0; i < n; i++) {
			assertEquals(ps.ptRing.modulus(data1[i] - data2[i]), subtracted[i]);
		}

		long[] multiplied = context.decryptAndDecode(context.multiply(ct1, ct2), privKey);
		for (int i = 0; i < n; i++) {
			assertEquals(ps.ptRing.modulus(data1[i] * data2[i]), multiplied[i]);
		}

		long[] multipliedCtPt = context.decryptAndDecode(context.multiply(ct1, pt2), privKey);
		for (int i = 0; i < n; i++) {
			assertEquals(ps.ptRing.modulus(data1[i] * data2[i]), multipliedCtPt[i]);
		}

		long[] multipliedPtCt = context.decryptAndDecode(context.multiply(pt1, ct2), privKey);
		for (int i = 0; i < n; i++) {
			assertEquals(ps.ptRing.modulus(data1[i] * data2[i]), multipliedPtCt[i]);
		}
	}

	@Test
	void testRotateSlotsLeftRightAndInterchange() {
		int half = n / 2;
		long[] data = new long[n];
		for (int i = 0; i < half; i++) {
			data[i] = i;
			data[i + half] = 1000 + i;
		}

		FVCipherText ct = context.encodeAndEncrypt(data);

		long[] swapped = context.decryptAndDecode(context.interchangeSlotVectors(ct), privKey);
		for (int i = 0; i < half; i++) {
			assertEquals(data[i + half], swapped[i]);
			assertEquals(data[i], swapped[i + half]);
		}

		int left = 3;
		long[] leftRotated = context.decryptAndDecode(context.rotateSlotsLeft(ct, left), privKey);
		for (int i = 0; i < half; i++) {
			assertEquals(data[(i + left) % half], leftRotated[i]);
			assertEquals(data[half + (i + left) % half], leftRotated[i + half]);
		}

		int right = 4;
		long[] rightRotated = context.decryptAndDecode(context.rotateSlotsRight(ct, right), privKey);
		for (int i = 0; i < half; i++) {
			int idx = (i - right) % half;
			if (idx < 0) {
				idx += half;
			}
			assertEquals(data[idx], rightRotated[i]);
			assertEquals(data[half + idx], rightRotated[i + half]);
		}
	}

	@Test
	void testSumIntoFirstSlot() {
		long[] data = new long[n];
		long expectedSum = 0L;
		for (int i = 0; i < n; i++) {
			data[i] = i % 11;
			expectedSum = ps.ptRing.modulus(expectedSum + data[i]);
		}

		FVCipherText ct = context.encodeAndEncrypt(data);
		FVCipherText ctSummed = context.sumIntoFirstSlot(ct);
		long[] decoded = context.decryptAndDecode(ctSummed, privKey);
		assertEquals(expectedSum, decoded[0], "Slot 0 should contain the sum of all slots");
	}
}
