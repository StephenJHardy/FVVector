package com.humanata.fvvector;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

class FVSerializationTest {

	@Test
	void testParameterRoundTrip() {
		FVParameters params = FVParameters.FVParamsN1024S128insecure;
		FVParameters restored = FVParameters.fromBytes(params.toBytes());
		assertEquals(params, restored);
	}

	@Test
	void testKeyPlaintextAndCiphertextRoundTrip() {
		FVParameters params = FVParameters.FVParamsN1024S128insecure;
		FVPrivateKey privKey = new FVPrivateKey(params);
		FVPublicKey pubKey = new FVPublicKey(privKey);
		FVEncoder encoder = new FVEncoder(params);

		long[] data = new long[(int) params.polynomialModulusExponent];
		data[0] = 7;
		data[1] = 11;
		data[2] = 13;

		FVPlainText pt = new FVPlainText();
		pt.encode(encoder, data);
		FVCipherText ct = pt.encrypt(pubKey);

		FVPrivateKey priv2 = FVPrivateKey.fromBytes(privKey.toBytes());
		FVPublicKey pub2 = FVPublicKey.fromBytes(pubKey.toBytes());
		FVPlainText pt2 = FVPlainText.fromBytes(pt.toBytes());
		FVCipherText ct2 = FVCipherText.fromBytes(ct.toBytes());

		long[] decodedPt = pt2.decode(new FVEncoder(params));
		assertEquals(params.ptRing.modulus(data[0]), decodedPt[0]);
		assertEquals(params.ptRing.modulus(data[1]), decodedPt[1]);
		assertEquals(params.ptRing.modulus(data[2]), decodedPt[2]);

		FVPlainText decrypted = ct2.decrypt(priv2);
		long[] decodedCt = decrypted.decode(new FVEncoder(priv2.params));
		assertEquals(params.ptRing.modulus(data[0]), decodedCt[0]);
		assertEquals(params.ptRing.modulus(data[1]), decodedCt[1]);
		assertEquals(params.ptRing.modulus(data[2]), decodedCt[2]);

		FVCipherText ct3 = pt2.encrypt(pub2);
		FVPlainText decrypted3 = ct3.decrypt(priv2);
		long[] decodedCt3 = decrypted3.decode(new FVEncoder(priv2.params));
		assertEquals(params.ptRing.modulus(data[0]), decodedCt3[0]);
		assertEquals(params.ptRing.modulus(data[1]), decodedCt3[1]);
		assertEquals(params.ptRing.modulus(data[2]), decodedCt3[2]);
	}

	@Test
	void testRelinearisationKeyRoundTrip() {
		FVParameters params = FVParameters.FVParamsN1024S128insecure;
		FVPrivateKey privKey = new FVPrivateKey(params);
		FVPublicKey pubKey = new FVPublicKey(privKey);
		FVEncoder encoder = new FVEncoder(params);

		long[] data1 = new long[(int) params.polynomialModulusExponent];
		long[] data2 = new long[(int) params.polynomialModulusExponent];
		for (int i = 0; i < data1.length; i++) {
			data1[i] = i % 7;
			data2[i] = i % 5;
		}

		FVPlainText pt1 = new FVPlainText();
		pt1.encode(encoder, data1);
		FVPlainText pt2 = new FVPlainText();
		pt2.encode(encoder, data2);
		FVCipherText ct1 = pt1.encrypt(pubKey);
		FVCipherText ct2 = pt2.encrypt(pubKey);
		ct2.multiplyBy(ct1);

		FVRelinearisationKey relinKey = new FVRelinearisationKey(privKey);
		FVRelinearisationKey relinKey2 = FVRelinearisationKey.fromBytes(relinKey.toBytes());
		ct2.relineariseCubic(relinKey2);

		long[] decoded = ct2.decrypt(privKey).decode(encoder);
		for (int i = 0; i < data1.length; i++) {
			assertEquals(params.ptRing.modulus(data1[i] * data2[i]), decoded[i]);
		}
	}

	@Test
	@Tag("slow")
	void testRotationKeyRoundTrip() {
		FVParameters params = FVParameters.FVParamsN1024S128insecure;
		FVPrivateKey privKey = new FVPrivateKey(params);
		FVPublicKey pubKey = new FVPublicKey(privKey);
		FVEncoder encoder = new FVEncoder(params);

		long[] data = new long[(int) params.polynomialModulusExponent];
		for (int i = 0; i < data.length; i++) {
			data[i] = i;
		}

		FVPlainText pt = new FVPlainText();
		pt.encode(encoder, data);
		FVCipherText ct = pt.encrypt(pubKey);

		FVRotationKey rotKey = new FVRotationKey(privKey, encoder);
		FVRotationKey rotKey2 = FVRotationKey.fromBytes(rotKey.toBytes());

		FVCipherText rotated = new FVCipherText(ct);
		int index = encoder.interchangeIndex();
		rotated.rotate(encoder, index);
		rotated.rotationRekey(rotKey2, index);

		long[] decoded = rotated.decrypt(privKey).decode(encoder);
		for (int i = 0; i < data.length / 2; i++) {
			assertEquals(data[i + data.length / 2], decoded[i]);
			assertEquals(data[i], decoded[i + data.length / 2]);
		}
	}
}
