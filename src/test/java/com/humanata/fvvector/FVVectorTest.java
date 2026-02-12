package com.humanata.fvvector;

import static org.junit.jupiter.api.Assertions.*;

import java.security.SecureRandom;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;


class FVVectorTest {

	static FVParameters ps;
	static FVPrivateKey privKey;
	static FVPublicKey pubKey;
	static FVEncoder encoder;
	static FVRelinearisationKey relinKey;
	static FVContext context;

	@BeforeAll
	public static void oneTimeSetUp() {
		// Insecure parameters for faster tests; do not use in production.
		ps = FVParameters.FVParamsN1024S128insecure;
		privKey = new FVPrivateKey(ps);
		pubKey = new FVPublicKey(privKey);
		encoder = new FVEncoder(ps);
		relinKey = new FVRelinearisationKey(privKey);
		context = new FVContext(pubKey, encoder, relinKey, null);
	}

	private static FVContext buildRotationContext() {
		return FVContext.BuildDefaultContext(privKey);
	}


	@Test
	void testEncryptDecrypt() {

		long data[] = new long[(int)ps.polynomialModulusExponent];
		data[0] = 100L;
		data[200] = 200L;
		data[300] = -300L;
		data[1023] = -35145234L;
		
		
		FVPlainText pt = context.encode(data);
		FVCipherText ct = context.encrypt(pt);
		
		long data2[] = context.decryptAndDecode(ct, privKey);
		
		assertEquals(ps.ptRing.modulus(data[0]), ps.ptRing.modulus(data2[0]));
		assertEquals(ps.ptRing.modulus(data[200]),ps.ptRing.modulus(data2[200]));
		assertEquals(ps.ptRing.modulus(data[300]),ps.ptRing.modulus(data2[300]));
		assertEquals(ps.ptRing.modulus(data[1023]),ps.ptRing.modulus(data2[1023]));
		
		long data3[] = context.decryptAndDecode(ct, privKey);
		
		assertEquals(ps.ptRing.modulus(data[0]), ps.ptRing.modulus(data3[0]));
		assertEquals(ps.ptRing.modulus(data[200]),ps.ptRing.modulus(data3[200]));
		assertEquals(ps.ptRing.modulus(data[300]),ps.ptRing.modulus(data3[300]));
		assertEquals(ps.ptRing.modulus(data[1023]),ps.ptRing.modulus(data3[1023]));
	}

	@Test
	void testEncryptedAddition() {

		SecureRandom rand = new SecureRandom();

		long data1[] = new long[(int)ps.polynomialModulusExponent];
		long data2[] = new long[(int)ps.polynomialModulusExponent];
		for(int i = 0; i < data1.length; i++)
		{
			data1[i] = ps.ptRing.modulus(rand.nextLong());
			data2[i] = ps.ptRing.modulus(rand.nextLong());
		}
		
		FVCipherText ct1 = context.encodeAndEncrypt(data1);
		FVCipherText ct2 = context.encodeAndEncrypt(data2);
		
		FVCipherText ct3 = context.add(ct1, ct2);

		long datares[] = context.decryptAndDecode(ct3, privKey);

		for(int i = 0; i < data1.length; i++)
		{
			assertEquals(ps.ptRing.modulus(data1[i] + data2[i]), ps.ptRing.modulus(datares[i]));
		}
	}

	@Test
	void testEncryptedSubtraction() {

		SecureRandom rand = new SecureRandom();

		long data1[] = new long[(int)ps.polynomialModulusExponent];
		long data2[] = new long[(int)ps.polynomialModulusExponent];
		for(int i = 0; i < data1.length; i++)
		{
			data1[i] = ps.ptRing.modulus(rand.nextLong());
			data2[i] = ps.ptRing.modulus(rand.nextLong());
		}
		
		FVCipherText ct1 = context.encodeAndEncrypt(data1);
		FVCipherText ct2 = context.encodeAndEncrypt(data2);
		
		FVCipherText ct3 = context.subtract(ct1, ct2);

		long datares[] = context.decryptAndDecode(ct3, privKey);

		for(int i = 0; i < data1.length; i++)
		{
			assertEquals(ps.ptRing.modulus(data1[i] - data2[i]), ps.ptRing.modulus(datares[i]));
		}
	}

	
	@Test
	void testEncryptedMultiplication() {

		SecureRandom rand = new SecureRandom();
		
		long data1[] = new long[(int)ps.polynomialModulusExponent];
		long data2[] = new long[(int)ps.polynomialModulusExponent];
		for(int i = 0; i < data1.length; i++)
		{
			data1[i] = ps.ptRing.modulus(rand.nextLong());
			data2[i] = ps.ptRing.modulus(rand.nextLong());
		}
		
		FVCipherText ct1 = context.encodeAndEncrypt(data1);
		FVCipherText ct2 = context.encodeAndEncrypt(data2);
		
		FVCipherText ct3 = context.multiplyWithoutRelinearisation(ct1, ct2);

		long datares[] = context.decryptAndDecode(ct3, privKey);

		for(int i = 0; i < data1.length; i++)
		{
			assertEquals(ps.ptRing.modulus(data1[i] * data2[i]), ps.ptRing.modulus(datares[i]));
		}
	}
	
	@Test
	void testRelinearisedEncryptedMultiplication() {
		
		SecureRandom rand = new SecureRandom();
		
		long data1[] = new long[(int)ps.polynomialModulusExponent];
		long data2[] = new long[(int)ps.polynomialModulusExponent];
		for(int i = 0; i < data1.length; i++)
		{
			data1[i] = ps.ptRing.modulus(rand.nextLong());
			data2[i] = ps.ptRing.modulus(rand.nextLong());
		}
		
		FVCipherText ct1 = context.encodeAndEncrypt(data1);
		FVCipherText ct2 = context.encodeAndEncrypt(data2);
		
		FVCipherText ct3 = context.multiply(ct1, ct2);

		long datares[] = context.decryptAndDecode(ct3, privKey);

		for(int i = 0; i < data1.length; i++)
		{
			assertEquals(ps.ptRing.modulus(data1[i] * data2[i]), ps.ptRing.modulus(datares[i]));
		}
	}

	@Test
	@Tag("slow")
	void testRotationOfCiphertexts() {
		FVContext rotationContext = buildRotationContext();

		long data1[] = new long[(int)ps.polynomialModulusExponent];
		for(int i = 0; i < data1.length; i++)
		{
			data1[i] = i;
		}
		
		FVCipherText ct1 = rotationContext.encodeAndEncrypt(data1);
		FVCipherText ct2 = rotationContext.interchangeSlotVectors(ct1);
		
		long[] decoded1 = rotationContext.decryptAndDecode(ct1, privKey);
		long[] decoded2 = rotationContext.decryptAndDecode(ct2, privKey);
		
		for(int i = 0; i < data1.length/2; i++)
		{
			assertEquals(decoded1[i],decoded2[i + data1.length/2]); 
			assertEquals(decoded1[i + data1.length/2], decoded2[i]);  	
		}

	}

	@Test
	@Tag("slow")
	void testSumIntoFirstSlot() {
		FVContext rotationContext = buildRotationContext();
		long data[] = new long[(int)ps.polynomialModulusExponent];
		long expectedSum = 0;
		for(int i = 0; i < data.length; i++)
		{
			data[i] = ps.ptRing.modulus(i);
			expectedSum = ps.ptRing.modulus(expectedSum + data[i]);
		}
		
		FVCipherText ct = rotationContext.encodeAndEncrypt(data);
		FVCipherText ctSummed = rotationContext.sumIntoFirstSlot(ct);
		
		long[] decoded = rotationContext.decryptAndDecode(ctSummed, privKey);
		assertEquals(expectedSum, decoded[0], "Slot 0 should contain the sum of all slots");
	}
	
}
