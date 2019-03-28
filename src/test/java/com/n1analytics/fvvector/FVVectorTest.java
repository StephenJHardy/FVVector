package com.n1analytics.fvvector;

import static org.junit.jupiter.api.Assertions.*;

import java.security.SecureRandom;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeAll;


class FVVectorTest {

	static FVParameters ps;
	static FVPrivateKey privKey;
	static FVContext context;

	@BeforeAll
	public static void oneTimeSetUp() {
		ps = FVParameters.generateParameterSet(FVParameters.SecurityParam.BITS_128, 2048, 14, 56-14);
		privKey = new FVPrivateKey(ps);
		context = FVContext.BuildDefaultContext(privKey);
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
	void testRotationOfCiphertexts() {

		long data1[] = new long[(int)ps.polynomialModulusExponent];
		for(int i = 0; i < data1.length; i++)
		{
			data1[i] = i;
		}
		
		FVCipherText ct1 = context.encodeAndEncrypt(data1);
		FVCipherText ct2 = context.interchangeSlotVectors(ct1);
		
		long[] decoded1 = context.decryptAndDecode(ct1, privKey);
		long[] decoded2 = context.decryptAndDecode(ct2, privKey);
		
		for(int i = 0; i < data1.length/2; i++)
		{
			assertEquals(decoded1[i],decoded2[i + data1.length/2]); 
			assertEquals(decoded1[i + data1.length/2], decoded2[i]);  	
		}

	}
	
}
