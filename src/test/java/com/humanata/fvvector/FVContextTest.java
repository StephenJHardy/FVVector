package com.humanata.fvvector;

import static org.junit.jupiter.api.Assertions.*;

import java.security.SecureRandom;

import org.junit.jupiter.api.Test;

class FVContextTest {

	@Test
	void testHelloWorld() {
		// Matches the Readme Hello World example: homomorphic multiplication of packed vectors.
		// Uses insecure params for faster test execution; do not use in production.
		FVParameters ps = FVParameters.FVParamsN1024S128insecure;
		FVPrivateKey privKey = new FVPrivateKey(ps);
		FVContext context = FVContext.BuildDefaultContext(privKey);

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

}
