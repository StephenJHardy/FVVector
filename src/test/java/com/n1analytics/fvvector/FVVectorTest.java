package com.n1analytics.fvvector;

import static org.junit.jupiter.api.Assertions.*;

import java.security.SecureRandom;

import org.junit.jupiter.api.Test;

class FVVectorTest {

	@Test
	void testEncryptDecrypt() {
		
		FVParameters ps = FVParameters.FVParamsN1024S128;
		FVPrivateKey privKey = new FVPrivateKey(ps);
		FVPublicKey pubKey = new FVPublicKey(privKey);
		FVContext context = new FVContext(pubKey);
		
		
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
		
		FVParameters ps = FVParameters.FVParamsN1024S128;
		FVPrivateKey privKey = new FVPrivateKey(ps);		
		FVPublicKey pubKey = new FVPublicKey(privKey);
		FVContext context = new FVContext(pubKey);
		
		SecureRandom rand = new SecureRandom();
//		rand.setSeed(1L);
		
		long data1[] = new long[(int)ps.polynomialModulusExponent];
		long data2[] = new long[(int)ps.polynomialModulusExponent];
		for(int i = 0; i < data1.length; i++)
		{
			data1[i] = ps.ptRing.modulus(rand.nextLong());
			data2[i] = ps.ptRing.modulus(rand.nextLong());
		}
		
		FVCipherText ct1 = context.encrypt(data1);
		FVCipherText ct2 = context.encrypt(data2);
		
		FVCipherText ct3 = context.add(ct1, ct2);

		long datares[] = context.decryptAndDecode(ct3, privKey);

		for(int i = 0; i < data1.length; i++)
		{
//			System.err.println(String.format("%d %d %d %d %d\n",data1[i],data2[i],datares[i],ps.ptRing.modulus(data1[i] + data2[i]),ps.ptRing.modulus(datares[i])));
			assertEquals(ps.ptRing.modulus(data1[i] + data2[i]), ps.ptRing.modulus(datares[i]));
		}
	}

	@Test
	void testEncryptedMultiplication() {
		
		FVParameters ps = FVParameters.generateParameterSet(FVParameters.SecurityParam.BITS_128, 2048, 14, 56-14);
		FVPrivateKey privKey = new FVPrivateKey(ps);		
		FVPublicKey pubKey = new FVPublicKey(privKey);
		FVContext context = new FVContext(pubKey); 

		SecureRandom rand = new SecureRandom();
		
		long data1[] = new long[(int)ps.polynomialModulusExponent];
		long data2[] = new long[(int)ps.polynomialModulusExponent];
		for(int i = 0; i < data1.length; i++)
		{
			data1[i] = ps.ptRing.modulus(rand.nextLong());
			data2[i] = ps.ptRing.modulus(rand.nextLong());
		}
		
		FVCipherText ct1 = context.encrypt(data1);
		FVCipherText ct2 = context.encrypt(data2);
		
		FVCipherText ct3 = context.multiply(ct1, ct2);

		long datares[] = context.decryptAndDecode(ct3, privKey);

		for(int i = 0; i < data1.length; i++)
		{
//			System.err.println(String.format("%d %d %d %d %d\n",data1[i],data2[i],datares[i],ps.ptRing.modulus(data1[i] + data2[i]),ps.ptRing.modulus(datares[i])));
			assertEquals(ps.ptRing.modulus(data1[i] * data2[i]), ps.ptRing.modulus(datares[i]));
		}
	}
	
	@Test
	void testRelinearisedEncryptedMultiplication() {
		
		FVParameters ps = FVParameters.generateParameterSet(FVParameters.SecurityParam.BITS_128, 2048, 14, 56-14);
		FVPrivateKey privKey = new FVPrivateKey(ps);		
		FVPublicKey pubKey = new FVPublicKey(privKey);
		FVRelinearisationKey relinKey = new FVRelinearisationKey(privKey);
		FVContext context = new FVContext(pubKey, relinKey); 

		SecureRandom rand = new SecureRandom();
		
		long data1[] = new long[(int)ps.polynomialModulusExponent];
		long data2[] = new long[(int)ps.polynomialModulusExponent];
		for(int i = 0; i < data1.length; i++)
		{
			data1[i] = ps.ptRing.modulus(rand.nextLong());
			data2[i] = ps.ptRing.modulus(rand.nextLong());
		}
		
		FVCipherText ct1 = context.encrypt(data1);
		FVCipherText ct2 = context.encrypt(data2);
		
		FVCipherText ct3 = context.multiplyAndRelinearise(ct1, ct2);

		long datares[] = context.decryptAndDecode(ct3, privKey);

		for(int i = 0; i < data1.length; i++)
		{
//			System.err.println(String.format("%d %d %d %d %d\n",data1[i],data2[i],datares[i],ps.ptRing.modulus(data1[i] + data2[i]),ps.ptRing.modulus(datares[i])));
			assertEquals(ps.ptRing.modulus(data1[i] * data2[i]), ps.ptRing.modulus(datares[i]));
		}
	}

	
}
